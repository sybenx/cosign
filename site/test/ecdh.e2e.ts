// Reading a whole conversation list (COSIGN.md §5.6): the shared secret with every
// correspondent, asked for in one round trip instead of one each. What a server gives for
// fifty at once must be exactly what it gives for one at a time, and an older server — one
// that knows nothing of `peers` — must still answer the first, so a phone can ask on.
//
//   node test/ecdh.e2e.ts     (sets up its own key in server/test-ecdh/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as F from '../../server/frost.ts';
import { Pool, sealParts, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-ecdh-phone.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(100); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-ecdh/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = ''; k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k); return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-ecdh/']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('rm', ['-rf', serverDir + 'test-ecdh']);
spawnSync('node', ['setup.ts', '--dir', 'test-ecdh', '--port', '8736', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/ecdh-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-ecdh/${s}`], { cwd: serverDir, stdio: ['ignore', l, l] }));
}
await sleep(3000);

const html = await (await fetch('http://localhost:8736/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('a key with two servers', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const server = ph.group.members.find((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;

// This test speaks as the phone: its member key, its shares, its app grant.
const answers = new Map<string, any>();
const parts = new Parts();
const ctl = new Pool(ph.group.relays, e => {
  if (e.pubkey !== server.pk) return;
  const m = parts.take(e.pubkey, openFrom(ph.sk, e));
  if (m?.id) answers.set(String(m.id), m);
});
ctl.start([{ kinds: [KIND_MEMBER], '#p': [phonePk] }]);
await sleep(2000);
const as = (msg: object) => { for (const e of sealParts(ph.sk, server.pk, msg)) ctl.publish(e); };
const grant = hex(32);
as({ type: 'app_grant', pk: grant, origin: 'A messaging app', via: 'App on this phone' });
await sleep(2500);

const participants = [...ph.shares.map((s: any) => s.idx), server.idx].sort((a: number, b: number) => a - b);
/** The shared x this phone would end up with, from its own halves and the server's. */
const sharedX = (peerX: string, theirs: string[]) => {
  const mine = ph.shares.map((s: any) => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants, peerX }));
  return F.bytesToHex(F.ecdhCombine([...mine, ...theirs]));
};
const ask = async (msg: object, ms = 15_000) => {
  const id = hex();
  as({ ...msg, id });
  await waitFor(() => answers.has(id), ms);
  return answers.get(id);
};
/** Somebody to talk to: a real key, as a correspondent's would be. */
const people = Array.from({ length: 60 }, () => bytesToHex(schnorr.getPublicKey(randomBytes(32))));

// --- One at a time, as it was ---------------------------------------------------------------

const t0 = Date.now();
const singles = new Map<string, string>();
for (const p of people.slice(0, 50)) {
  const r = await ask({ type: 'ecdh_req', peerX: p, participants, grant });
  if (r?.ok) singles.set(p, sharedX(p, r.points));
}
const oneByOne = Date.now() - t0;
check('fifty conversations, one round trip each', singles.size === 50, `${(oneByOne / 1000).toFixed(1)} s`);

// --- All at once ------------------------------------------------------------------------------

const t1 = Date.now();
const batch = await ask({ type: 'ecdh_req', peerX: people[0], peers: people.slice(0, 50), participants, grant }, 30_000);
const together = Date.now() - t1;
check('the same fifty in one', !!batch?.ok && (batch.many?.length ?? 0) === 50, `${(together / 1000).toFixed(1)} s`);
check('and every one of them is the same secret as before',
  (batch?.many ?? []).every((row: any) => singles.get(row.peerX) === sharedX(row.peerX, row.points)));
console.log(`    ${(oneByOne / 1000).toFixed(1)} s one at a time, ${(together / 1000).toFixed(1)} s together: ${(oneByOne / Math.max(together, 1)).toFixed(0)}× faster`);

// --- An older server, which knows nothing of `peers` ---------------------------------------------
//
// It answers `peerX` and ignores the rest, which is what this request looks like to it.
const old = await ask({ type: 'ecdh_req', peerX: people[0], participants, grant });
check('an older server still answers the one it knows about', !!old?.ok && !old.many && singles.get(people[0]) === sharedX(people[0], old.points));

// --- What it will and won't answer for -----------------------------------------------------------

const capped = await ask({ type: 'ecdh_req', peerX: people[0], peers: people, participants, grant }, 30_000);
check('sixty asked for, fifty answered', (capped?.many?.length ?? 0) === 50, String(capped?.many?.length));
const messy = await ask({ type: 'ecdh_req', peerX: people[0], peers: [people[0], people[0], 'npub1nonsense', '', people[1]], participants, grant });
check('repeats and nonsense are dropped, not refused', (messy?.many ?? []).map((r: any) => r.peerX).join() === [people[0], people[1]].join(),
  (messy?.many ?? []).length + ' answered');

// --- The gate is the same gate -------------------------------------------------------------------

const noGrant = await ask({ type: 'ecdh_req', peerX: people[0], peers: people.slice(0, 5), participants, grant: hex(32) });
check('an app with no access gets nothing, however many it asks about', noGrant?.ok === false && String(noGrant?.reason).startsWith('revoked'), String(noGrant?.reason));
const tooFew = await ask({ type: 'ecdh_req', peerX: people[0], peers: people.slice(0, 5), participants: [ph.shares[0].idx, server.idx], grant });
check('nor one asking with fewer shares than it takes to sign', tooFew?.ok === false, String(tooFew?.reason));

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
