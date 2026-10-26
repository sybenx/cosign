// The member library (site/src/member) against real servers: the half a host runs — the
// Marble Mac app, the extension, an iOS app — driven here by a host that keeps the parts in
// memory (member-host.ts) and does the maths with the same FROST the servers use.
//
// A weighted key: the fake phone makes it, then the library joins as a second device (3
// parts), signs with one server, works out its own key for app data, and follows a quiet
// refresh — one nobody commits, which must leave it on its old epoch and still signing, and
// one committed, which must move it. Two bugs in this library were found downstream by the
// Mac app before this test existed; it is cosign's job to prove, not the app's.
//
//   node test/member.e2e.ts      (sets up its own group in server/test-member/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, KIND_MEMBER } from '../../server/net.ts';
import { openDevice } from '../src/member/index.ts';
import { hostFor, type Kept } from './member-host.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-member-phone.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-member/${s}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-member/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-member/']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('node', ['setup.ts', '--dir', 'test-member', '--port', '8786', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/member-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-member/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_REFRESH_MIN_AGE: '15', COSIGN_PENDING_DROP: '10' } }));
}
await sleep(3000);

// --- The key ------------------------------------------------------------------------------

const html = await (await fetch('http://localhost:8786/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };

// --- The library joins as a device ---------------------------------------------------------

const kept: Kept = { mailboxKey: bytesToHex(randomBytes(32)), shares: [], epoch: 0 };
const ops = hostFor(kept);
const device = await openDevice({
  ops, relays: ph.group.relays, name: 'Test Mac',
  onStatus: t => console.log(`[mac] ${t}`),
  onRemoved: by => console.log(`[mac] removed by ${by}`),
});
let code = '';
const joined = device.join({ onCode: u => { code = u; } }).then(() => null, (e: Error) => e);
check('the library shows a join code', await waitFor(() => code.startsWith('cosign:join?'), 10_000));
const j = new URL(code.replace('cosign:', 'cosign://'));
asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
await sleep(1500);
asPhone(servers[0].pk, { type: 'add_device', id: hex(6), pk: j.searchParams.get('pk'), name: 'Test Mac', relays: j.searchParams.getAll('r'), lock: true });
const err = await Promise.race([joined, sleep(60_000).then(() => new Error('nothing happened in a minute'))]);
check('the phone vouches and the library has its parts', err === null, String((err as Error)?.message ?? ''));
if (err !== null) { console.log(phone.out().split('\n').slice(-6).join('\n')); done(1); }

check('three parts, as a device on a weighted key', kept.shares.length === 3, `${kept.shares.map(s => s.idx).join(', ')}`);
check('the same key the phone made', device.status().pubkey === ph.group.groupX);
check('the server counts it a member', await waitFor(() => state('a').group.members.some((m: any) => m.name === 'Test Mac'), 20_000));
// The boundary the library exists for: what it keeps and hands back has no part in it.
check('nothing the library keeps holds a part of the key', kept.shares.every(s => !JSON.stringify(kept.group).includes(s.secret)));

// --- Signing, and your own things ----------------------------------------------------------

const signs = async (label: string) => {
  const ev = await device.sign({ kind: 1, content: `${label} ${hex(4)}`, tags: [] }).catch(e => e);
  check(label, verifyEvent(ev) && ev.pubkey === ph.group.groupX, String(ev?.message ?? ''));
};
await signs('the library signs with one server');

const sealed = await device.encryptToSelf('a note only this account reads').catch(e => e);
check('it works out its own key with a server', typeof sealed === 'string', String(sealed?.message ?? ''));
check('and reads back what it sealed', typeof sealed === 'string' && await device.decryptFromSelf(sealed) === 'a note only this account reads');

// --- A quiet refresh nobody commits --------------------------------------------------------

const before = JSON.stringify(kept.shares);
asPhone(phonePk, { type: 'test_periodic', commitTo: 'none' });
check('the plan and both dealers’ parts reach the library', await waitFor(() => (kept.group as any)?.pending?.epoch === 1, 60_000));
check('it holds them: still on epoch 0', device.status().epoch === 0 && kept.epoch === 0);
check('and its parts are untouched', JSON.stringify(kept.shares) === before);
await signs('a held refresh doesn’t stop it signing');
check('nobody commits: the servers drop it', await waitFor(() => !state('a').pending && !state('b').pending, 40_000));
check('still epoch 0 everywhere', !state('a').epoch && !state('b').epoch && device.status().epoch === 0);

// --- One that is committed ------------------------------------------------------------------

asPhone(phonePk, { type: 'test_periodic', commitTo: 'all' });
check('committed, the servers move to epoch 1', await waitFor(() => state('a').epoch === 1 && state('b').epoch === 1, 60_000));
check('and the library moves with them', await waitFor(() => device.status().epoch === 1 && kept.epoch === 1, 30_000));
check('its parts changed; the key didn’t', JSON.stringify(kept.shares) !== before && device.status().pubkey === ph.group.groupX);
await signs('it signs on the new epoch');

// --- Its new parts really are the key's (the phone gone) ------------------------------------

phone.k.kill();
await sleep(14_000);
await signs('without the phone, its 3 parts and a server’s 1 sign');

device.close();

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
