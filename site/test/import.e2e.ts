// Moving a key you already have out of a web page and into Cosign (site/src/import.ts):
// the page deals it, gives a shared server its share, and hands a phone its three by
// QRST, the user typing the five digits the phone shows; the page is signed in by the
// same move. Then the phone and the server sign as the old key, and the server alone
// can't.
//
//   node test/import.e2e.ts        (starts and stops a shared server itself, in server/test-import/)

import { readFileSync, openSync, mkdirSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { generateSecretKey, getPublicKey, verifyEvent, getEventHash } from 'nostr-tools/pure';
import { bytesToHex } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { Transfer, Store, browserEnv } from '../vendor/qrst-web/index.ts';
import { parseUri } from '../vendor/qrst-core/uri.ts';
import { importToPhone } from '../src/import.ts';
import { cosignMember, type MemberMove } from '../src/member.ts';
import type { Server } from '../src/servers.ts';
import { Pool, sealParts, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';
import * as Sig from '../../server/sign.ts';
import * as F from '../../server/frost.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };

execFileSync('rm', ['-rf', serverDir + 'test-import']);
mkdirSync(serverDir + 'logs', { recursive: true });
// Two shared servers: a new account needs at least two.
const hostProcs = ['h', 'h2'].map((d, i) => { const log = openSync(serverDir + `logs/import-${d}.log`, 'w'); return spawn('node', ['server.ts', '--root', `test-import/${d}`, '--port', String(8997 + i * 2)], { cwd: serverDir, env: { ...process.env, COSIGN_ENROLL: 'open' }, stdio: ['ignore', log, log] }); });
const done = (code: number) => { for (const p of hostProcs) p.kill(); process.exit(code); };
await sleep(3000);
const hosts = ['h', 'h2'].map(d => JSON.parse(readFileSync(serverDir + `test-import/${d}/host.json`, 'utf8')));
const host = hosts[0];
const servers: Server[] = hosts.map((h, i) => ({ pk: h.pk, relays: h.relays, https: null, enroll: 'open', version: 'test', operator: h.pk, nip05: `test server ${i + 1}`, verified: true, at: 0 }));

// --- The phone: scans the page's code, shows its five digits, keeps what arrives --------

const oldKey = generateSecretKey(), oldPub = getPublicKey(oldKey);
const phoneSk = bytesToHex(generateSecretKey()), phonePk = getPublicKey(F.hexToBytes(phoneSk));
let phoneCode = '', answering = true, accepted = false;
let member = null as MemberMove | null;
const store = () => new Store(undefined, () => Math.floor(Date.now() / 1000), [], ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net']);

function phoneScans(uri: string) {
  const t = Transfer.join({ profile: cosignMember, store: store(), env: browserEnv(), baseUrl: 'https://cosign.aaro.cc/', origin: '', check: 'type' }, parseUri(uri), { viaCamera: true });
  t.onChange = () => {
    const v = t.view();
    if (v.session.phase === 'code' && v.session.code) phoneCode = v.session.code;
    if (v.session.phase === 'accept' && !accepted) { accepted = true; t.accept(); } // the app checks the shares first
    if (v.value && !member) member = v.value;
  };
}

// --- The page --------------------------------------------------------------------------

let typed = 0;
const t0 = Date.now();
const imp = importToPhone({
  secretKey: oldKey, origin: 'https://astral.test', baseUrl: 'https://cosign.aaro.cc/', servers,
  ui: {
    status: s => console.log(`     [page] ${s}`),
    code: uri => phoneScans(uri),
    enterCode: (_left, submit) => { void waitFor(() => !!phoneCode, 30_000).then(() => { typed++; submit(phoneCode); }); },
  },
});
const signer = await Promise.race([imp.done, sleep(120_000).then(() => null)]).catch(e => e);
check('the page moves the key and is signed in', signer && !(signer instanceof Error), signer instanceof Error ? signer.message : `${Date.now() - t0} ms, ${typed} code typed`);
if (!signer || signer instanceof Error) done(1);
check('the phone got 3 shares of the old key', member?.group.groupX === oldPub && member.shares.length === 3);
const points = new Map(member!.group.members.flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]).map(p => [p.idx, p.sharePub]));
check('each share lies on its point', member!.shares.every(s => bytesToHex(secp256k1.Point.BASE.multiply(BigInt('0x' + s.secret)).toBytes(true)) === points.get(s.idx)));

// The phone claims its place with each server, then answers as the phone.
const serverPks = member!.group.members.filter(m => m.role === 'server').map(m => m.pk!);
const g: Sig.Group = { groupX: member!.group.groupX, threshold: member!.group.threshold, members: member!.group.members.map(m => ({ idx: m.idx, sharePub: m.sharePub, ...(m.shares ? { shares: m.shares } : {}) })) };
const parts = new Parts();
const send = (to: string, m: object) => { for (const e of sealParts(phoneSk, to, m)) pool.publish(e); };
const pool = new Pool(member!.group.relays, e => {
  const m = parts.take(e.pubkey, openFrom(phoneSk, e));
  if (!m || !answering || !serverPks.includes(e.pubkey) || m.type !== 'sign_req') return;
  if (m.event.pubkey !== g.groupX || getEventHash(m.event) !== m.msg) return;
  const mine = Sig.commitAll(g, member!.shares);
  const zs = Sig.partialAll(2, g, member!.shares, mine.nonces, m.msg, [...m.commits, ...mine.commits]);
  send(e.pubkey, { type: 'sign_res', id: m.id, ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] });
});
pool.start([{ kinds: [KIND_MEMBER], '#p': [phonePk] }]);
await sleep(2000);
for (const pk of serverPks) send(pk, { type: 'pair_ack', token: member!.claim, name: 'Test phone' });
const groupDir = () => execFileSync('ls', [serverDir + 'test-import/h/groups']).toString().trim();
const claimed = await waitFor(() => { try { return JSON.parse(readFileSync(`${serverDir}test-import/h/groups/${groupDir()}/state.json`, 'utf8')).group.members.some((m: any) => m.pk === phonePk); } catch { return false; } }, 20_000);
check('the phone claims its place with the server', claimed);
const pingAll = () => { for (const pk of serverPks) send(pk, { type: 'ping', idx: 1, ts: Date.now() }); };
const ping = setInterval(pingAll, 5000);
pingAll();
await sleep(2000);

check('the page signs as the old key', (await signer.getPublicKey()) === oldPub);
const note = await signer.signEvent({ kind: 1, content: 'moved into Cosign', tags: [] }).catch((e: Error) => e);
check('the phone (3) and a server (1) sign it', verifyEvent(note) && note.pubkey === oldPub, String(note?.message ?? ''));

answering = false; clearInterval(ping);
const err = await signer.signEvent({ kind: 1, content: 'server alone', tags: [] }).then(() => null, (e: Error) => e);
check('the servers alone can’t', !!err, err?.message);

signer.close?.();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
