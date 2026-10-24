// "I already have an account", as the phone does it (Phone.importNow): the device holds
// an nsec, deals it with the FROST library's dealer (frost dealFromSecret: the device 3
// shares, each server 1, any 4 sign) and gives two shared servers their shares with the
// device's own member key already in the record (enroll, how: 'dealt', no claim). Then a
// site signs through the servers with the device co-signing, as the same npub; the
// servers alone can't. An odd-y key is used, so the dealer's negation is covered.
//
//   node test/dealt.e2e.ts        (starts and stops everything itself, in server/test-dealt/)

import { readFileSync, openSync, mkdirSync, existsSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { verifyEvent, getEventHash, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../../server/net.ts';
import * as Sig from '../../server/sign.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const W = createRequire(import.meta.url)('../../server/frost-wasm/cosign_frost.js');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 32) => bytesToHex(randomBytes(n));

execFileSync('rm', ['-rf', serverDir + 'test-dealt']);
mkdirSync(serverDir + 'logs', { recursive: true });
const hosts = [8993, 8994].map((port, i) => spawn('node', ['server.ts', '--root', `test-dealt/h${i + 1}`, '--port', String(port)], {
  cwd: serverDir, env: { ...process.env, COSIGN_ENROLL: 'open', COSIGN_UNFINISHED_AFTER: '8', COSIGN_AGE_EVERY: '1000' }, stdio: ['ignore', openSync(serverDir + `logs/dealt-h${i + 1}.log`, 'w'), openSync(serverDir + `logs/dealt-h${i + 1}.log`, 'a')],
}));
const done = (code: number) => { for (const h of hosts) h.kill(); process.exit(code); };
await sleep(3000);
const hostCfg = [1, 2].map(i => JSON.parse(readFileSync(serverDir + `test-dealt/h${i}/host.json`, 'utf8')));

// --- The device -----------------------------------------------------------------------

const sk = hex(), pk = pubOf(sk);
const relays = [...new Set(hostCfg.flatMap(h => h.relays as string[]))];
const replies = new Map<string, any>();
let me: any = null;
let answering = true;
const parts = new Parts();
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };
const pool = new Pool(relays, e => {
  const m = parts.take(e.pubkey, openFrom(sk, e));
  if (!m) return;
  if (m.id && m.type.startsWith('enroll')) return void replies.set(m.id, m);
  if (!me || !answering || m.type !== 'sign_req') return;
  const ev = m.event;
  if (ev.pubkey !== me.group.groupX || getEventHash(ev) !== m.msg) return;
  const mine = Sig.commitAll(me.group, me.shares);
  const zs = Sig.partialAll(2, me.group, me.shares, mine.nonces, m.msg, [...m.commits, ...mine.commits]);
  send(e.pubkey, { type: 'sign_res', id: m.id, ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] });
});
pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
await sleep(2000);

async function ask(hostPk: string, msg: any) {
  msg.id = hex(8);
  const until = Date.now() + 25_000;
  while (!replies.has(msg.id) && Date.now() < until) { send(hostPk, msg); await waitFor(() => replies.has(msg.id), 4000); }
  return replies.get(msg.id) ?? { type: 'no answer' };
}

// A key whose point has odd y, so the dealer negates it (the same npub).
let secret = randomBytes(32);
while (secp256k1.getPublicKey(secret, true)[0] !== 3) secret = randomBytes(32);
const npubX = getPublicKey(secret);

const keys = await Promise.all(hostCfg.map(h => ask(h.pk, { type: 'enroll_key' })));
check('both servers hand out a member key', keys.every(k => k.type === 'enroll_key'));

const dealt = JSON.parse(W.dealFromSecret(secret, [1, 2, 3, 4, 5], 4));
secret.fill(0);
check('the dealt key is the same npub', dealt.groupX === npubX);
const sh = (i: number) => dealt.shares.find((s: any) => s.idx === i);
const signerSk = hex();
const record = {
  groupX: dealt.groupX, threshold: 4, relays,
  members: [
    { idx: 1, name: 'Test phone', role: 'phone', pk, sharePub: sh(1).sharePub, shares: [1, 2, 3].map(i => ({ idx: i, sharePub: sh(i).sharePub })) },
    ...keys.map((k, i) => ({ idx: 4 + i, name: `Server ${i + 1}`, role: 'server', pk: k.pk, sharePub: sh(4 + i).sharePub })),
  ],
};
const wrong = await ask(hostCfg[0].pk, { type: 'enroll', how: 'dealt', key: keys[0].key, group: record, share: sh(5).secret, signer: { sk: signerSk, pk: pubOf(signerSk) } });
check('a share that isn’t this server’s is refused', wrong.type === 'enroll_failed' && wrong.reason.startsWith('bad-share'), wrong.reason);
const enrolled = await Promise.all(keys.map((k, i) => ask(hostCfg[i].pk, { type: 'enroll', how: 'dealt', key: k.key, group: record, share: sh(4 + i).secret, signer: { sk: signerSk, pk: pubOf(signerSk) } })));
check('both servers take their share', enrolled.every(e => e.type === 'enrolled'), enrolled.map(e => e.reason ?? e.type).join(', '));
if (!enrolled.every(e => e.type === 'enrolled')) done(1);

me = { group: { groupX: dealt.groupX, threshold: 4, members: record.members }, shares: [1, 2, 3].map(i => ({ idx: i, secret: sh(i).secret })) };
const ping = setInterval(() => { for (const k of keys) send(k.pk, { type: 'ping', idx: 1, ts: Date.now() }); }, 5000);
for (const k of keys) send(k.pk, { type: 'ping', idx: 1, ts: Date.now() });
await sleep(2000);

const t = hex(16);
for (const k of keys) send(k.pk, { type: 'ticket', t, origin: 'dealt.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(pubOf(signerSk), relays));
try { await site.connect(t); } catch (e) { check('a site connects', false, String(e)); done(1); }
check('a site gets the npub you had', (await site.getPublicKey()) === npubX);
const note = await site.signEvent({ kind: 1, content: 'an account I already had', tags: [] }).catch(e => e);
check('the phone (3) and a server (1) sign as it', verifyEvent(note) && note.pubkey === npubX, String(note?.message ?? ''));

answering = false; clearInterval(ping);
const err = await site.signEvent({ kind: 1, content: 'servers alone', tags: [] }).then(() => null, e => e as Error);
check('the two servers alone can’t', !!err, err?.message);

// Taking it out again: any four shares put the key back together (as its npub).
const all = JSON.stringify({ groupX: dealt.groupX, threshold: 4, members: dealt.shares.map((s: any) => ({ idx: s.idx, sharePub: s.sharePub })) });
const from = (idxs: number[]) => { try { return getPublicKey(W.reconstruct(all, JSON.stringify(idxs.map(i => [i, sh(i).secret])))); } catch { return null; } };
check('four shares make the key again', from([1, 2, 3, 4]) === npubX);
check('three don’t', from([1, 2, 3]) === null);

// --- Age-out: an account a stranger started and never finished is let go -----------------

const k2 = await ask(hostCfg[0].pk, { type: 'enroll_key' });
const [nobody, other] = [pubOf(hex()), pubOf(hex())];
const half = await ask(hostCfg[0].pk, {
  type: 'enroll', how: 'dkg', key: k2.key, signer: { sk: signerSk, pk: pubOf(signerSk) },
  group: { threshold: 4, relays, members: [
    { idx: 1, name: 'Nobody', role: 'phone', pk: nobody, sharePub: '', shares: [1, 2, 3].map(idx => ({ idx, sharePub: '' })) },
    { idx: 4, name: 'Server 1', role: 'server', pk: k2.pk, sharePub: '' }, { idx: 5, name: 'Server 2', role: 'server', pk: other, sharePub: '' }] },
  plan: { session: hex(16), threshold: 4, holders: [{ idx: 1, pk: nobody }, { idx: 2, pk: nobody }, { idx: 3, pk: nobody }, { idx: 4, pk: k2.pk }, { idx: 5, pk: other }] },
});
check('a stranger starts an account and never finishes it', half.type === 'enrolled' && existsSync(`${serverDir}test-dealt/h1/groups/${half.group}`), half.reason);
const halfDir = `${serverDir}test-dealt/h1/groups/${half.group}`;
const doneDir = `${serverDir}test-dealt/h1/groups/${enrolled[0].group}`;
check('it is let go once its window passes', await waitFor(() => !existsSync(halfDir), 30_000));
check('a finished account stays, however long it sits idle', existsSync(doneDir));

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
