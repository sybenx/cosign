// "Create account": a device makes a brand-new key with one shared server it has never
// used, with no code and no setup step: it asks the server's host key for a member key,
// enrolls a group whose key doesn't exist yet (`how: 'dkg'`), and the two make it
// together (the device 3 shares, the server 1, any 4 sign). Then a site signs through
// the server with the device co-signing; without the device, the server alone can't.
//
//   node test/create.e2e.ts        (starts and stops everything itself, in server/test-create/)

import { readFileSync, readdirSync, openSync, mkdirSync } from 'node:fs';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { verifyEvent, getEventHash } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../../server/net.ts';
import * as Sig from '../../server/sign.ts';
import * as F from '../../server/frost.ts';
import { DkgRun } from '../../server/dkg.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 32) => bytesToHex(randomBytes(n));

execFileSync('rm', ['-rf', serverDir + 'test-create']);
mkdirSync(serverDir + 'logs', { recursive: true });
const log = openSync(serverDir + 'logs/create-host.log', 'w');
const hostProc = spawn('node', ['server.ts', '--root', 'test-create/h', '--port', '8995'], { cwd: serverDir, env: { ...process.env, COSIGN_ENROLL: 'open' }, stdio: ['ignore', log, log] });
const done = (code: number) => { hostProc.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-create']); process.exit(code); };
await sleep(3000);
const host = JSON.parse(readFileSync(serverDir + 'test-create/h/host.json', 'utf8'));

// --- The device -----------------------------------------------------------------------

const sk = hex(), pk = pubOf(sk);
const relays = host.relays as string[];
const replies = new Map<string, any>();
let dkg: DkgRun | null = null;
let me: any = null; // { group, shares } once the key is made
let answering = true;
const parts = new Parts();
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };
const pool = new Pool(relays, e => {
  const m = parts.take(e.pubkey, openFrom(sk, e));
  if (!m) return;
  if (m.type === 'dkg1' || m.type === 'dkg2') return dkg?.take(m, e.pubkey);
  if (m.id && (m.type.startsWith('enroll'))) return void replies.set(m.id, m);
  if (!me || !answering) return;
  if (m.type === 'sign_req') {
    const ev = m.event;
    if (ev.pubkey !== me.group.groupX || getEventHash(ev) !== m.msg) return;
    const mine = Sig.commitAll(me.group, me.shares);
    const zs = Sig.partialAll(2, me.group, me.shares, mine.nonces, m.msg, [...m.commits, ...mine.commits]);
    send(e.pubkey, { type: 'sign_res', id: m.id, ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] });
  } else if (m.type === 'ecdh_req') {
    const points = me.shares.map((s: Sig.Share) => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants: m.participants, peerX: m.peerX }));
    send(e.pubkey, { type: 'ecdh_res', id: m.id, ok: true, points, point: points[0] });
  }
});
pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
await sleep(2000);

async function ask(msg: any) {
  msg.id = hex(8);
  const until = Date.now() + 25_000;
  while (!replies.has(msg.id) && Date.now() < until) {
    send(host.pk, msg);
    await waitFor(() => replies.has(msg.id), 4000);
  }
  return replies.get(msg.id) ?? { type: 'no answer' };
}

const key = await ask({ type: 'enroll_key' });
check('the server hands out a member key', key.type === 'enroll_key' && /^[0-9a-f]{64}$/.test(key.pk));

const signerSk = hex();
const group = {
  threshold: 4, relays,
  members: [
    { idx: 1, name: 'Test browser', role: 'phone', pk, sharePub: '', shares: [1, 2, 3].map(idx => ({ idx, sharePub: '' })) },
    { idx: 4, name: 'Shared server', role: 'server', pk: key.pk, sharePub: '' },
  ],
};
const plan = { session: hex(16), threshold: 4, holders: [{ idx: 1, pk }, { idx: 2, pk }, { idx: 3, pk }, { idx: 4, pk: key.pk }] };

const bad = await ask({ type: 'enroll', how: 'dkg', key: key.key, group, plan: { ...plan, holders: plan.holders.map(h => h.idx === 4 ? { ...h, idx: 3 } : h) }, signer: { sk: signerSk, pk: pubOf(signerSk) } });
check('a plan that disagrees with the record is refused', bad.type === 'enroll_failed' && bad.reason.startsWith('bad-'), bad.reason);

const t0 = Date.now();
const enrolled = await ask({ type: 'enroll', how: 'dkg', key: key.key, group, plan, signer: { sk: signerSk, pk: pubOf(signerSk) } });
check('the server takes on a group with no key yet', enrolled.type === 'enrolled', enrolled.reason ?? enrolled.group);
if (enrolled.type !== 'enrolled') done(1);

let made: any = null;
dkg = new DkgRun(plan, pk, send, r => { made = r; });
dkg.start();
await waitFor(() => !!made, 60_000);
check('the device and the server make the key', !!made, `${Date.now() - t0} ms`);
if (!made) done(1);
const stateFile = serverDir + `test-create/h/groups/${enrolled.group}/state.json`;
await waitFor(() => !!JSON.parse(readFileSync(stateFile, 'utf8')).group.groupX, 15_000);
const st = JSON.parse(readFileSync(stateFile, 'utf8'));
check('the server has the same key, and one share of it', st.group.groupX === made.groupX && st.self.shares.length === 1 && st.self.shares[0].idx === 4 && !st.dkg);
check('the device has 3', made.shares.length === 3);

const points = new Map<number, string>(made.members.map((m: any) => [m.idx, m.sharePub]));
me = {
  shares: made.shares,
  group: { groupX: made.groupX, threshold: 4, members: group.members.map(m => ({ ...m, sharePub: points.get(m.idx)!, ...(m.shares ? { shares: m.shares.map(s => ({ idx: s.idx, sharePub: points.get(s.idx)! })) } : {}) })) },
};
const ping = setInterval(() => send(key.pk, { type: 'ping', idx: 1, ts: Date.now() }), 5000);
send(key.pk, { type: 'ping', idx: 1, ts: Date.now() });
await sleep(2000);

// A site, by ticket from the device.
const t = hex(16);
send(key.pk, { type: 'ticket', t, origin: 'create.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(pubOf(signerSk), relays));
try { await site.connect(t); } catch (e) { check('a site connects', false, String(e)); done(1); }
check('a site gets the new key', (await site.getPublicKey()) === made.groupX);
const note = await site.signEvent({ kind: 1, content: 'a key made with a shared server', tags: [] }).catch(e => e);
check('the device (3) and the server (1) sign', verifyEvent(note) && note.pubkey === made.groupX, String(note?.message ?? ''));
const f = await site.signEvent({ kind: 3, content: '', tags: [['p', hex()]] }).catch(e => e);
check('a follow list too', verifyEvent(f), String(f?.message ?? ''));

answering = false; clearInterval(ping);
const err = await site.signEvent({ kind: 1, content: 'server alone', tags: [] }).then(() => null, e => e as Error);
check('the server alone can’t', !!err, err?.message);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
