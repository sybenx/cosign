// A Cosign server running as a Cloudflare Worker (../../worker), reached as the relay it
// is: a device makes a key with it by DKG (device 3 shares, the Worker 1), then runs
// signing rounds itself with the Worker co-signing (as the phone does for an app on it,
// NIP-55), and a shared secret (ECDH). The Worker holds no signer key, so it never answers
// sites; that's the other servers' job.
//
//   (cd worker && npx wrangler dev --port 8800 --var COSIGN_URL:ws://127.0.0.1:8800)
//   node test/worker.e2e.ts [ws://127.0.0.1:8800]

import { generateSecretKey, getPublicKey, getEventHash, type Event } from 'nostr-tools/pure';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';
import * as Sig from '../../server/sign.ts';
import * as F from '../../server/frost.ts';
import { DkgRun } from '../../server/dkg.ts';

const url = process.argv[2] ?? 'ws://127.0.0.1:8800';
const status = await (await fetch(url.replace(/^ws/, 'http') + '/status')).json() as any;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(200); return pred(); };
const hex = (n = 32) => bytesToHex(randomBytes(n));

const sk = hex(), pk = getPublicKey(hexToBytes(sk));
const replies = new Map<string, any>();
let dkg: DkgRun | null = null;
const parts = new Parts();
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };
const pool = new Pool([url], (e: Event) => {
  const m = parts.take(e.pubkey, openFrom(sk, e));
  if (!m) return;
  if (m.type === 'dkg1' || m.type === 'dkg2') return dkg?.take(m, e.pubkey);
  if (m.id) replies.set(m.id, m);
});
pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
await sleep(1500);
async function ask(to: string, msg: any, ms = 20_000) {
  msg.id ??= hex(8);
  const until = Date.now() + ms;
  while (!replies.has(msg.id) && Date.now() < until) { send(to, msg); await waitFor(() => replies.has(msg.id), 3000); }
  return replies.get(msg.id) ?? { type: 'no answer' };
}

const key = await ask(status.host, { type: 'enroll_key' });
check('the Worker hands out a member key', key.type === 'enroll_key', key.reason);
const group = {
  threshold: 4, relays: [url],
  members: [
    { idx: 1, name: 'Test device', role: 'phone', pk, sharePub: '', shares: [1, 2, 3].map(idx => ({ idx, sharePub: '' })) },
    { idx: 4, name: 'Worker', role: 'server', pk: key.pk, sharePub: '' },
  ],
};
const plan = { session: hex(16), threshold: 4, holders: [{ idx: 1, pk }, { idx: 2, pk }, { idx: 3, pk }, { idx: 4, pk: key.pk }] };
const t0 = Date.now();
const enrolled = await ask(status.host, { type: 'enroll', how: 'dkg', key: key.key, group, plan });
check('it takes on a group with no key yet', enrolled.type === 'enrolled', enrolled.reason ?? enrolled.group);
let made: any = null;
dkg = new DkgRun(plan, pk, send, r => { made = r; });
dkg.start();
check('the device and the Worker make a key', await waitFor(() => !!made, 60_000), `${Date.now() - t0} ms`);
if (!made) process.exit(1);

const points = new Map<number, string>(made.members.map((m: any) => [m.idx, m.sharePub]));
const g: Sig.Group = { groupX: made.groupX, threshold: 4, members: group.members.map(m => ({ idx: m.idx, sharePub: points.get(m.idx)!, ...(m.shares ? { shares: m.shares.map(s => ({ idx: s.idx, sharePub: points.get(s.idx)! })) } : {}) })) };

// An app on the device, as NIP-55 does it: grant it, then rounds the device runs.
const grant = hex();
send(key.pk, { type: 'app_grant', pk: grant, origin: 'Test app', via: 'Test device' });
await sleep(2000);
const ev = { pubkey: made.groupX, kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'signed with a Worker' };
const id = getEventHash(ev as any);
const mine = Sig.commitAll(g, made.shares);
const t1 = Date.now();
const res = await ask(key.pk, { type: 'cosign_req', event: ev, msg: id, participants: [1, 2, 3, 4], commits: mine.commits, commit: mine.commits[0], frost: 2, grant, approved: false });
check('the Worker co-signs a round the device runs', res.ok === true, `${Date.now() - t1} ms ${res.reason ?? ''}`);
if (res.ok) {
  const commits = [...mine.commits, ...res.commits];
  const zs = Sig.partialAll(2, g, made.shares, mine.nonces, id, commits);
  const sig = Sig.combine(2, g, id, commits, [...zs, ...res.zs]);
  check('and the signature is plain BIP-340 under the key', schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(made.groupX)));
}
const peer = generateSecretKey(), peerX = getPublicKey(peer);
const e2 = await ask(key.pk, { type: 'ecdh_req', peerX, participants: [1, 2, 3, 4], grant });
if (e2.ok) {
  const mineP = made.shares.map((s: any) => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants: [1, 2, 3, 4], peerX }));
  const x = F.ecdhCombine([...mineP, ...(e2.points ?? [e2.point])]);
  const expect = bytesToHex(secp256k1.getSharedSecret(peer, hexToBytes('02' + made.groupX)).slice(1));
  check('a shared secret with the Worker matches the key’s', x === expect || bytesToHex(x as any) === expect);
} else check('a shared secret with the Worker', false, e2.reason);
const page = await (await fetch(url.replace(/^ws/, 'http') + '/status')).json() as any;
check('its page counts the key', page.groups >= 1);
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
