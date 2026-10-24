// A stand-in for the Android app's answering half: joins the group, co-signs, and
// approves (or, with --deny, declines) anything held for the phone.
//
//   node test/fake-phone.ts '<cosign:pair?... uri>' [--deny]
//   node test/fake-phone.ts [--deny]        reuse /tmp/cosign-fake-phone.json

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { getEventHash } from 'nostr-tools/pure';
import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../net.ts';

const args = process.argv.slice(2);
const deny = args.includes('--deny');
const stateFile = process.env.PHONE_STATE ?? '/tmp/cosign-fake-phone.json';
const say = (t: string) => console.log(`[phone] ${t}`);

const pairUri = args[0]?.startsWith('cosign:') ? new URL(args[0].replace('cosign:', 'cosign://')) : null;
let st: any = !pairUri && existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : null;
const sk: string = st?.sk ?? F.bytesToHex(F.randomBytes(32));
const pk = pubOf(sk);
const relays = st?.group.relays ?? pairUri!.searchParams.getAll('r');

const pool = new Pool(relays, e => {
  if (e.kind !== KIND_MEMBER) return;
  const msg = parts.take(e.pubkey, openFrom(sk, e));
  if (!msg) return;
  if ((msg.type === 'sign_req' || msg.type === 'ecdh_req') && Date.now() / 1000 - e.created_at > 30) return; // replayed
  handle(msg, e.pubkey);
});
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };
const parts = new Parts();
const decided = new Set<string>();
const servers = () => st.group.members.filter((m: any) => m.role === 'server');

function handle(msg: any, from: string) {
  if (msg.type === 'pair_offer' && !st && from === pairUri?.searchParams.get('pk')) {
    st = { sk, idx: msg.idx, share: msg.share, signer: msg.signer, group: msg.group };
    st.group.members.find((m: any) => m.idx === msg.idx).pk = pk;
    writeFileSync(stateFile, JSON.stringify(st, null, 2));
    send(from, { type: 'pair_ack', token: msg.token });
    say(`joined ${st.group.npub} as member ${st.idx}`);
    return;
  }
  if (!st) return;
  const srv = st.group.members.find((m: any) => m.pk === from && m.role === 'server');
  if (!srv) return;
  if (msg.type === 'sign_req') {
    const ev = msg.event;
    const reply = (r: object) => send(from, { type: 'sign_res', id: msg.id, ...r });
    if (ev.pubkey !== st.group.groupX || getEventHash(ev) !== msg.msg) return reply({ ok: false, reason: 'event mismatch' });
    if (msg.hold && !msg.undo && deny) { say(`DECLINED: ${msg.hold}`); return reply({ ok: false, reason: 'declined on the phone' }); }
    const mine = Sig.commit(st.group, st.idx, st.share);
    const z = Sig.partial(msg.frost === 2 && !process.env.OLD_MATH ? 2 : 1, st.group, st.idx, st.share, mine.nonces, msg.msg, [msg.commit, mine.commit]);
    say(msg.hold && !msg.undo ? `APPROVED: ${msg.hold}` : msg.undo ? `co-signed an undo for ${srv.name}` : `co-signed kind ${ev.kind} for ${srv.name} (a server is down)`);
    reply({ ok: true, commit: mine.commit, z });
  } else if (msg.type === 'ecdh_req') {
    send(from, { type: 'ecdh_res', id: msg.id, ok: true, point: F.ecdhPartial({ idx: st.idx, secret: st.share, participants: msg.participants, peerX: msg.peerX }) });
  } else if (msg.type === 'repair') {
    // Vouching for a new device: our part of its share, half to the server, half to it.
    const d = Sig.repairStep1(st.group, st.idx, st.share, msg.helpers, msg.k);
    const sigma = Sig.repairStep2([d.find(x => x[0] === st.idx)![1], msg.delta]);
    send(from, { type: 'repair_delta', id: msg.id, delta: d.find(x => x[0] === srv.idx)![1] });
    send(msg.pk, { type: 'sigma', id: msg.id, k: msg.k, sigma });
    say(`vouched for a new device as member ${msg.k}`);
  } else if (msg.type === 'members') {
    st.group.members = msg.members.map((m: any) => ({ ...m, pk: m.idx === st.idx ? pk : m.pk }));
    writeFileSync(stateFile, JSON.stringify(st, null, 2));
    say(`members now ${st.group.members.map((m: any) => m.name).join(', ')}`);
  } else if (msg.type === 'deleting') {
    say(`deleting ${msg.count} for ${msg.by}`);
    if (process.env.CANCEL_DELETES) { send(from, { type: 'cancel_batch', batch: msg.batch }); say('UNDO tapped'); }
  } else if (msg.type === 'approve_batch') {
    if (decided.has(msg.batch)) return; // the server asks again in case a relay dropped it; the app ignores repeats too
    decided.add(msg.batch);
    say(`${deny ? 'DECLINED' : 'APPROVED'} batch: ${msg.text}`);
    send(from, { type: 'batch_decision', batch: msg.batch, approve: !deny });
  } else if (msg.type === 'state') {
    say(`state: ${msg.sites.length} site(s), ${msg.changes.length} change(s)`);
  }
}

pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
setTimeout(() => { if (!st && pairUri) send(pairUri.searchParams.get('pk')!, { type: 'pair_hello', token: pairUri.searchParams.get('t') }); }, 1500);
const ping = () => { if (st) for (const s of servers()) send(s.pk, { type: 'ping', idx: st.idx, ts: Date.now() }); };
setInterval(ping, 10_000); setTimeout(ping, 2500);
