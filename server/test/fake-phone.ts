// A stand-in for the Android app, speaking the same protocol. Used by the e2e
// test, and handy for trying the servers without a phone.
//
//   node test/fake-phone.ts '<cosign:pair?... uri>' [--deny] [--state file]

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { getEventHash } from 'nostr-tools/pure';
import * as F from '../frost.ts';
import { Pool, sealTo, openFrom, pubOf, KIND_MEMBER } from '../net.ts';

const args = process.argv.slice(2);
const deny = args.includes('--deny');
const stateFile = args.includes('--state') ? args[args.indexOf('--state') + 1] : '/tmp/cosign-fake-phone.json';
const say = (t: string) => console.log(`[phone] ${t}`);
let e_id = '';

let st: any = existsSync(stateFile) && !args[0]?.startsWith('cosign:') ? JSON.parse(readFileSync(stateFile, 'utf8')) : null;
let pairUri: URL | null = args[0]?.startsWith('cosign:') ? new URL(args[0].replace('cosign:', 'cosign://')) : null;
const sk: string = st?.sk ?? F.bytesToHex(F.randomBytes(32));
const pk = pubOf(sk);
const relays = st?.group.relays ?? pairUri!.searchParams.getAll('r');

const pool = new Pool(relays, e => {
  if (e.kind !== KIND_MEMBER) return;
  const msg = openFrom(sk, e);
  if (msg && (msg.type === 'sign_req' || msg.type === 'ecdh_req') && Date.now() / 1000 - e.created_at > 30) return; // replayed
  if (msg) { e_id = e.id.slice(0, 8); handle(msg, e.pubkey); }
});
const send = (to: string, m: object) => pool.publish(sealTo(sk, to, m));
const servers = () => st.group.members.filter((m: any) => m.role === 'server');

function handle(msg: any, from: string) {
  if (msg.type === 'pair_offer' && !st && from === pairUri?.searchParams.get('pk')) {
    // The real app asks here: "Join npub… as 1 of 3?"
    st = { sk, idx: msg.idx, share: msg.share, group: msg.group };
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
    const auto = st.group.autoKinds.includes(ev.kind);
    if (!auto && deny) { say(`declined kind ${ev.kind} req=${msg.id} ev=${e_id}`); return reply({ ok: false, reason: 'declined on the phone' }); }
    const mine = F.commit(st.idx);
    const z = F.partialSign({ groupX: st.group.groupX, msg: msg.msg, commits: [msg.commit, mine.commit], idx: st.idx, secret: st.share, nonces: mine.nonces });
    say(`${auto ? 'auto-signed' : 'APPROVED'} kind ${ev.kind} for ${srv.name}`);
    reply({ ok: true, commit: mine.commit, z });
  } else if (msg.type === 'ecdh_req') {
    const point = F.ecdhPartial({ idx: st.idx, secret: st.share, participants: msg.participants, peerX: msg.peerX });
    send(from, { type: 'ecdh_res', id: msg.id, ok: true, point });
  }
}

pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
setTimeout(() => {
  if (!st && pairUri) { say('sending pair_hello'); send(pairUri.searchParams.get('pk')!, { type: 'pair_hello', token: pairUri.searchParams.get('t') }); }
}, 1500);
setInterval(() => { if (st) for (const s of servers()) send(s.pk, { type: 'ping', idx: st.idx, ts: Date.now() }); }, 10_000);
setTimeout(() => { if (st) for (const s of servers()) send(s.pk, { type: 'ping', idx: st.idx, ts: Date.now() }); }, 2500);
