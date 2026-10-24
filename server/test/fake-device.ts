// A stand-in for a new device joining your key: it shows a code (printed), and when one
// of your devices vouches for it, it gets its share from two helpers' sigmas, checks it,
// and from then on co-signs like the fake phone.
//
//   node test/fake-device.ts [name]        prints JOIN <cosign:join?… uri>

import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { getEventHash } from 'nostr-tools/pure';
import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../net.ts';

const W = createRequire(import.meta.url)('../frost-wasm/cosign_frost.js');
const name = process.argv[2] ?? 'Test tablet';
const relays = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
const sk = F.bytesToHex(F.randomBytes(32));
const pk = pubOf(sk);
const say = (t: string) => console.log(`[device] ${t}`);
let st: any = null;
const got: { welcome?: any; sigma?: string; server?: string } = {};
const parts = new Parts();
const pool = new Pool(relays, e => {
  const msg = parts.take(e.pubkey, openFrom(sk, e));
  if (msg) handle(msg, e.pubkey);
});
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };

function handle(msg: any, from: string) {
  if (!st) {
    if (msg.type === 'welcome') { got.welcome = msg; got.server = from; }
    if (msg.type === 'sigma') got.sigma = msg.sigma;
    if (got.welcome && got.sigma) {
      const w = got.welcome;
      const share = W.repairStep3(JSON.stringify({ groupX: w.group.groupX, threshold: w.group.threshold, members: w.group.members }), [w.sigma, got.sigma], w.k);
      st = { sk, idx: w.k, share, signer: w.signer, group: { ...w.group, members: [...w.group.members, { idx: w.k, name, role: 'device', pk, sharePub: W.sharePub(share) }] } };
      writeFileSync('/tmp/cosign-fake-device.json', JSON.stringify(st, null, 2));
      send(from, { type: 'joined', id: w.id, sharePub: W.sharePub(share) });
      say(`JOINED ${w.group.npub} as member ${w.k}`);
    }
    return;
  }
  const srv = st.group.members.find((m: any) => m.pk === from && m.role === 'server');
  if (!srv) return;
  if (msg.type === 'sign_req') {
    const ev = msg.event;
    const reply = (r: object) => send(from, { type: 'sign_res', id: msg.id, ...r });
    if (ev.pubkey !== st.group.groupX || getEventHash(ev) !== msg.msg) return reply({ ok: false, reason: 'event mismatch' });
    const mine = Sig.commit(st.group, st.idx, st.share);
    reply({ ok: true, commit: mine.commit, z: Sig.partial(msg.frost === 2 ? 2 : 1, st.group, st.idx, st.share, mine.nonces, msg.msg, [msg.commit, mine.commit]) });
    say(`co-signed kind ${ev.kind} for ${srv.name}`);
  } else if (msg.type === 'members') {
    st.group.members = msg.members;
    say(`members now ${msg.members.map((m: any) => m.name).join(', ')}`);
  }
}

pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
console.log(`JOIN cosign:join?pk=${pk}&name=${encodeURIComponent(name)}&${relays.map(r => 'r=' + encodeURIComponent(r)).join('&')}`);
const ping = () => { if (st) for (const s of st.group.members.filter((m: any) => m.role === 'server')) send(s.pk, { type: 'ping', idx: st.idx, ts: Date.now() }); };
setInterval(ping, 10_000);
