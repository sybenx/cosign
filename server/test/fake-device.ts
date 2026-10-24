// A stand-in for a new device joining your key: it shows a code (printed), and when one
// of your devices vouches for it, it gets its shares from the helpers' sigmas, checks them,
// and from then on co-signs like the fake phone.
//
//   node test/fake-device.ts [name]        prints JOIN <cosign:join?… uri>
//   node test/fake-device.ts --resume      the one in DEVICE_STATE, back from being away

import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { getEventHash } from 'nostr-tools/pure';
import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../net.ts';
import { refreshing } from './refresh-member.ts';

const W = createRequire(import.meta.url)('../frost-wasm/cosign_frost.js');
const name = process.argv[2] ?? 'Test tablet';
const relays = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
const stateFile = process.env.DEVICE_STATE ?? '/tmp/cosign-fake-device.json';
let st: any = process.argv.includes('--resume') && existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : null;
const sk: string = st?.sk ?? F.bytesToHex(F.randomBytes(32));
const pk = pubOf(sk);
const say = (t: string) => console.log(`[device] ${t}`);
const got: { welcome?: any; sigmas: [number, number, string][]; server?: string } = { sigmas: [] };
const parts = new Parts();
const pool = new Pool(relays, e => {
  const msg = parts.take(e.pubkey, openFrom(sk, e));
  if (msg) handle(msg, e.pubkey);
});
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };
const rf = refreshing({ st: () => st, pk, send, save: () => writeFileSync(stateFile, JSON.stringify(st, null, 2)), say });

function handle(msg: any, from: string) {
  if (!st) {
    // A sigma per helper share for each new share: from the server's welcome and the vouching device.
    if (msg.type === 'welcome') { got.welcome = msg; got.server = from; got.sigmas.push(...(msg.sigmas ?? [[msg.k, 0, msg.sigma]])); }
    if (msg.type === 'sigma') got.sigmas.push(...(msg.sigmas ?? [[msg.k, -1, msg.sigma]]));
    const w = got.welcome;
    if (!w) return;
    const ks: number[] = w.ks ?? [w.k];
    const need = w.helpers?.length ?? 2;
    if (!ks.every(k => got.sigmas.filter(x => x[0] === k).length >= need)) return;
    const g = JSON.stringify({ groupX: w.group.groupX, threshold: w.group.threshold, members: Sig.sharePoints(w.group) });
    const shares = ks.map(k => ({ idx: k, secret: W.repairStep3(g, got.sigmas.filter(x => x[0] === k).map(x => x[2]), k) as string }));
    const points = shares.map(x => ({ idx: x.idx, sharePub: W.sharePub(x.secret) }));
    const me = { idx: ks[0], name, role: 'device', pk, sharePub: points[0].sharePub, ...(ks.length > 1 ? { shares: points } : {}) };
    st = { sk, idx: ks[0], shares, share: shares[0].secret, signer: w.signer, group: { ...w.group, members: [...w.group.members, me] } };
    writeFileSync(stateFile, JSON.stringify(st, null, 2));
    send(from === got.server ? from : got.server!, { type: 'joined', id: w.id, sharePubs: points.map(p => [p.idx, p.sharePub]), sharePub: points[0].sharePub });
    say(`JOINED ${w.group.npub} as member ${ks[0]} with shares ${ks.join(', ')}`);
    return;
  }
  if (msg.type === 'removed') return say(`REMOVED by ${msg.by}`);
  if (st.group.members.some((m: any) => m.pk === from) && rf.take(msg, from)) return;
  const srv = st.group.members.find((m: any) => m.pk === from && m.role === 'server');
  if (!srv) return;
  if (msg.type === 'sign_req') {
    const ev = msg.event;
    const reply = (r: object) => send(from, { type: 'sign_res', id: msg.id, ...r });
    if (ev.pubkey !== st.group.groupX || getEventHash(ev) !== msg.msg) return reply({ ok: false, reason: 'event mismatch' });
    const mine = Sig.commitAll(st.group, st.shares);
    const zs = Sig.partialAll(msg.frost === 2 ? 2 : 1, st.group, st.shares, mine.nonces, msg.msg, [...(msg.commits ?? [msg.commit]), ...mine.commits]);
    reply({ ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] });
    say(`co-signed kind ${ev.kind} for ${srv.name}`);
  } else if (msg.type === 'members') {
    st.group.members = msg.members;
    say(`members now ${msg.members.map((m: any) => m.name).join(', ')}`);
  }
}

pool.start([{ kinds: [KIND_MEMBER], '#p': [pk] }]);
if (st) { say(`back as member ${st.idx}`); setTimeout(() => ping(), 1500); }
else console.log(`JOIN cosign:join?pk=${pk}&name=${encodeURIComponent(name)}&${relays.map(r => 'r=' + encodeURIComponent(r)).join('&')}`);
const ping = () => { if (st) for (const s of st.group.members.filter((m: any) => m.role === 'server')) send(s.pk, { type: 'ping', idx: st.idx, ts: Date.now() }); };
setInterval(ping, 10_000);
