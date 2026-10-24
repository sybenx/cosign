// A stand-in for the Android app's answering half: joins the group, co-signs, and
// approves (or, with --deny, declines) anything held for the phone.
//
//   node test/fake-phone.ts '<cosign:pair?... uri>' [--deny]
//   node test/fake-phone.ts [--deny]        reuse /tmp/cosign-fake-phone.json
//   node test/fake-phone.ts --restore <paper.json>   a new phone, from a paper backup

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { getEventHash } from 'nostr-tools/pure';
import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { DkgRun } from '../dkg.ts';
import { refreshing } from './refresh-member.ts';
import { restoreShares } from '../backup.ts';
import * as nip44 from 'nostr-tools/nip44';
import { nip19 } from 'nostr-tools';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../net.ts';

const args = process.argv.slice(2);
const deny = args.includes('--deny');
const stateFile = process.env.PHONE_STATE ?? '/tmp/cosign-fake-phone.json';
const say = (t: string) => console.log(`[phone] ${t}`);

const pairUri = args[0]?.startsWith('cosign:') ? new URL(args[0].replace('cosign:', 'cosign://')) : null;
/** A paper backup this phone is restoring from: its key, its servers, its relays. */
const paper = args[0] === '--restore' ? JSON.parse(readFileSync(args[1], 'utf8')) : null;
let st: any = !pairUri && !paper && existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : null;
const sk: string = st?.sk ?? F.bytesToHex(F.randomBytes(32));
const pk = pubOf(sk);
const relays = st?.group.relays ?? paper?.relays ?? pairUri!.searchParams.getAll('r');
const paperPk = paper ? pubOf(paper.sk) : null;

const pool = new Pool(relays, e => {
  if (e.kind !== KIND_MEMBER) return;
  const toPaper = paperPk && e.tags.some(t => t[0] === 'p' && t[1] === paperPk);
  const msg = parts.take(e.pubkey, openFrom(toPaper ? paper.sk : sk, e));
  if (!msg) return;
  if ((msg.type === 'sign_req' || msg.type === 'ecdh_req') && Date.now() / 1000 - e.created_at > 30) return; // replayed
  if (String(msg.type).startsWith('test_') && Date.now() / 1000 - e.created_at > 15) return; // a trigger from before a restart
  handle(msg, e.pubkey);
});
const send = (to: string, m: object) => { for (const e of sealParts(sk, to, m)) pool.publish(e); };
const parts = new Parts();
const decided = new Set<string>();
const servers = () => st.group.members.filter((m: any) => m.role === 'server');

let dkg: DkgRun | null = null;
/** My shares: one from the earlier dealer, three in a weighted key. */
const myShares = (): Sig.Share[] => st.shares ?? [{ idx: st.idx, secret: st.share }];
const rf = refreshing({ st: () => st, pk, send: (to, m) => send(to, m), save: () => writeFileSync(stateFile, JSON.stringify(st, null, 2)), say });

let making: { id: string; sk: string; pk: string } | null = null; // a paper backup being made
let restoring = false;
const sendAsPaper = (to: string, m: object) => { for (const e of sealParts(paper.sk, to, m)) pool.publish(e); };

function handle(msg: any, from: string) {
  // Restoring from paper: the servers answer the paper's key, then this phone's when it's done.
  if (paper && !st) {
    if (msg.type === 'backup' && !restoring) {
      restoring = true;
      try {
        const shares = restoreShares(paper.sk, msg);
        say(`paper read: shares ${shares.map(x => x.idx).join(', ')}`);
        restored = { shares, signer: msg.signer, group: msg.group, epoch: msg.epochNow };
        for (const srv of paper.servers) sendAsPaper(srv, { type: 'recover', pk, name: 'Restored phone' });
      } catch (e: any) { say(`PAPER FAILED: ${e.message}`); }
    } else if (msg.type === 'recovering') say(`waiting until ${new Date(msg.until * 1000).toISOString()}`);
    else if (msg.type === 'recovery_cancelled') say(`CANCELLED by ${msg.by}`);
    else if (msg.type === 'recovered' && restored) {
      const me = restored.group.members.find((m: any) => m.idx === msg.idx);
      Object.assign(me, { role: 'device', pk, name: 'Restored phone' });
      st = { sk, idx: msg.idx, shares: restored.shares, signer: restored.signer, group: restored.group, epoch: restored.epoch };
      writeFileSync(stateFile, JSON.stringify(st, null, 2));
      say(`RECOVERED as member ${msg.idx}`);
    }
    return;
  }
  if (msg.type === 'dkg1' || msg.type === 'dkg2') return dkg?.take(msg, from);
  if (msg.type === 'pair_offer' && msg.weighted && !st && !dkg && from === pairUri?.searchParams.get('pk')) {
    // No key yet: make it with both servers, then tell this one.
    const offer = msg;
    dkg = new DkgRun(offer.plan, pk, send, r => {
      const group = { ...offer.group, groupX: r.groupX, npub: nip19.npubEncode(r.groupX) };
      const mine = r.shares.map(s => s.idx);
      for (const m of group.members) {
        const idxs: number[] = m.shares?.map((s: any) => s.idx) ?? [m.idx];
        const pts = idxs.map(idx => ({ idx, sharePub: r.members.find(x => x.idx === idx)!.sharePub }));
        m.sharePub = pts[0].sharePub; if (m.shares) m.shares = pts;
        if (idxs.includes(mine[0])) m.pk = pk;
      }
      st = { sk, idx: mine[0], shares: r.shares, signer: offer.signer, group };
      writeFileSync(stateFile, JSON.stringify(st, null, 2));
      const ack = () => send(from, { type: 'pair_ack', token: offer.token, groupX: r.groupX });
      ack(); setTimeout(ack, 4000);
      say(`made ${group.npub} with the servers; holding shares ${mine.join(', ')}`);
    });
    dkg.start();
    say('making the key with the servers');
    return;
  }
  if (msg.type === 'pair_offer' && !msg.weighted && !st && from === pairUri?.searchParams.get('pk')) {
    st = { sk, idx: msg.idx, share: msg.share, signer: msg.signer, group: msg.group };
    st.group.members.find((m: any) => m.idx === msg.idx).pk = pk;
    writeFileSync(stateFile, JSON.stringify(st, null, 2));
    send(from, { type: 'pair_ack', token: msg.token });
    say(`joined ${st.group.npub} as member ${st.idx}`);
    return;
  }
  if (!st) return;
  // The test reports a device lost as this phone, by writing to it from its own key.
  if (msg.type === 'test_report' && from === pk) return rf.report(Number(msg.idx));
  // Likewise for making a paper backup: written to PAPER_FILE.
  if (msg.type === 'test_backup' && from === pk) {
    const bsk = F.bytesToHex(F.randomBytes(32));
    making = { id: F.bytesToHex(F.randomBytes(6)), sk: bsk, pk: pubOf(bsk) };
    send(servers()[0].pk, { type: 'add_device', id: making.id, pk: making.pk, name: 'Paper backup', lock: true, backup: true });
    return say('making a paper backup');
  }
  if (st.group.members.some((m: any) => m.pk === from) && rf.take(msg, from)) return;
  const srv = st.group.members.find((m: any) => m.pk === from && m.role === 'server');
  if (!srv) return;
  if (msg.type === 'sign_req') {
    const ev = msg.event;
    const reply = (r: object) => send(from, { type: 'sign_res', id: msg.id, ...r });
    if (ev.pubkey !== st.group.groupX || getEventHash(ev) !== msg.msg) return reply({ ok: false, reason: 'event mismatch' });
    if (msg.hold && !msg.undo && deny) { say(`DECLINED: ${msg.hold}`); return reply({ ok: false, reason: 'declined on the phone' }); }
    const shares = myShares();
    const mine = Sig.commitAll(st.group, shares);
    const zs = Sig.partialAll(msg.frost === 2 && !process.env.OLD_MATH ? 2 : 1, st.group, shares, mine.nonces, msg.msg, [...(msg.commits ?? [msg.commit]), ...mine.commits]);
    say(msg.hold && !msg.undo ? `APPROVED: ${msg.hold}` : msg.undo ? `co-signed an undo for ${srv.name}` : `co-signed kind ${ev.kind} for ${srv.name} (a server is down)`);
    reply({ ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] });
  } else if (msg.type === 'ecdh_req') {
    const points = myShares().map(s => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants: msg.participants, peerX: msg.peerX }));
    send(from, { type: 'ecdh_res', id: msg.id, ok: true, points, point: points[0] });
  } else if (msg.type === 'repair') {
    // Vouching for a new device: each of our shares splits its part of each new share
    // into deltas; the server's go to it, ours are summed here into sigmas for the device.
    const mine = myShares(), idxs = mine.map(x => x.idx);
    const ks: number[] = msg.ks ?? [msg.k];
    const fromSrv: [number, number, number, string][] = msg.deltas ?? [[msg.k, srv.idx, st.idx, msg.delta]];
    const local = new Map<string, string[]>(); const toSrv: [number, number, number, string][] = [];
    for (const k of ks) for (const x of mine) for (const [j, d] of Sig.repairStep1(st.group, x.idx, x.secret, msg.helpers, k)) {
      if (idxs.includes(j)) local.set(`${k}:${j}`, [...local.get(`${k}:${j}`) ?? [], d]); else toSrv.push([k, x.idx, j, d]);
    }
    const sigmas = ks.flatMap(k => idxs.map(j => [k, j, Sig.repairStep2([...local.get(`${k}:${j}`) ?? [], ...fromSrv.filter(t => t[0] === k && t[2] === j).map(t => t[3])])]));
    const one = sigmas.length === 1;
    send(from, { type: 'repair_delta', id: msg.id, deltas: toSrv, ...(one ? { delta: toSrv[0][3] } : {}) });
    if (making && msg.pk === making.pk) {
      // A paper: our pieces, sealed to it, kept by the servers.
      send(from, { type: 'backup_piece', id: msg.id, content: nip44.v2.encrypt(JSON.stringify({ sigmas }), nip44.v2.utils.getConversationKey(F.hexToBytes(sk), making.pk)) });
      return;
    }
    send(msg.pk, { type: 'sigma', id: msg.id, sigmas, ...(one ? { k: ks[0], sigma: sigmas[0][2] } : {}) });
    say(`vouched for a new device: shares ${ks.join(', ')}`);
  } else if (msg.type === 'backup_made' && making) {
    writeFileSync(process.env.PAPER_FILE ?? '/tmp/cosign-paper.json', JSON.stringify({ sk: making.sk, servers: servers().map((m: any) => m.pk), relays: st.group.relays }));
    say('PAPER made');
    making = null;
  } else if (msg.type === 'recovery') {
    say(`RECOVERY asked for ${msg.name}`);
    if (process.env.CANCEL_RECOVERY) for (const s of servers()) send(s.pk, { type: 'cancel_recovery', lock: true });
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

let restored: any = null;
pool.start([{ kinds: [KIND_MEMBER], '#p': paperPk ? [pk, paperPk] : [pk] }]);
if (paper) {
  // Ask every server for the paper's pieces, then, while waiting, whether the wait is over.
  const ask = () => { if (st) return; for (const srv of paper.servers) sendAsPaper(srv, restored ? { type: 'recover_finish' } : { type: 'backup_get' }); };
  setTimeout(ask, 2000); setInterval(ask, 5000);
}
const hello = () => { if (!st && !dkg && pairUri) send(pairUri.searchParams.get('pk')!, { type: 'pair_hello', token: pairUri.searchParams.get('t') }); };
setTimeout(hello, 1500); setInterval(hello, 6000);
const ping = () => { if (st) for (const s of servers()) send(s.pk, { type: 'ping', idx: st.idx, ts: Date.now() }); };
setInterval(ping, 10_000); setTimeout(ping, 2500);
