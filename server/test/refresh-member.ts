// A device's side of report lost and refresh (refresh.ts), for the test phone and the
// test device: making the plan when it reports one lost, following a plan someone else
// made, and reading what the servers kept for it while it was away (mail).

import * as nip44 from 'nostr-tools/nip44';
import { RefreshRun, type RefreshPlan, type RefreshResult } from '../refresh.ts';
import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';

export interface DeviceState { sk: string; idx: number; shares?: { idx: number; secret: string }[]; share?: string; epoch?: number; group: { threshold: number; members: any[]; groupX?: string }; pending?: RefreshResult & { id?: string } }

export function refreshing(o: { st: () => DeviceState; pk: string; send: (to: string, msg: object) => void; save: () => void; say: (t: string) => void }) {
  let run: RefreshRun | null = null;
  const shares = () => o.st().shares ?? [{ idx: o.st().idx, secret: o.st().share! }];
  const idxsOf = (m: any): number[] => m.shares?.map((s: any) => s.idx) ?? [m.idx];
  const points = () => new Map<number, string>(o.st().group.members.flatMap((m: any) => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]).map((p: any) => [p.idx, p.sharePub]));
  const servers = () => o.st().group.members.filter((m: any) => m.role === 'server' && !m.removed);

  function done(r: RefreshResult) {
    const st = o.st(), at = new Map(r.points);
    for (const m of st.group.members) {
      if (!idxsOf(m).every(i => at.has(i))) continue;
      const pts = idxsOf(m).map(idx => ({ idx, sharePub: at.get(idx)! }));
      m.sharePub = pts[0].sharePub;
      if (m.shares) m.shares = pts;
    }
    st.shares = r.shares; delete st.share; st.epoch = r.epoch;
    o.save();
    for (const s of servers()) o.send(s.pk, { type: 'refreshed', epoch: r.epoch });
    o.say(`refreshed to epoch ${r.epoch}`);
  }

  // A periodic refresh (COSIGN.md §7.7): the new shares wait as pending until it's committed.
  // The device that asked for it checks it with each server first, then commits.
  let checking: { epoch: number; msg: string; g: Sig.Group; nonces: Record<number, string>; commits: Sig.Commit[]; ok: Set<string>; commitTo: 'all' | 'first' | 'none' } | null = null;
  const checkMessage = (epoch: number) => F.bytesToHex(sha256(utf8ToBytes(`cosign-refresh:${o.st().group.groupX}:${epoch}`)));
  function pendingGroup(r: RefreshResult): Sig.Group {
    const at = new Map(r.points);
    return { groupX: o.st().group.groupX!, threshold: o.st().group.threshold, members: o.st().group.members.filter((m: any) => !m.removed).map((m: any) => ({
      idx: m.idx, sharePub: at.get(idxsOf(m)[0]) ?? m.sharePub,
      ...(m.shares ? { shares: m.shares.map((x: any) => ({ idx: x.idx, sharePub: at.get(x.idx) ?? x.sharePub })) } : {}),
    })) };
  }
  const committedIds = new Set<string>();
  function pending(r: RefreshResult, check: false | 'all' | 'first' | 'none', id?: string) {
    o.st().pending = { ...r, id }; o.save();
    o.say(`pending epoch ${r.epoch}`);
    // The servers may have committed it before our part of the run finished.
    if (id && committedIds.has(`${r.epoch}:${id}`)) return committed(r.epoch, id);
    if (!check) return;
    const g = pendingGroup(r), msg = checkMessage(r.epoch);
    const mine = Sig.commitAll(g, r.shares);
    checking = { epoch: r.epoch, msg, g, nonces: mine.nonces, commits: mine.commits, ok: new Set(), commitTo: check };
    for (const s of servers()) o.send(s.pk, { type: 'sign_check', id: `${r.epoch}:${s.pk.slice(0, 8)}`, epoch: r.epoch, msg, commits: mine.commits });
  }
  function onCheck(msg: any, from: string) {
    const c = checking, r = o.st().pending;
    if (!c || !r || !msg.ok || c.ok.has(from)) return;
    const commits = [...c.commits, ...msg.commits];
    const zs = Sig.partialAll(2, c.g, r.shares, c.nonces, c.msg, commits);
    const sig = Sig.combine(2, c.g, c.msg, commits, [...zs, ...msg.zs]);
    if (!schnorr.verify(F.hexToBytes(sig), F.hexToBytes(c.msg), F.hexToBytes(c.g.groupX))) return o.say(`CHECK FAILED with ${from.slice(0, 8)}`);
    c.ok.add(from);
    o.say(`checked epoch ${c.epoch} with ${c.ok.size} of ${servers().length} servers`);
    // A check round uses its nonces once: the next server gets fresh ones.
    const fresh = Sig.commitAll(c.g, r.shares); c.nonces = fresh.nonces; c.commits = fresh.commits;
    const rest = servers().filter((s: any) => !c.ok.has(s.pk));
    if (rest.length) { o.send(rest[0].pk, { type: 'sign_check', id: `${c.epoch}:${rest[0].pk.slice(0, 8)}`, epoch: c.epoch, msg: c.msg, commits: c.commits }); return; }
    if (c.commitTo === 'none') return o.say('not committing (test)');
    for (const s of c.commitTo === 'first' ? servers().slice(0, 1) : servers()) o.send(s.pk, { type: 'refresh_commit', epoch: c.epoch, id: r.id });
    o.say(`committed epoch ${c.epoch}`);
  }
  function committed(epoch: number, id?: string) {
    if (id) committedIds.add(`${epoch}:${id}`);
    const r = o.st().pending;
    // Only the attempt that was committed: a dropped one's shares never are.
    if (!r || r.epoch !== epoch || (id && r.id && r.id !== id)) return;
    delete o.st().pending; checking = null;
    const { id: _, ...result } = r;
    done(result);
  }

  function follow(plan: RefreshPlan) {
    if ((o.st().epoch ?? 0) >= plan.epoch || (run?.plan.epoch === plan.epoch && run.plan.id === plan.id) || (o.st().pending?.epoch === plan.epoch && o.st().pending?.id === plan.id)) return;
    run = new RefreshRun(plan, o.pk, shares(), o.send, plan.periodic ? r => pending(r, false, plan.id) : done);
    run.start();
  }

  return {
    /** A silent periodic refresh: no lock, nobody removed; checked with each server, then committed (`commitTo` 'first' or 'none' for tests). */
    periodic(commitTo: 'all' | 'first' | 'none' = 'all') {
      const st = o.st();
      const left = st.group.members.filter((m: any) => !m.removed);
      const plan: RefreshPlan = {
        epoch: (st.epoch ?? 0) + 1, threshold: st.group.threshold, dealers: [o.pk, servers()[0].pk], periodic: true, id: F.bytesToHex(F.randomBytes(8)),
        holders: left.flatMap((m: any) => idxsOf(m).map(i => ({ idx: i, pk: m.idx === st.idx ? o.pk : m.pk }))),
        points: left.flatMap((m: any) => idxsOf(m).map(i => [i, points().get(i)!] as [number, string])),
      };
      for (const s of servers()) o.send(s.pk, { type: 'refresh_request', plan });
      run = new RefreshRun(plan, o.pk, shares(), o.send, r => pending(r, commitTo, plan.id));
      const parts = new Map(run.outgoing());
      for (const b of left.filter((m: any) => m.role === 'backup' && parts.get(m.pk))) {
        const ck = nip44.v2.utils.getConversationKey(F.hexToBytes(st.sk), b.pk);
        for (const s of servers()) o.send(s.pk, { type: 'backup_store', epoch: plan.epoch, content: nip44.v2.encrypt(JSON.stringify(parts.get(b.pk)), ck) });
      }
      for (const m of left.filter((m: any) => m.role !== 'server' && m.role !== 'backup' && m.pk && m.pk !== o.pk)) {
        o.send(m.pk, { type: 'refresh_plan', plan });
        const ck = nip44.v2.utils.getConversationKey(F.hexToBytes(st.sk), m.pk);
        for (const body of [{ type: 'refresh_plan', plan }, parts.get(m.pk)].filter(Boolean))
          for (const s of servers()) o.send(s.pk, { type: 'mail_for', to: m.pk, epoch: plan.epoch, content: nip44.v2.encrypt(JSON.stringify(body), ck) });
      }
      run.start();
      o.say(`periodic refresh to epoch ${plan.epoch}`);
    },
    /** Report member `idx` lost (with this device's lock), and refresh with a server as the other dealer; with no idx, just refresh. */
    report(idx: number | null) {
      const st = o.st();
      const left = st.group.members.filter((m: any) => m.idx !== idx && !m.removed);
      const plan: RefreshPlan = {
        epoch: (st.epoch ?? 0) + 1, threshold: st.group.threshold, dealers: [o.pk, servers()[0].pk],
        holders: left.flatMap((m: any) => idxsOf(m).map(i => ({ idx: i, pk: m.idx === st.idx ? o.pk : m.pk }))),
        points: left.flatMap((m: any) => idxsOf(m).map(i => [i, points().get(i)!] as [number, string])),
      };
      for (const s of servers()) o.send(s.pk, idx === null ? { type: 'refresh_request', lock: true, plan } : { type: 'remove_member', id: Date.now().toString(16), idx, lock: true, plan });
      run = new RefreshRun(plan, o.pk, shares(), o.send, done);
      // Other devices: the plan and our part, straight to them, and kept by the servers for one that's away.
      const parts = new Map(run.outgoing());
      // The paper's part, sealed to it and kept on the servers (COSIGN.md §8.2).
      for (const b of left.filter((m: any) => m.role === 'backup' && parts.get(m.pk))) {
        const ck = nip44.v2.utils.getConversationKey(F.hexToBytes(st.sk), b.pk);
        for (const s of servers()) o.send(s.pk, { type: 'backup_store', epoch: plan.epoch, content: nip44.v2.encrypt(JSON.stringify(parts.get(b.pk)), ck) });
      }
      for (const m of left.filter((m: any) => m.role !== 'server' && m.role !== 'backup' && m.pk && m.pk !== o.pk)) {
        o.send(m.pk, { type: 'refresh_plan', plan });
        const ck = nip44.v2.utils.getConversationKey(F.hexToBytes(st.sk), m.pk);
        for (const body of [{ type: 'refresh_plan', plan }, parts.get(m.pk)].filter(Boolean))
          for (const s of servers()) o.send(s.pk, { type: 'mail_for', to: m.pk, epoch: plan.epoch, content: nip44.v2.encrypt(JSON.stringify(body), ck) });
      }
      run.start();
      o.say(idx === null ? `refreshing to epoch ${plan.epoch}` : `reported member ${idx} lost; refreshing to epoch ${plan.epoch}`);
    },
    /** True if it was a refresh message. Mail is opened and handled as if from its sender. */
    take(msg: any, from: string): boolean {
      if (msg.type === 'mail') {
        let inner: any;
        try { inner = JSON.parse(nip44.v2.decrypt(msg.content, nip44.v2.utils.getConversationKey(F.hexToBytes(o.st().sk), msg.from))); } catch { return true; }
        return this.take(inner, msg.from);
      }
      if (msg.type === 'refresh_plan') { follow(msg.plan); return true; }
      if (msg.type === 'refresh_part') { run?.take(msg, from); return true; }
      if (msg.type === 'sign_check_res') { onCheck(msg, from); return true; }
      if (msg.type === 'refresh_committed') { committed(Number(msg.epoch), msg.id ?? undefined); return true; }
      return false;
    },
  };
}
