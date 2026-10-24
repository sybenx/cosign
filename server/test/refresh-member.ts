// A device's side of report lost and refresh (refresh.ts), for the test phone and the
// test device: making the plan when it reports one lost, following a plan someone else
// made, and reading what the servers kept for it while it was away (mail).

import * as nip44 from 'nostr-tools/nip44';
import { RefreshRun, type RefreshPlan, type RefreshResult } from '../refresh.ts';
import * as F from '../frost.ts';

export interface DeviceState { sk: string; idx: number; shares?: { idx: number; secret: string }[]; share?: string; epoch?: number; group: { threshold: number; members: any[] } }

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

  function follow(plan: RefreshPlan) {
    if ((o.st().epoch ?? 0) >= plan.epoch || run?.plan.epoch === plan.epoch) return;
    run = new RefreshRun(plan, o.pk, shares(), o.send, done);
    run.start();
  }

  return {
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
      return false;
    },
  };
}
