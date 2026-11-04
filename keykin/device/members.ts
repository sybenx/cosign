// What an app checks member-key signatures against (core 14.19 §5.9, "What a verifier needs"):
//
//   members.devices()       {self, asOf, keys: [{key, added_by, flagged}]}: the current device member keys
//                           in this device's view, at state `asOf`
//   members.removed(since)  a durable log, for the account's life, of {seq, key, why, change, state}
//   members.onRemoved(cb)   each new or updated entry, and each newly flagged key
//   members.keep(key)       the person keeps a flagged key: it stops being flagged
//
// An entry appears as soon as a key is out of the device set, with `state: null`, and is updated with the
// post-redeal hash once that change's redeal has applied here, so an app can revoke at once. A key is
// `flagged` when the device that added it has been removed (§6.7.6 F5): current, but an app SHOULD treat
// it as removed for an allowlist until the person keeps it. Servers, the helper and the backup are not
// devices and never appear.

import { stateHash } from '../src/codes.ts';
import type { DeviceNode } from './node.ts';

export interface RemovedEntry { seq: number; key: string; why: 'remove' | 'self' | 'void'; change: string | null; state: string | null }
export interface DeviceKey { key: string; added_by: string | null; flagged: boolean }
export type MembersEvent = { removed: RemovedEntry } | { flagged: string };

export class Members {
  readonly d: DeviceNode;
  log: RemovedEntry[] = [];
  kept = new Set<string>();
  #seq = 0;
  #flagsTold = new Set<string>();
  #started = false;
  #listeners = new Set<(e: MembersEvent) => void>();
  constructor(d: DeviceNode) { this.d = d; }

  #approver(p: any): string | null {
    const a = p.c.approval ?? {};
    return a.lock?.member ?? a.pair?.[0]?.member ?? a.paper?.member ?? a.self?.member ?? (a.recovery ? a.recovery.backup : null);
  }
  /** Who approved each device's add (record devices: null). */
  #addedBy(): Map<string, string | null> {
    const out = new Map<string, string | null>();
    for (const x of this.d.rec?.members ?? []) if (x.kind === 'device') out.set(x.key, null);
    for (const p of this.d.m?.accepted ?? []) if (p.type === 'add') out.set((p.c.change as any).add.key, this.#approver(p));
    return out;
  }

  devices(): { self: string; asOf: string; keys: DeviceKey[] } {
    const m = this.d.m, by = this.#addedBy();
    const removed = m?.removed ?? new Set<string>();
    const keys = m ? [...m.devices].filter((k) => !removed.has(k)).sort() : [];
    return { self: this.d.kp.pub, asOf: stateHash(this.d.state?.ids ?? []),
      keys: keys.map((key) => { const a = by.get(key) ?? null; return { key, added_by: a, flagged: !!a && removed.has(a) && !this.kept.has(key) }; }) };
  }
  removed(since = 0): RemovedEntry[] { return this.log.filter((e) => e.seq > since).map((e) => ({ ...e })); }
  onRemoved(cb: (e: MembersEvent) => void): () => void { this.#listeners.add(cb); return () => void this.#listeners.delete(cb); }
  keep(key: string) { this.kept.add(key); this.d.persist(); }

  #tell(e: MembersEvent) { if (!this.#started) return; for (const cb of this.#listeners) { try { cb(e); } catch { /* a listener never wedges the device */ } } }

  /** Bring the log up to date with this device's view (called on every membership or state change). */
  update() {
    const m = this.d.m, st = this.d.state;
    if (!m || !st || this.d.wiped) return;
    const by = this.#addedBy();
    const ids = st.ids;
    for (const k of [...m.removed].filter((k) => by.has(k)).sort()) {
      const rm = m.accepted.find((p) => p.type === 'remove' && (p.c.change as any).remove === k);
      let e = this.log.find((x) => x.key === k);
      if (!e) {
        // A remove change (a self remove is approved by `self`), or §3.2's conflicting adds (void).
        const why: RemovedEntry['why'] = rm ? ((rm.c.approval as any)?.self ? 'self' : 'remove') : 'void';
        const add = m.accepted.find((p) => p.type === 'add' && (p.c.change as any).add.key === k);
        e = { seq: ++this.#seq, key: k, why, change: rm?.ev.id ?? add?.ev.id ?? null, state: null };
        this.log.push(e);
        this.#tell({ removed: { ...e } });
      }
      if (e.state === null) {
        // The post-redeal hash once that change's redeal is in this device's state; a void has no redeal.
        const redeals = rm ? m.accepted.filter((q) => q.listHash === rm.listHash && q.type === 'redeal').map((q) => (q.c.change as any).redeal.id as string) : [];
        if (e.why === 'void' || redeals.some((r) => ids.has(r))) { e.state = stateHash(ids); e.seq = ++this.#seq; this.#tell({ removed: { ...e } }); }
      }
    }
    for (const k of this.devices().keys.filter((x) => x.flagged).map((x) => x.key)) if (!this.#flagsTold.has(k)) { this.#flagsTold.add(k); this.#tell({ flagged: k }); }
    // What happened before this device's first view is in the log, but told to nobody: history, not news.
    this.#started = true;
  }

  dump() { return { log: this.log, kept: [...this.kept], seq: this.#seq, told: [...this.#flagsTold] }; }
  load(x: any) { if (!x) return; this.log = x.log ?? []; this.kept = new Set(x.kept ?? []); this.#seq = x.seq ?? 0; this.#flagsTold = new Set(x.told ?? []); this.#started = true; }
  clear() { this.log = []; this.kept.clear(); this.#seq = 0; this.#flagsTold.clear(); }
}
