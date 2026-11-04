// Key families module §1–§2: the events, and settling a child's family from anchored heights. Pure;
// the anchors themselves (NIP-03 OpenTimestamps, Bitcoin headers) are the caller's to verify.

import { verifyEvent, type NostrEvent } from './event.ts';
import { strictJson } from './bytes.ts';

export const KIND_FAMILY = 1244, KIND_RELEASE = 1245, KIND_LEAKED = 1246, KIND_ACCEPT = 1247;
export const FAMILY_KINDS = new Set([KIND_FAMILY, KIND_RELEASE, KIND_LEAKED, KIND_ACCEPT]);
export const WINDOW = 2016, GRACE = 144;

const one = (e: NostrEvent, t: string) => { const xs = e.tags.filter((x) => x[0] === t); return xs.length === 1 ? xs[0][1] : null; };

/** §1: a family event with its embedded accept, both signatures checked. Returns `{master, child}` or null. */
export function parseFamily(e: NostrEvent): { id: string; master: string; child: string } | null {
  if (e.kind !== KIND_FAMILY || !verifyEvent(e)) return null;
  const child = one(e, 'p');
  let acc: NostrEvent;
  try { acc = strictJson(e.content); } catch { return null; }
  if (!child || acc.kind !== KIND_ACCEPT || !verifyEvent(acc) || acc.pubkey !== child || one(acc, 'p') !== e.pubkey) return null;
  return { id: e.id, master: e.pubkey, child };
}
export function parseRelease(e: NostrEvent): { family: string; master: string } | null {
  if (e.kind !== KIND_RELEASE || !verifyEvent(e)) return null;
  const f = one(e, 'e');
  return f ? { family: f, master: e.pubkey } : null;
}

export interface Anchored<T> { v: T; height: number }
export type Status = { kind: 'none' } | { kind: 'pending'; family: string } | { kind: 'settled'; family: string; master: string } | { kind: 'disputed'; families: string[] };

/** §2: settle child `C` at block `tip`. `families` and `releases` carry their anchored heights (only
 *  complete proofs; a pending one is simply absent). */
export function settle(child: string, families: Anchored<{ id: string; master: string; child: string }>[], releases: Anchored<{ family: string; master: string }>[], tip: number): Status {
  // 1. Every family for C with a proof, sorted by anchored height, then id.
  let fs = families.filter((f) => f.v.child === child).sort((a, b) => a.height - b.height || (a.v.id < b.v.id ? -1 : 1));
  // 2. Two families from the same master are one: the earliest counts.
  const seenMaster = new Set<string>();
  fs = fs.filter((f) => (seenMaster.has(f.v.master) ? false : (seenMaster.add(f.v.master), true)));
  const byId = new Map(fs.map((f) => [f.v.id, f]));
  const releasedAt = (f: Anchored<{ id: string; master: string }>) => {
    const hs = releases.filter((r) => r.v.master === f.v.master && byId.get(r.v.family)?.v.master === f.v.master).map((r) => r.height);
    return hs.length ? Math.min(...hs) : null;
  };
  // A family blocks others within the window from a different master; released ones still block.
  const disputeWith = (f: Anchored<{ id: string; master: string }>) => fs.filter((o) => o !== f && o.v.master !== f.v.master && Math.abs(o.height - f.height) <= WINDOW);
  const dead = new Set<string>();
  // 3. Dead pairs: any anchored release for (master, C) kills every family of that pair.
  for (const f of fs) if (releasedAt(f) !== null) dead.add(f.v.id);
  // 4. No claims on a settled child: anchored while another was settled (from the end of its window,
  //    without grace) and not yet released.
  for (const f of fs) for (const o of fs) {
    if (o === f || o.height >= f.height) continue;
    const settledFrom = o.height + WINDOW, rel = releasedAt(o);
    if (f.height >= settledFrom && (rel === null || rel > f.height) && disputeWith(o).length === 0) dead.add(f.v.id);
  }
  // 5. The first family decides.
  const first = fs.find((f) => !dead.has(f.v.id));
  if (!first) return { kind: 'none' };
  const d = disputeWith(first);
  if (d.length) return { kind: 'disputed', families: [first.v.id, ...d.map((x) => x.v.id)] };
  if (tip - first.height >= WINDOW + GRACE) return { kind: 'settled', family: first.v.id, master: first.v.master };
  return { kind: 'pending', family: first.v.id };
}
