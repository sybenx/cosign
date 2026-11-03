// The repair exchange between helper members (core §4.2 step 3, §6.7.4): each helper member runs
// `frost-core`'s step 1 for each index it holds, keeps the deltas addressed to its own indices,
// sends the rest (`repair_delta`), and sums what it holds into one sigma for the new holder.

import { repairDeltas, repairSigma } from './frost.ts';
import type { Commitment } from './curve.ts';

export interface HelperMember { key: string; shares: Map<number, bigint> }

/** Step 1 for one helper member: deltas to keep, and `repair_delta` payloads per other member. */
export function repairStart(C: Commitment, helpers: { key: string; indices: number[] }[], me: HelperMember, participant: number) {
  const all = helpers.flatMap((h) => h.indices);
  const kept: string[] = [];
  const out = new Map<string, string[]>();
  for (const [i, s] of me.shares) {
    const d = repairDeltas(C, all, i, s, participant);
    for (const h of helpers) for (const j of h.indices) {
      if (h.key === me.key) kept.push(d.get(j)!);
      else out.set(h.key, [...(out.get(h.key) ?? []), d.get(j)!]);
    }
  }
  return { kept, out };
}
/** Step 2: the sigma, from the kept deltas and every helper's `repair_delta` for this member. */
export const repairFinish = (kept: string[], received: string[][]) => repairSigma([...kept, ...received.flat()]);

/** All helpers at once (in one process, for tests and the simulation): one sigma per helper member. */
export function repairAll(C: Commitment, helpers: HelperMember[], participant: number): Map<string, string> {
  const hs = helpers.map((h) => ({ key: h.key, indices: [...h.shares.keys()] }));
  const starts = helpers.map((h) => repairStart(C, hs, h, participant));
  return new Map(helpers.map((h, k) => [h.key, repairFinish(starts[k].kept, starts.filter((_, j) => j !== k).map((s) => s.out.get(h.key) ?? []))]));
}
