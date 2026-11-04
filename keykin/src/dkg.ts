// Fresh accounts by distributed key generation (Account admin §1.1): FROST's `keys::dkg`, threshold 4,
// one participant per index (the device's 1, 2, 3 and the backup seat's 5, 6; the servers' 4, 7, 8).
// The commitment for the epoch record is rebuilt from the share points and checked against all of them.

import { idHex, liftX, pointFrom, rebuildCommitment, derivePoint, mul, scalarFrom, type Commitment } from './curve.ts';
import { hedge } from './frost.ts';
import { sha, refuse, utf8ToBytes } from './bytes.ts';
import { W } from './wasm.ts';

const byIndex = (hexId: string) => Number(BigInt('0x' + hexId));

export interface Round1 { secret: string; package: string }
/** Part 1 for one index; its secret package stays with the participant. */
export function dkg1(i: number, max: number, os: Uint8Array): Round1 {
  // The polynomial is hedged too (Account admin §1.1): SHA-256(OS randomness ‖ counter ‖ purpose).
  return JSON.parse(W.dkgPart1(idHex(i), max, 4, hedge(0n, sha(utf8ToBytes(`keykin-dkg/1:${i}`)), os)));
}
/** Part 2: round-2 packages for every other index (each sealed to its holder in transit). */
export function dkg2(secret: string, others: Map<number, string>): { secret: string; packages: Map<number, string> } {
  const r = JSON.parse(W.dkgPart2(secret, JSON.stringify([...others].map(([i, p]) => [idHex(i), p]))));
  return { secret: r.secret, packages: new Map(r.packages.map(([k, p]: [string, string]) => [byIndex(k), p])) };
}
/** Part 3: this index's share, the group key and every share point, even y. */
export function dkg3(secret2: string, round1Others: Map<number, string>, round2For: Map<number, string>) {
  const r = JSON.parse(W.dkgPart3(secret2, JSON.stringify([...round1Others].map(([i, p]) => [idHex(i), p])), JSON.stringify([...round2For].map(([i, p]) => [idHex(i), p]))));
  const points = new Map<number, string>(r.points.map(([k, p]: [string, string]) => [byIndex(k), p]));
  return { share: scalarFrom(r.share), g: r.groupX as string, points };
}
/** The commitment `C` for the epoch record, rebuilt from the group point and three share points, and
 *  checked against every other share point. */
export function dkgCommitment(g: string, points: Map<number, string>): Commitment {
  const pts = [...points].sort((a, b) => a[0] - b[0]);
  if (pts.length < 4) refuse('dkg', 'not enough share points');
  const C = rebuildCommitment([[0n, liftX(g)], ...pts.slice(0, 3).map(([i, p]) => [BigInt(i), pointFrom(p)] as [bigint, any])]);
  for (const [i, p] of pts) if (!derivePoint(C, BigInt(i)).equals(pointFrom(p))) refuse('dkg', `share point ${i} is off the polynomial`);
  return C;
}

/** All participants in one process (tests; the simulation runs servers' parts on the servers). */
export function dkgLocal(indices: number[], os: () => Uint8Array) {
  const r1 = new Map(indices.map((i) => [i, dkg1(i, indices.length, os())]));
  const others = (i: number) => new Map([...r1].filter(([j]) => j !== i).map(([j, x]) => [j, x.package]));
  const r2 = new Map(indices.map((i) => [i, dkg2(r1.get(i)!.secret, others(i))]));
  const out = new Map(indices.map((i) => [i, dkg3(r2.get(i)!.secret, others(i), new Map([...r2].filter(([j]) => j !== i).map(([j, x]) => [j, x.packages.get(i)!])))]));
  const first = out.get(indices[0])!;
  return { g: first.g, C: dkgCommitment(first.g, first.points), shares: new Map([...out].map(([i, x]) => [i, x.share])) };
}
export { mul };
