// Signing, on the Zcash Foundation's FROST (frost-wasm, built from ../frost), with the
// earlier hand-rolled math kept only so members not updated yet still work.
//
// Scheme 2 is RFC 9591 (the library). Scheme 1 is frost.ts. Commitments mean the same
// in both (D = hiding nonce·G, E = binding nonce·G), so a coordinator can learn from a
// partner's partial which one it used and finish the round the same way. A request
// says `frost: 2`; a member that predates this doesn't read it and answers in scheme 1.

import * as F from './frost.ts';
import { W } from './wasm.ts';

export interface Commit { idx: number; D: string; E: string }
export type Scheme = 1 | 2;
/** A member holds one share (a server) or several (a device holds 3 in a weighted key). */
export interface Group { groupX: string; threshold: number; members: { idx: number; sharePub: string; shares?: { idx: number; sharePub: string }[] }[] }
/** One of this member's own shares. */
export interface Share { idx: number; secret: string }

/** Every share point in the group, whoever holds it: what the library calls the members. */
export const sharePoints = (g: Group) => g.members.flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]);

/**
 * The group with every share point **rebuilt from the group key** rather than taken from the
 * member list, and null if they cannot be rebuilt.
 *
 * This matters because a share point from the list is not evidence of anything. The library
 * verifies a partial against the point it is handed (`public_package` in `frost/src/lib.rs`
 * builds the verifying shares straight from each member's `sharePub`), and a server's member
 * list is where that point comes from. So a member whose point a dishonest server chose can
 * produce a partial that **verifies**, using nothing but the real library: it signs with the
 * secret behind the point it supplied. The aggregate then fails — it cannot forge the group's
 * signature — but anything a caller decides at *verification* time has already been decided
 * wrongly.
 *
 * `sharePubAt` rebuilds the group polynomial's commitment from the first `threshold` points and
 * refuses unless its constant term is the group key. Fail-closed: if those points have been
 * tampered with so that the constant term comes out wrong, this returns null and the caller must
 * refuse rather than fall back to the list.
 *
 * **What this does and does not catch.** It catches a stale share, a corrupted copy at rest, and
 * a dishonest *partner* — the cases a partial fails for by accident or by one member's malice.
 * It does **not** catch a server that writes the whole member list, and an earlier version of
 * this comment wrongly said it did. The constant term constrains a weighted *sum* of the points,
 * not each point: an attacker that chooses `threshold - 1` of them with scalars it knows can
 * solve the last from public data so the sum still lands on the group key, and a partial made
 * with one of its own scalars then verifies. It learns nothing about the account's key, and the
 * aggregate still refuses it — which is why `attempt` clears `viaServer` only after
 * `Sig.combine` returns — but for a decryption, where there is no aggregate to refuse it, the
 * check is weaker than it looks. Closing that needs the rebuilt commitment to be checked against
 * the member's *own* share points as well (`~/igloo/cosign-extension-reads-spec.md` §3), which
 * is a change this branch does not make.
 */
export function sound(g: Group): Group | null {
  try {
    const members = sharePoints(g).map(({ idx }) => ({ idx, sharePub: sharePubAt(g, idx) }));
    return { groupX: g.groupX, threshold: g.threshold, members };
  } catch { return null; }
}

/** Verify a partial against points rebuilt from the group key. False if they can't be rebuilt. */
export function verifiedPartials(g: Group, msg: string, commits: Commit[], partials: [number, string][]): boolean {
  const ok = sound(g);
  if (!ok) return false;
  return partials.every(([i, z]) => W.verifyPartial(json(ok), msg, JSON.stringify(commits), i, z));
}
const json = (g: Group) => JSON.stringify({ groupX: g.groupX, threshold: g.threshold, members: sharePoints(g) });
const oldNonces = (hex: string) => ({ d: BigInt('0x' + hex.slice(0, 64)), e: BigInt('0x' + hex.slice(64)) });

/** Fresh nonces (hex, hiding ‖ binding) and their commitment. Good for either scheme, once. */
export function commit(g: Group, idx: number, secret: string): { nonces: string; commit: Commit } {
  return JSON.parse(W.commit(json(g), idx, secret));
}

export function partial(scheme: Scheme, g: Group, idx: number, secret: string, nonces: string, msg: string, commits: Commit[]): string {
  return scheme === 2
    ? W.sign(json(g), idx, secret, nonces, msg, JSON.stringify(commits))
    : F.partialSign({ groupX: g.groupX, msg, commits, idx, secret, nonces: oldNonces(nonces) });
}

/** Which scheme a partner's partial is valid under, or null if neither. */
export function schemeOf(g: Group, msg: string, commits: Commit[], idx: number, z: string): Scheme | null {
  if (W.verifyPartial(json(g), msg, JSON.stringify(commits), idx, z)) return 2;
  const sharePub = sharePoints(g).find(m => m.idx === idx)?.sharePub;
  if (sharePub && F.verifyPartial({ groupX: g.groupX, msg, commits, idx, sharePub, z })) return 1;
  return null;
}

/** The final signature. Throws unless it verifies. */
export function combine(scheme: Scheme, g: Group, msg: string, commits: Commit[], partials: [number, string][]): string {
  return scheme === 2
    ? W.aggregate(json(g), msg, JSON.stringify(commits), JSON.stringify(partials))
    : F.aggregate({ groupX: g.groupX, msg, commits, partials: partials.map(p => p[1]) });
}

// Adding a device (repair): see frost/src/lib.rs. Each helper's step 1, its step 2, and
// the share point the new member must end up with.
export const repairStep1 = (g: Group, idx: number, secret: string, helpers: number[], k: number): [number, string][] =>
  JSON.parse(W.repairStep1(json(g), idx, secret, Uint16Array.from(helpers), k));
export const repairStep2 = (deltas: string[]): string => W.repairStep2(deltas);
export const sharePubAt = (g: Group, k: number): string => W.sharePubAt(json(g), k);

// --- Several shares at once (a member holding more than one) -------------------------
//
// A round is every share of the members taking part; each member commits and signs
// with all of its own. The library only ever sees shares.

/** Fresh nonces and a commitment for each of my shares. */
export function commitAll(g: Group, mine: Share[]): { nonces: Record<number, string>; commits: Commit[] } {
  const nonces: Record<number, string> = {}; const commits: Commit[] = [];
  for (const s of mine) { const c = commit(g, s.idx, s.secret); nonces[s.idx] = c.nonces; commits.push(c.commit); }
  return { nonces, commits };
}

/** My partials over every commitment in the round, one per share of mine. */
export function partialAll(scheme: Scheme, g: Group, mine: Share[], nonces: Record<number, string>, msg: string, commits: Commit[]): [number, string][] {
  return mine.map(s => [s.idx, partial(scheme, g, s.idx, s.secret, nonces[s.idx], msg, commits)]);
}

/** Which scheme a partner's partials are all valid under, or null. The earlier math only ever had one share each. */
export function schemeOfAll(g: Group, msg: string, commits: Commit[], partials: [number, string][]): Scheme | null {
  if (partials.every(([i, z]) => W.verifyPartial(json(g), msg, JSON.stringify(commits), i, z))) return 2;
  if (partials.length === 1 && commits.length === 2) return schemeOf(g, msg, commits, partials[0][0], partials[0][1]) === 1 ? 1 : null;
  return null;
}
