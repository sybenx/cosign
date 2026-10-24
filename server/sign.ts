// Signing, on the Zcash Foundation's FROST (frost-wasm, built from ../frost), with the
// earlier hand-rolled math kept only so members not updated yet still work.
//
// Scheme 2 is RFC 9591 (the library). Scheme 1 is frost.ts. Commitments mean the same
// in both (D = hiding nonce·G, E = binding nonce·G), so a coordinator can learn from a
// partner's partial which one it used and finish the round the same way. A request
// says `frost: 2`; a member that predates this doesn't read it and answers in scheme 1.

import { createRequire } from 'node:module';
import * as F from './frost.ts';

const W = createRequire(import.meta.url)('./frost-wasm/cosign_frost.js');

export interface Commit { idx: number; D: string; E: string }
export type Scheme = 1 | 2;
/** A member holds one share (a server) or several (a device holds 3 in a weighted key). */
export interface Group { groupX: string; threshold: number; members: { idx: number; sharePub: string; shares?: { idx: number; sharePub: string }[] }[] }
/** One of this member's own shares. */
export interface Share { idx: number; secret: string }

/** Every share point in the group, whoever holds it: what the library calls the members. */
export const sharePoints = (g: Group) => g.members.flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]);
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
