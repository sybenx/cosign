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
export interface Group { groupX: string; threshold: number; members: { idx: number; sharePub: string }[] }

const json = (g: Group) => JSON.stringify({ groupX: g.groupX, threshold: g.threshold, members: g.members.map(m => ({ idx: m.idx, sharePub: m.sharePub })) });
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
  const sharePub = g.members.find(m => m.idx === idx)?.sharePub;
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
