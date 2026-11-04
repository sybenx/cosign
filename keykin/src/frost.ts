// FROST-secp256k1-SHA256-TR-v1 (core §1) through keykin/frost-wasm, plus the trusted dealer an
// import uses (§11.2; DKG is the Account admin module's). Indices are numbers here and 32-byte
// identifiers on the wasm side (§3.2). Nonces stay in this process's memory (§5.2).

import { createRequire } from 'node:module';
import { schnorr } from '@noble/curves/secp256k1.js';
import { randomBytes, sha, hexToBytes, bytesToHex, refuse } from './bytes.ts';
import { type Commitment, commitmentHex, idHex, mod, mul, N, scalarHex, compHex, G, Point } from './curve.ts';

const W: any = createRequire(import.meta.url)('../frost-wasm/keykin_frost.js');

/** A signing commitment as it travels (§5.1). */
export interface SignCommit { i: number; D: string; E: string }
const toWasm = (cs: SignCommit[]) => JSON.stringify(cs.map((c) => ({ i: idHex(c.i), D: c.D, E: c.E })));
const cj = (C: Commitment) => JSON.stringify(commitmentHex(C));

/** Secret nonces for one index of one request: memory only, used once. */
export class Nonces {
  #hex: string | null;
  readonly i: number;
  constructor(i: number, hex: string) { this.i = i; this.#hex = hex; }
  /** Hands the nonces over exactly once (§5.2: "use each once"). */
  take(): string { const h = this.#hex; if (h === null) refuse('nonce_used'); this.#hex = null; return h as string; }
  get used() { return this.#hex === null; }
}

/** §5.2: the hedged random input, `SHA-256(fresh OS randomness ‖ share ‖ context)`. */
export const hedge = (share: bigint, context: Uint8Array, osRandom: Uint8Array = randomBytes(32)) =>
  bytesToHex(sha(osRandom, hexToBytes(scalarHex(share)), context));

export function commit(C: Commitment, i: number, share: bigint, hedgeHex: string): { nonces: Nonces; commit: SignCommit } {
  const r = JSON.parse(W.commit(cj(C), idHex(i), scalarHex(share), hedgeHex));
  return { nonces: new Nonces(i, r.nonces), commit: { i, D: r.commit.D, E: r.commit.E } };
}

export function signShare(C: Commitment, i: number, share: bigint, nonces: Nonces, msg: string, commits: SignCommit[]): string {
  if (nonces.i !== i) refuse('nonce_mismatch');
  return W.sign(cj(C), idHex(i), scalarHex(share), nonces.take(), msg, toWasm(commits));
}

export const verifyShare = (C: Commitment, msg: string, commits: SignCommit[], i: number, z: string): boolean =>
  W.verifyPartial(cj(C), msg, toWasm(commits), idHex(i), z);

export function aggregate(C: Commitment, msg: string, commits: SignCommit[], zs: { i: number; z: string }[]): string {
  const sig = W.aggregate(cj(C), msg, toWasm(commits), JSON.stringify(zs.map((p) => [idHex(p.i), p.z])));
  if (!schnorr.verify(hexToBytes(sig), hexToBytes(msg), hexToBytes(compHex(C[0]).slice(2)))) refuse('bad_signature');
  return sig;
}

export const sharePoint = (C: Commitment, i: number) => W.sharePoint(cj(C), idHex(i)) as string;

// --- Repair (§4.2 step 3, frost-core's `repairable`) -------------------------------------

/** Step 1 for one helper index: a delta for every helper index (keep yours, send the others). */
export function repairDeltas(C: Commitment, helpers: number[], i: number, share: bigint, participant: number): Map<number, string> {
  const out: [string, string][] = JSON.parse(W.repairStep1(cj(C), JSON.stringify(helpers.map(idHex)), idHex(i), scalarHex(share), idHex(participant)));
  const back = new Map(helpers.map((h) => [idHex(h), h]));
  return new Map(out.map(([h, d]) => [back.get(h)!, d]));
}
/** Step 2: one sigma from every delta addressed to a member's helper indices. */
export const repairSigma = (deltas: string[]) => W.repairStep2(JSON.stringify(deltas)) as string;
/** Step 3: the new share from the sigmas, checked against `P_i^S`; throws if it misses. */
export function repairShare(C: Commitment, sigmas: string[], participant: number): bigint {
  try { return BigInt('0x' + W.repairStep3(cj(C), JSON.stringify(sigmas), idHex(participant))); }
  catch { return refuse('repair_failed', 'the summed share misses its point'); }
}

// --- Dealing a key someone already has (import, §11.2) -----------------------------------

/** Shamir shares of `secret` at `indices`, threshold 4, even y (BIP-340): the same npub. */
export function deal(secret: bigint, indices: number[], rand: () => bigint = () => mod(BigInt('0x' + bytesToHex(randomBytes(32))))) {
  let a0 = mod(secret);
  if (a0 === 0n) refuse('bad_secret');
  if (mul(a0).toAffine().y % 2n === 1n) a0 = N - a0;
  const coef = [a0, rand(), rand(), rand()];
  const f = (x: bigint) => coef.reduce((acc, c, k) => mod(acc + c * x ** BigInt(k)), 0n);
  return { commitment: coef.map((c) => mul(c)) as Commitment, shares: new Map(indices.map((i) => [i, f(BigInt(i))])), secret: a0 };
}
export { G, Point };
