// FROST, small and hand-rolled, for a 2-of-3 group that signs Nostr events.
//
// This is a prototype. It is FROST in shape (two nonces per signer, binding
// factors over the whole commitment list, Lagrange-weighted shares) with a
// BIP-340 challenge, so every aggregate is an ordinary Schnorr signature any
// Nostr client verifies. It is NOT RFC 9591's hash-to-scalar, and it is not
// bifrost's wire format. The same construction is implemented in Kotlin on the
// phone; vectors/frost.json pins the two together.
//
//   rho_i = int(H_tag("cosign/rho", Y_x || msg || B || be32(i))) mod n
//   R     = sum_i (D_i + rho_i * E_i)          (negated when R has odd y)
//   c     = int(H_tag("BIP0340/challenge", R_x || Y_x || msg)) mod n
//   z_i   = s(d_i + rho_i * e_i) + lambda_i * s_i * c         s = -1 if R odd
//   sig   = R_x || sum_i z_i
//
// B is the commitment list sorted by index: be32(i) || D_i(33) || E_i(33).

import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

export const Point = secp256k1.Point;
export type Pt = InstanceType<typeof Point>;
export const N = Point.Fn.ORDER;
export const G = Point.BASE;

const mod = (a: bigint) => ((a % N) + N) % N;
const be32 = (i: number) => new Uint8Array([(i >>> 24) & 255, (i >>> 16) & 255, (i >>> 8) & 255, i & 255]);
export const toInt = (b: Uint8Array) => BigInt('0x' + (bytesToHex(b) || '0'));
export const toHex32 = (a: bigint) => a.toString(16).padStart(64, '0');
const inv = (a: bigint) => {
  // Fermat: a^(n-2) mod n
  let r = 1n, b = mod(a), e = N - 2n;
  while (e > 0n) { if (e & 1n) r = (r * b) % N; b = (b * b) % N; e >>= 1n; }
  return r;
};
const tagged = (tag: string, ...m: Uint8Array[]) => schnorr.utils.taggedHash(tag, ...m);
const mulG = (k: bigint) => G.multiply(mod(k));
const xOnly = (p: Pt) => p.toBytes(true).slice(1);

export function randomScalar(): bigint {
  for (;;) { const k = toInt(randomBytes(32)); if (k > 0n && k < N) return k; }
}

// --- Dealing -----------------------------------------------------------------

export interface Share { idx: number; secret: string; pub: string }
export interface Dealt { groupX: string; threshold: number; shares: Share[] }

/** Trusted dealer: split a secret key into n shares, t needed to sign. */
export function deal(secretHex: string | null, n = 3, t = 2): Dealt {
  let a0 = secretHex ? mod(BigInt('0x' + secretHex)) : randomScalar();
  // BIP-340 keys are x-only with even y. If ours is odd, sign with n - a0,
  // which has the same x and therefore the same npub.
  if (!mulG(a0).hasEvenY()) a0 = N - a0;
  const coeffs = [a0];
  for (let k = 1; k < t; k++) coeffs.push(randomScalar());
  const f = (x: bigint) => coeffs.reduceRight((acc, c) => mod(acc * x + c), 0n);
  const shares: Share[] = [];
  for (let i = 1; i <= n; i++) {
    const s = f(BigInt(i));
    shares.push({ idx: i, secret: toHex32(s), pub: bytesToHex(mulG(s).toBytes(true)) });
  }
  return { groupX: bytesToHex(xOnly(mulG(a0))), threshold: t, shares };
}

export function lagrange(i: number, participants: number[]): bigint {
  let num = 1n, den = 1n;
  for (const j of participants) {
    if (j === i) continue;
    num = mod(num * BigInt(j));
    den = mod(den * BigInt(j - i));
  }
  return mod(num * inv(den));
}

// --- Signing -----------------------------------------------------------------

export interface Nonces { d: bigint; e: bigint }
export interface Commit { idx: number; D: string; E: string }

export function commit(idx: number): { nonces: Nonces; commit: Commit } {
  const d = randomScalar(), e = randomScalar();
  return { nonces: { d, e }, commit: { idx, D: bytesToHex(mulG(d).toBytes(true)), E: bytesToHex(mulG(e).toBytes(true)) } };
}

function encodeList(commits: Commit[]): Uint8Array {
  const sorted = [...commits].sort((a, b) => a.idx - b.idx);
  return concatBytes(...sorted.flatMap(c => [be32(c.idx), hexToBytes(c.D), hexToBytes(c.E)]));
}

interface RoundCtx { rho: Map<number, bigint>; R: Pt; flip: boolean; c: bigint; Rx: Uint8Array; participants: number[] }

function roundContext(groupX: string, msgHex: string, commits: Commit[]): RoundCtx {
  const Y = hexToBytes(groupX), msg = hexToBytes(msgHex);
  if (msg.length !== 32) throw new Error('message must be 32 bytes');
  const ids = commits.map(c => c.idx);
  if (new Set(ids).size !== ids.length) throw new Error('duplicate participant');
  const B = encodeList(commits);
  const rho = new Map<number, bigint>();
  let R = Point.ZERO;
  for (const cm of commits) {
    const r = mod(toInt(tagged('cosign/rho', Y, msg, B, be32(cm.idx))));
    rho.set(cm.idx, r);
    R = R.add(Point.fromHex(cm.D)).add(Point.fromHex(cm.E).multiply(r));
  }
  if (R.is0()) throw new Error('degenerate group commitment');
  const flip = !R.hasEvenY();
  const Rx = xOnly(R);
  const c = mod(toInt(tagged('BIP0340/challenge', Rx, Y, msg)));
  return { rho, R, flip, c, Rx, participants: [...ids].sort((a, b) => a - b) };
}

/** One signer's share of the signature. The nonces must never be used again. */
export function partialSign(a: { groupX: string; msg: string; commits: Commit[]; idx: number; secret: string; nonces: Nonces }): string {
  const ctx = roundContext(a.groupX, a.msg, a.commits);
  if (!ctx.participants.includes(a.idx)) throw new Error('signer is not a participant');
  const rho = ctx.rho.get(a.idx)!;
  const k = mod(a.nonces.d + rho * a.nonces.e);
  const lam = lagrange(a.idx, ctx.participants);
  const z = mod((ctx.flip ? N - k : k) + lam * BigInt('0x' + a.secret) * ctx.c);
  return toHex32(z);
}

/** Check another signer's partial against its public share point. */
export function verifyPartial(a: { groupX: string; msg: string; commits: Commit[]; idx: number; sharePub: string; z: string }): boolean {
  const ctx = roundContext(a.groupX, a.msg, a.commits);
  const cm = a.commits.find(c => c.idx === a.idx);
  if (!cm) return false;
  const rho = ctx.rho.get(a.idx)!;
  let Ri = Point.fromHex(cm.D).add(Point.fromHex(cm.E).multiply(rho));
  if (ctx.flip) Ri = Ri.negate();
  const lam = lagrange(a.idx, ctx.participants);
  const rhs = Ri.add(Point.fromHex(a.sharePub).multiply(mod(lam * ctx.c)));
  const z = BigInt('0x' + a.z);
  if (z === 0n || z >= N) return false;
  return mulG(z).equals(rhs);
}

/** Sum the partials into a BIP-340 signature, and check it. */
export function aggregate(a: { groupX: string; msg: string; commits: Commit[]; partials: string[] }): string {
  const ctx = roundContext(a.groupX, a.msg, a.commits);
  const z = a.partials.reduce((acc, p) => mod(acc + BigInt('0x' + p)), 0n);
  const sig = concatBytes(ctx.Rx, hexToBytes(toHex32(z)));
  if (!schnorr.verify(sig, hexToBytes(a.msg), hexToBytes(a.groupX))) throw new Error('aggregate signature does not verify');
  return bytesToHex(sig);
}

// --- Threshold ECDH (for NIP-04 / NIP-44 on behalf of the group key) ----------

/** lambda_i * s_i * P, as a compressed point. Combining two gives the shared point. */
export function ecdhPartial(a: { idx: number; secret: string; participants: number[]; peerX: string }): string {
  const P = Point.fromHex('02' + a.peerX);
  const k = mod(lagrange(a.idx, a.participants) * BigInt('0x' + a.secret));
  return bytesToHex(P.multiply(k).toBytes(true));
}

export function ecdhCombine(parts: string[]): Uint8Array {
  const S = parts.reduce((acc, p) => acc.add(Point.fromHex(p)), Point.ZERO);
  if (S.is0()) throw new Error('degenerate shared point');
  return xOnly(S);
}

export { bytesToHex, hexToBytes, randomBytes };

/** Whether this round's group commitment had odd y (and so was negated). For tests. */
export const roundFlips = (groupX: string, msg: string, commits: Commit[]) => roundContext(groupX, msg, commits).flip;
