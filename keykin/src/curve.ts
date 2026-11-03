// secp256k1 arithmetic Core needs outside FROST itself: share points derived from a commitment
// (§3.1), the commitment a device rebuilds from its own points (§3.4 step 4), Lagrange weights
// at 32-byte identifiers, and redeal polynomials (§6.7.1). Pure.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, KeykinError, refuse } from './bytes.ts';

export const Point = secp256k1.Point;
export type Point = InstanceType<typeof secp256k1.Point>;
export const N = Point.Fn.ORDER;
export const G = Point.BASE;

export const mod = (a: bigint) => ((a % N) + N) % N;
export const inv = (a: bigint) => Point.Fn.inv(mod(a));
export const scalarHex = (k: bigint) => mod(k).toString(16).padStart(64, '0');
export function scalarFrom(h: string, what = 'scalar'): bigint {
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) refuse('malformed', `${what}: expected 32 bytes of hex`);
  const k = BigInt('0x' + h);
  if (k >= N) refuse('malformed', `${what}: out of range`);
  return k;
}

/** k·P, with 0·P the identity (noble refuses a zero multiplier). */
export const mul = (k: bigint, p: Point = G): Point => (mod(k) === 0n ? Point.ZERO : p.multiply(mod(k)));

/** A 33-byte compressed point. The identity has no encoding, so it is always refused. */
export function pointFrom(h: string, what = 'point'): Point {
  if (typeof h !== 'string' || !/^0[23][0-9a-f]{64}$/.test(h)) refuse('malformed', `${what}: expected a 33-byte compressed point`);
  try { return Point.fromHex(h); } catch { throw new KeykinError('malformed', `${what}: not on the curve`); }
}
export function compHex(p: Point): string {
  if (p.is0()) throw new KeykinError('identity', 'the identity has no encoding');
  return p.toHex(true);
}
export const compBytes = (p: Point) => hexToBytes(compHex(p));
/** The even-y point of an x-only key. */
export const liftX = (xhex: string) => pointFrom('02' + xhex, 'x-only key');
export const xOnly = (p: Point) => compHex(p).slice(2);

/** A commitment `C_S`: `[C0, C1, C2, C3]`. */
export type Commitment = Point[];
export const commitmentFrom = (hs: string[], what = 'commitment'): Commitment => {
  if (!Array.isArray(hs) || hs.length !== 4) refuse('malformed', `${what}: expected 4 points`);
  return hs.map((h, k) => pointFrom(h, `${what}[${k}]`));
};
export const commitmentHex = (c: Commitment) => c.map(compHex);

/** `P_i = Σ C_k·i^k`, the share point at index i: always derived, never taken from a message. */
export function derivePoint(c: Commitment, i: bigint): Point {
  let acc = Point.ZERO, x = 1n;
  for (const ck of c) { acc = acc.add(mul(x, ck)); x = mod(x * i); }
  return acc;
}

/** `Σ D_k·i^k` for a redeal's `[D1, D2, D3]` (D0 the identity, §6.7.2). */
export function deriveDelta(d: Point[], i: bigint): Point {
  return derivePoint([Point.ZERO, ...d], i);
}

/** `C + D` for a redeal: the commitment after applying it (§6.7.1). */
export const addRedeal = (c: Commitment, d: Point[]): Commitment => [c[0], ...d.map((dk, k) => c[k + 1].add(dk))];

/** Lagrange coefficient of `i` at 0 over the set `xs`. Refuses repeats. */
export function lagrange(i: bigint, xs: bigint[]): bigint {
  if (new Set(xs.map(String)).size !== xs.length) refuse('repeated_index');
  let num = 1n, den = 1n;
  for (const j of xs) if (j !== i) { num = mod(num * j); den = mod(den * (j - i)); }
  return mod(num * inv(den));
}

/** Lagrange interpolation at `x0` of scalar points `(x, y)`. */
export function interpolate(pts: [bigint, bigint][], x0: bigint): bigint {
  let tot = 0n;
  for (const [xj, yj] of pts) {
    let num = 1n, den = 1n;
    for (const [xm] of pts) if (xm !== xj) { num = mod(num * (x0 - xm)); den = mod(den * (xj - xm)); }
    tot = mod(tot + yj * num * inv(den));
  }
  return tot;
}

function polyMul(a: bigint[], b: bigint[]): bigint[] {
  const r = new Array(a.length + b.length - 1).fill(0n);
  a.forEach((x, i) => b.forEach((y, j) => { r[i + j] = mod(r[i + j] + x * y); }));
  return r;
}

/** Rebuild a degree-3 commitment from four points at distinct x (core §3.4 step 4: a device's
 *  own 3 share points plus the group point at x = 0). */
export function rebuildCommitment(pts: [bigint, Point][]): Commitment {
  if (pts.length !== 4) refuse('malformed', 'rebuild needs exactly four points');
  const out: Point[] = [Point.ZERO, Point.ZERO, Point.ZERO, Point.ZERO];
  for (const [xj, yj] of pts) {
    let basis = [1n], den = 1n;
    for (const [xk] of pts) if (xk !== xj) { basis = polyMul(basis, [mod(-xk), 1n]); den = mod(den * (xj - xk)); }
    const di = inv(den);
    for (let k = 0; k < 4; k++) out[k] = out[k].add(mul(mod(basis[k] * di), yj));
  }
  return out;
}

export const sameCommitment = (a: Commitment, b: Commitment) => a.length === b.length && a.every((p, k) => p.equals(b[k]));

/** A 32-byte FROST identifier (core §3.2): big-endian scalar, hex. */
export const idHex = (i: bigint | number) => scalarHex(BigInt(i));
export { bytesToHex };
