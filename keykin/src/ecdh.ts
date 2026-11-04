// Weighted decryption answers with a DLEQ proof (core §5.5). Pure.

import { sha, u32be, randomBytes, hexToBytes, refuse, type Bytes } from './bytes.ts';
import { type Commitment, derivePoint, lagrange, mul, mod, pointFrom, compBytes, compHex, scalarFrom, scalarHex, G } from './curve.ts';

export interface DleqContext { g: string; epochId: string; state: string; signers: number[] }
/** One index's answer for one `Q`. */
export interface EcdhAnswer { i: number; Y: string; R1: string; R2: string; z: string }

const big = (b: Bytes) => mod(BigInt('0x' + Buffer.from(b).toString('hex')));

function challenge(ctx: DleqContext, i: number, W: Bytes, Q: Bytes, Y: Bytes, R1: Bytes, R2: Bytes): bigint {
  return big(sha('keykin/ecdh-dleq/1', hexToBytes(ctx.g), hexToBytes(ctx.epochId), hexToBytes(ctx.state), u32be(i), W, Q, Y, R1, R2));
}

/** The co-signer's answer for index `i` with share `s`: `Y = λ_i·s_i·Q` and its proof. `osRandom` is
 *  fresh randomness; `requestHash` the SHA-256 of the request, so one random state never gives one
 *  `k` for two requests (§5.5, vectors.md case 2). */
export function ecdhAnswer(ctx: DleqContext, C: Commitment, i: number, s: bigint, Qhex: string, requestHash: Bytes, osRandom: Bytes = randomBytes(32)): EcdhAnswer {
  const Q = pointFrom(Qhex, 'Q');
  const lam = lagrange(BigInt(i), ctx.signers.map(BigInt));
  const ls = mod(lam * s);
  const Y = mul(ls, Q), W = mul(lam, derivePoint(C, BigInt(i)));
  if (!mul(s).equals(derivePoint(C, BigInt(i)))) refuse('bad_share', 'share does not match P_i at this state');
  const k = big(sha('keykin/ecdh-k/1', osRandom, hexToBytes(scalarHex(s)), compBytes(Q), requestHash));
  const R1 = mul(k), R2 = mul(k, Q);
  const e = challenge(ctx, i, compBytes(W), compBytes(Q), compBytes(Y), compBytes(R1), compBytes(R2));
  return { i, Y: compHex(Y), R1: compHex(R1), R2: compHex(R2), z: scalarHex(mod(k + e * ls)) };
}

/** Check one answer against `P_i^S` derived from the state's commitment. */
export function verifyDleq(ctx: DleqContext, C: Commitment, Qhex: string, a: EcdhAnswer): boolean {
  const Q = pointFrom(Qhex, 'Q');
  let Y, R1, R2, z;
  try { Y = pointFrom(a.Y, 'Y'); R1 = pointFrom(a.R1, 'R1'); R2 = pointFrom(a.R2, 'R2'); z = scalarFrom(a.z, 'z'); } catch { return false; }
  const lam = lagrange(BigInt(a.i), ctx.signers.map(BigInt));
  const W = mul(lam, derivePoint(C, BigInt(a.i)));
  const e = challenge(ctx, a.i, compBytes(W), compBytes(Q), compBytes(Y), compBytes(R1), compBytes(R2));
  return mul(z).equals(R1.add(mul(e, W))) && mul(z, Q).equals(R2.add(mul(e, Y)));
}

/** The coordinator's check of one member's whole answer (§5.5): its indices exactly, every proof. */
export function checkEcdhAnswers(ctx: DleqContext, C: Commitment, points: string[], memberIndices: number[], answers: EcdhAnswer[][]): void {
  if (!Array.isArray(answers) || answers.length !== points.length) refuse('bad_answer', 'one answer list per point');
  answers.forEach((perQ, q) => {
    const got = perQ.map((a) => a.i);
    if (got.length !== memberIndices.length || new Set(got).size !== got.length || !memberIndices.every((i) => got.includes(i)))
      refuse('bad_answer', 'indices must equal the member\'s indices exactly');
    for (const a of perQ) if (!verifyDleq(ctx, C, points[q], a)) refuse('bad_proof', `index ${a.i}`);
  });
}

/** Sum of weighted values: with the asker's own `λ_j·s_j·Q`, this is `x·Q`. */
export const sumPoints = (ys: string[]) => ys.map((y) => pointFrom(y)).reduce((a, b) => a.add(b));
export const ownPart = (signers: number[], i: number, s: bigint, Qhex: string) => mul(mod(lagrange(BigInt(i), signers.map(BigInt)) * s), pointFrom(Qhex, 'Q'));
export { G };
