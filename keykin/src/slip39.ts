// SLIP-0039 (satoshilabs/slips), written from the specification: Shamir over GF(256) with a digest
// share, two levels (groups and members), the RS1024 checksum, and the four-round Feistel encryption.
// Backup module §3 uses one group, 2 of 3, empty passphrase, iteration exponent 1, extendable.

import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, concatBytes, utf8ToBytes, refuse } from './bytes.ts';
import { WORDS } from './slip39-words.ts';

const RADIX = 10, ID_BITS = 15, META_WORDS = 4, CHECKSUM_WORDS = 3, MIN_WORDS = 20;
const SECRET_INDEX = 255, DIGEST_INDEX = 254, DIGEST_LEN = 4, BASE_ITER = 10000, ROUNDS = 4;
const WORD_INDEX = new Map(WORDS.map((w, i) => [w, i]));

// --- GF(256), the Rijndael field -----------------------------------------------------------
const EXP = new Uint8Array(255), LOG = new Uint8Array(256);
{ let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x ^= (x << 1) ^ ((x & 0x80) ? 0x11b : 0); x &= 0xff; } }
// (x ← x·3: x·2 reduced mod x^8+x^4+x^3+x+1, plus x.)
const gmul = (a: number, b: number) => (a === 0 || b === 0 ? 0 : EXP[(LOG[a] + LOG[b]) % 255]);
const gdiv = (a: number, b: number) => { if (b === 0) throw new Error('div0'); return a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255]; };

/** Lagrange interpolation at x of the points (xi, yi), each yi a byte vector. */
function interpolate(points: [number, Uint8Array][], x: number): Uint8Array {
  const xs = points.map((p) => p[0]);
  if (new Set(xs).size !== xs.length) refuse('slip39', 'share indices must be unique');
  const len = points[0][1].length;
  if (points.some((p) => p[1].length !== len)) refuse('slip39', 'share values must have one length');
  const hit = points.find((p) => p[0] === x);
  if (hit) return hit[1];
  const out = new Uint8Array(len);
  for (const [xi, yi] of points) {
    let basis = 1;
    for (const xj of xs) if (xj !== xi) basis = gmul(basis, gdiv(x ^ xj, xi ^ xj));
    for (let k = 0; k < len; k++) out[k] ^= gmul(yi[k], basis);
  }
  return out;
}

const digestOf = (r: Uint8Array, s: Uint8Array) => hmac(sha256, r, s).slice(0, DIGEST_LEN);

/** SplitSecret(T, N, S): shares for indices 0 … N−1. */
export function splitSecret(T: number, N: number, S: Uint8Array, rand: (n: number) => Uint8Array = randomBytes): Uint8Array[] {
  if (!(0 < T && T <= N && N <= 16)) refuse('slip39', 'need 0 < T ≤ N ≤ 16');
  if (S.length * 8 < 128 || S.length % 2) refuse('slip39', 'secret length');
  if (T === 1) return Array.from({ length: N }, () => S.slice());
  const R = rand(S.length - DIGEST_LEN);
  const D = concatBytes(digestOf(R, S), R);
  const random = Array.from({ length: T - 2 }, () => rand(S.length));
  const base: [number, Uint8Array][] = [...random.map((y, i) => [i, y] as [number, Uint8Array]), [DIGEST_INDEX, D], [SECRET_INDEX, S]];
  return Array.from({ length: N }, (_, i) => (i < T - 2 ? random[i] : interpolate(base, i)));
}

/** RecoverSecret(T, shares): interpolate S and D, and check the digest. */
export function recoverSecret(T: number, shares: [number, Uint8Array][]): Uint8Array {
  if (T === 1) return shares[0][1];
  const S = interpolate(shares, SECRET_INDEX), D = interpolate(shares, DIGEST_INDEX);
  const want = digestOf(D.slice(DIGEST_LEN), S);
  if (!want.every((b, k) => b === D[k])) refuse('slip39', 'invalid digest of the shared secret');
  return S;
}

// --- RS1024 ---------------------------------------------------------------------------------
const GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120];
function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 20;
    chk = (((chk & 0xfffff) << 10) ^ v) >>> 0;
    for (let i = 0; i < 10; i++) if ((b >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}
const csValues = (ext: boolean) => [...(ext ? 'shamir_extendable' : 'shamir')].map((c) => c.charCodeAt(0));
export const rs1024Verify = (ext: boolean, data: number[]) => polymod([...csValues(ext), ...data]) === 1;
export function rs1024Create(ext: boolean, data: number[]): number[] {
  const p = polymod([...csValues(ext), ...data, 0, 0, 0]) ^ 1;
  return [0, 1, 2].map((i) => (p >>> (10 * (2 - i))) & 1023);
}

// --- the Feistel encryption -----------------------------------------------------------------
function passBytes(p: string) {
  if (![...p].every((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126)) refuse('slip39', 'the passphrase is printable ASCII');
  return utf8ToBytes(p);
}
function feistel(input: Uint8Array, passphrase: string, e: number, id: number, ext: boolean, order: number[]): Uint8Array {
  if (input.length % 2) refuse('slip39', 'even length');
  const half = input.length / 2;
  let L = input.slice(0, half), R = input.slice(half);
  const salt = ext ? new Uint8Array(0) : concatBytes(utf8ToBytes('shamir'), new Uint8Array([id >> 8, id & 0xff]));
  const pw = passBytes(passphrase);
  for (const i of order) {
    const f = pbkdf2(sha256, concatBytes(new Uint8Array([i]), pw), concatBytes(salt, R), { c: (BASE_ITER / ROUNDS) << e, dkLen: half });
    const next = L.map((b, k) => b ^ f[k]);
    L = R; R = next;
  }
  return concatBytes(R, L);
}
export const encrypt = (ms: Uint8Array, p: string, e: number, id: number, ext: boolean) => feistel(ms, p, e, id, ext, [0, 1, 2, 3]);
export const decrypt = (ems: Uint8Array, p: string, e: number, id: number, ext: boolean) => feistel(ems, p, e, id, ext, [3, 2, 1, 0]);

// --- shares as mnemonics --------------------------------------------------------------------
export interface Share { id: number; ext: boolean; e: number; gi: number; gt: number; g: number; mi: number; mt: number; value: Uint8Array }

export function encodeShare(s: Share): string {
  const valueBits = s.value.length * 8, padded = Math.ceil(valueBits / RADIX) * RADIX;
  let n = BigInt(s.id);
  for (const [v, bits] of [[s.ext ? 1 : 0, 1], [s.e, 4], [s.gi, 4], [s.gt - 1, 4], [s.g - 1, 4], [s.mi, 4], [s.mt - 1, 4]] as [number, number][]) n = (n << BigInt(bits)) | BigInt(v);
  n = (n << BigInt(padded)) | BigInt('0x' + (Buffer.from(s.value).toString('hex') || '0'));
  const words = (ID_BITS + 1 + 4 + 4 * 5 + padded) / RADIX;
  const data = Array.from({ length: words }, (_, k) => Number((n >> BigInt(RADIX * (words - 1 - k))) & 1023n));
  return [...data, ...rs1024Create(s.ext, data)].map((i) => WORDS[i]).join(' ');
}

export function decodeShare(mnemonic: string): Share {
  const idx = mnemonic.trim().split(/\s+/).map((w) => { const i = WORD_INDEX.get(w.toLowerCase()); if (i === undefined) refuse('slip39', `not a SLIP-39 word: ${w}`); return i!; });
  if (idx.length < MIN_WORDS) refuse('slip39', 'mnemonic too short');
  const padLen = (RADIX * (idx.length - META_WORDS - CHECKSUM_WORDS)) % 16;
  if (padLen > 8) refuse('slip39', 'invalid mnemonic length');
  const ext = ((idx[1] >> 4) & 1) === 1;
  if (!rs1024Verify(ext, idx)) refuse('slip39', 'invalid checksum');
  let n = 0n;
  for (const i of idx.slice(0, -CHECKSUM_WORDS)) n = (n << 10n) | BigInt(i);
  const totalBits = RADIX * (idx.length - CHECKSUM_WORDS), valueBitsPadded = totalBits - 40;
  // The 40-bit header, from the top: id 15 | ext 1 | e 4 | GI 4 | Gt 4 | g 4 | I 4 | t 4.
  const meta = n >> BigInt(valueBitsPadded);
  const field = (shift: number, bits: number) => Number((meta >> BigInt(shift)) & ((1n << BigInt(bits)) - 1n));
  const valueBytes = (valueBitsPadded - padLen) / 8;
  const v = n & ((1n << BigInt(valueBitsPadded)) - 1n);
  if (v >> BigInt(valueBytes * 8) !== 0n) refuse('slip39', 'invalid padding');
  const value = Uint8Array.from(Buffer.from(v.toString(16).padStart(valueBytes * 2, '0'), 'hex'));
  if (value.length * 8 < 128) refuse('slip39', 'invalid master secret length');
  return { id: field(25, 15), ext, e: field(20, 4), gi: field(16, 4), gt: field(12, 4) + 1, g: field(8, 4) + 1, mi: field(4, 4), mt: field(0, 4) + 1, value };
}

/** GenerateShares(GT, [(T_i, N_i)], MS, P, e), ext = 1 as the spec now requires. */
export function generate(gt: number, groups: [number, number][], ms: Uint8Array, passphrase = '', e = 1, rand: (n: number) => Uint8Array = randomBytes): string[][] {
  if (ms.length * 8 < 128 || ms.length % 2) refuse('slip39', 'master secret length');
  if (gt < 1 || gt > groups.length) refuse('slip39', 'group threshold');
  if (groups.some(([t, n]) => t === 1 && n > 1)) refuse('slip39', 'a 1-of-N group is not allowed');
  const idb = rand(2), id = ((idb[0] << 8) | idb[1]) & 0x7fff;
  const ems = encrypt(ms, passphrase, e, id, true);
  const gshares = splitSecret(gt, groups.length, ems, rand);
  return groups.map(([t, n], gi) => splitSecret(t, n, gshares[gi], rand).map((value, mi) =>
    encodeShare({ id, ext: true, e, gi, gt, g: groups.length, mi, mt: t, value })));
}

/** Combine mnemonics (the spec's checks, then both levels, then decryption). */
export function combine(mnemonics: string[], passphrase = ''): Uint8Array {
  if (!mnemonics.length) refuse('slip39', 'no shares');
  const shares = mnemonics.map(decodeShare);
  const s0 = shares[0];
  for (const s of shares) if (s.id !== s0.id || s.ext !== s0.ext || s.e !== s0.e || s.gt !== s0.gt || s.g !== s0.g || s.value.length !== s0.value.length)
    refuse('slip39', 'shares do not belong together');
  if (s0.g < s0.gt) refuse('slip39', 'group threshold exceeds group count');
  const byGroup = new Map<number, Share[]>();
  for (const s of shares) byGroup.set(s.gi, [...(byGroup.get(s.gi) ?? []), s]);
  if (byGroup.size !== s0.gt) refuse('slip39', `need exactly ${s0.gt} groups`);
  const groupShares: [number, Uint8Array][] = [];
  for (const [gi, ms] of byGroup) {
    if (new Set(ms.map((m) => m.mt)).size !== 1) refuse('slip39', 'member thresholds differ');
    if (new Set(ms.map((m) => m.mi)).size !== ms.length) refuse('slip39', 'duplicate member index');
    if (ms.length !== ms[0].mt) refuse('slip39', 'wrong number of member shares');
    groupShares.push([gi, recoverSecret(ms[0].mt, ms.map((m) => [m.mi, m.value]))]);
  }
  const ems = recoverSecret(s0.gt, groupShares);
  return decrypt(ems, passphrase, s0.e, s0.id, s0.ext);
}

/** Backup module §3: the backup secret as three friends' pieces, any two of which recover it. */
export const backupPieces = (secret: Uint8Array) => generate(1, [[2, 3]], secret, '', 1)[0];
export { sha256 };
