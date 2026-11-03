// Byte, hash and encoding helpers every Keykin module shares. Pure.

import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes };
export type Bytes = Uint8Array;

/** A part of a hash input: raw bytes, or a string taken as UTF-8. */
export type Part = Bytes | string;
const raw = (p: Part) => (typeof p === 'string' ? utf8ToBytes(p) : p);

/** SHA-256 of the parts, concatenated. */
export const sha = (...parts: Part[]): Bytes => sha256(concatBytes(...parts.map(raw)));
export const shaHex = (...parts: Part[]) => bytesToHex(sha(...parts));

/** 4- and 8-byte big-endian integers. */
export function u32be(n: number): Bytes {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`u32: ${n}`);
  const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b;
}
export function u64be(n: number): Bytes {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`u64: ${n}`);
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b;
}

export const b64u = (b: Bytes) => Buffer.from(b).toString('base64url');
/** Strict base64url: the URL alphabet only, no padding, no spaces (Buffer alone would take anything). */
export function fromB64u(s: string): Bytes {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new KeykinError('malformed', 'base64url');
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

/** HKDF-SHA256 with an empty salt (core §4.5). */
export const hkdf32 = (ikm: Bytes, info: string): Bytes => hkdf(sha256, ikm, new Uint8Array(0), utf8ToBytes(info), 32);

/** Fixed-length hex: refuses anything else, so a malformed field never reaches the maths. */
export function hexN(h: unknown, n: number, what: string): Bytes {
  if (typeof h !== 'string' || h.length !== 2 * n || !/^[0-9a-f]*$/.test(h)) throw new KeykinError('malformed', `${what}: expected ${n} bytes of lowercase hex`);
  return hexToBytes(h);
}

/** RFC 8785 canonical JSON. Keykin bodies hold only strings, integers, booleans, null, arrays and
 *  objects; ES2015 `JSON.stringify` already serialises those as JCS does, so only key order is ours
 *  (UTF-16 code units, as RFC 8785 §3.2.3 says). */
export function jcs(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    // The strict profile: numbers in Keykin bodies are safe integers (spec issue 45).
    if (!Number.isSafeInteger(v)) throw new KeykinError('malformed', 'JCS: numbers are safe integers');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(o[k])).join(',') + '}';
  }
  throw new KeykinError('malformed', `JCS: ${typeof v}`);
}
export const jcsBytes = (v: unknown) => utf8ToBytes(jcs(v));

/** Bytewise comparison, for "sorted bytewise" (core §4.5, §6.7.1). */
export function cmpBytes(a: Bytes, b: Bytes): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
export const eqBytes = (a: Bytes, b: Bytes) => a.length === b.length && cmpBytes(a, b) === 0;

/** A refusal with a stable code, the `code` of an `error` message (core §9.1). */
export class KeykinError extends Error {
  code: string;
  constructor(code: string, message?: string) { super(message ? `${code}: ${message}` : code); this.code = code; }
}
export const refuse = (code: string, message?: string): never => { throw new KeykinError(code, message); };

/** The strict JSON profile Keykin reads every inbound body with (spec issue 45): RFC 8259 as JSON.parse
 *  takes it, but an object naming one key twice is refused (JSON.parse would silently keep the last). */
const strictSeen = new Map<string, boolean>();
export function strictJson(text: string): any {
  const v = JSON.parse(text);
  let dup = strictSeen.get(text);
  if (dup === undefined) { dup = hasDuplicateKey(text); if (strictSeen.size > 20_000) strictSeen.clear(); strictSeen.set(text, dup); }
  if (dup) throw new KeykinError('malformed', 'duplicate key');
  return v;
}
/** Scan valid JSON for an object that names one key twice (JSON.parse silently keeps the last). */
export function hasDuplicateKey(text: string): boolean {
  const stack: (Set<string> | null)[] = [];
  let i = 0, expectKey = false;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const raw = text.slice(i + 1, j);
      const str = raw.includes('\\') ? JSON.parse(text.slice(i, j + 1)) : raw;
      const top = stack[stack.length - 1];
      if (expectKey && top) { if (top.has(str)) return true; top.add(str); expectKey = false; }
      i = j + 1; continue;
    }
    if (ch === '{') { stack.push(new Set()); expectKey = true; }
    else if (ch === '[') stack.push(null);
    else if (ch === '}' || ch === ']') stack.pop();
    else if (ch === ',') expectKey = stack[stack.length - 1] instanceof Set;
    i++;
  }
  return false;
}
