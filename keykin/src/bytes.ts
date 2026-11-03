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
/** Strict base64url (§9.5): the URL alphabet only, no padding or spaces, a length that is not 1 mod 4 and
 *  zero unused bits; checked by re-encoding, since Buffer alone would take anything. */
export function fromB64u(s: string): Bytes {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new KeykinError('malformed', 'base64url');
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s) throw new KeykinError('malformed', 'base64url: unused bits or length');
  return new Uint8Array(b);
}
/** Strict standard base64 with padding (§9.5: a part's `data`, NIP-44 payloads): length 0 mod 4, at most
 *  two `=` and only at the end, zero unused bits. */
export function fromB64(s: string): Bytes {
  if (typeof s !== 'string' || s.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new KeykinError('malformed', 'base64');
  const b = Buffer.from(s, 'base64');
  if (b.toString('base64') !== s) throw new KeykinError('malformed', 'base64: unused bits');
  return new Uint8Array(b);
}

/** HKDF-SHA256 with an empty salt (core §4.5). */
export const hkdf32 = (ikm: Bytes, info: string): Bytes => hkdf(sha256, ikm, new Uint8Array(0), utf8ToBytes(info), 32);

/** Fixed-length hex: refuses anything else, so a malformed field never reaches the maths. */
export function hexN(h: unknown, n: number, what: string): Bytes {
  if (typeof h !== 'string' || h.length !== 2 * n || !/^[0-9a-f]*$/.test(h)) throw new KeykinError('malformed', `${what}: expected ${n} bytes of lowercase hex`);
  return hexToBytes(h);
}

/** RFC 8785 canonical JSON over the complete tree (§9.5). On values that pass the profile, ES2019
 *  `JSON.stringify` writes strings and safe integers exactly as JCS does (`"` and `\` escaped, the five as
 *  `\b \t \n \f \r`, everything else raw), so only key order is ours: UTF-16 code units, sorted by hand
 *  rather than by an object's own order. Anything outside the profile is refused, never written. */
export function jcs(v: unknown, depth = 1): string {
  if (depth > MAX_DEPTH) bad(`JCS: nested deeper than ${MAX_DEPTH}`);
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') { const f = stringFault(v); if (f) bad(`JCS: ${f}`); return JSON.stringify(v); }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) bad('JCS: numbers are safe integers');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map((x) => jcs(x, depth + 1)).join(',') + ']';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return '{' + keys.map((k) => jcs(k, depth + 1) + ':' + jcs(o[k], depth + 1)).join(',') + '}';
  }
  return bad(`JCS: ${typeof v}`);
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

// --- The JSON profile (core §9.5) ------------------------------------------------------------
// One RFC 8259 reader, written by hand because JSON.parse cannot refuse what §9.5 refuses: a key named
// twice, `1.0`, `1e0` or `-0`, a number past 2^53 − 1, an escaped lone surrogate or control character,
// nesting past depth 32. Every refusal is `malformed` with the cause in the message.

const MAX_DEPTH = 32;
const NUM = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
const STR = /"((?:[^"\\\u0000-\u001f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*)"/y;
const WS = /[ \t\n\r]*/y;
const ESC: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
const bad = (why: string): never => { throw new KeykinError('malformed', why); };

/** Why a string breaks §9.5 (a lone surrogate, a control character other than the five), or null. */
export function stringFault(s: string): string | null {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 && c !== 8 && c !== 9 && c !== 10 && c !== 12 && c !== 13) return `contains control character U+${c.toString(16).toUpperCase().padStart(4, '0')}`;
    if (c >= 0xd800 && c <= 0xdbff) { const d = s.charCodeAt(i + 1); if (d >= 0xdc00 && d <= 0xdfff) { i++; continue; } return 'contains a lone surrogate'; }
    if (c >= 0xdc00 && c <= 0xdfff) return 'contains a lone surrogate';
  }
  return null;
}

/** `numbers: 'grammar'` is kind 0 content's reading (§9.5): numbers are checked against RFC 8259's
 *  grammar only and never refused for their form or size. */
export function parseJson(text: string, o: { numbers?: 'strict' | 'grammar' } = {}): any {
  if (typeof text !== 'string') bad('not text');
  const strict = o.numbers !== 'grammar';
  let i = 0;
  const ws = () => { WS.lastIndex = i; WS.exec(text); i = WS.lastIndex; };
  const str = (): string => {
    STR.lastIndex = i;
    const m = STR.exec(text);
    if (!m) bad('a string');
    i = STR.lastIndex;
    const raw = m![1];
    const v = raw.includes('\\') ? raw.replace(/\\(?:u([0-9a-fA-F]{4})|(.))/g, (_, h, c) => (h ? String.fromCharCode(parseInt(h, 16)) : ESC[c])) : raw;
    const f = stringFault(v);
    if (f) bad(f);
    return v;
  };
  const value = (depth: number): any => {
    if (depth > MAX_DEPTH) bad(`nested deeper than ${MAX_DEPTH}`);
    const c = text[i];
    if (c === '{') {
      i++; ws();
      const out: Record<string, unknown> = {}, seen = new Set<string>();
      if (text[i] === '}') { i++; return out; }
      for (;;) {
        if (text[i] !== '"') bad('a key');
        const k = str();
        if (seen.has(k)) bad(`the key "${k}" twice`);
        seen.add(k); ws();
        if (text[i] !== ':') bad('":"'); i++; ws();
        // defineProperty, so a key "__proto__" is an ordinary key.
        Object.defineProperty(out, k, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') { i++; ws(); continue; }
        if (text[i] === '}') { i++; return out; }
        bad('"," or "}"');
      }
    }
    if (c === '[') {
      i++; ws();
      const out: unknown[] = [];
      if (text[i] === ']') { i++; return out; }
      for (;;) {
        out.push(value(depth + 1)); ws();
        if (text[i] === ',') { i++; ws(); continue; }
        if (text[i] === ']') { i++; return out; }
        bad('"," or "]"');
      }
    }
    if (c === '"') return str();
    for (const [w, v] of [['true', true], ['false', false], ['null', null]] as const) if (text.startsWith(w, i)) { i += w.length; return v; }
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) bad(i >= text.length ? 'unexpected end' : `unexpected "${text[i]}"`);
    i = NUM.lastIndex;
    const n = Number(m![0]);
    if (strict) {
      if (m![1] || m![2]) bad(`the number ${m![0]} is not an integer spelled -?(0|[1-9][0-9]*)`);
      if (m![0] === '-0') bad('-0');
      if (!Number.isSafeInteger(n)) bad(`the number ${m![0]} is beyond 2^53 - 1`);
    }
    return n;
  };
  ws();
  const v = value(1);
  ws();
  if (i !== text.length) bad('text after the value');
  return v;
}
export const strictJson = (text: string): any => parseJson(text);

/** Fatal UTF-8 (§9.5): overlong forms, encoded surrogates and values past U+10FFFF are refused, never
 *  repaired; a byte order mark is kept, so the JSON reader refuses it. */
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export function utf8Strict(b: Uint8Array): string {
  try { return UTF8.decode(b); } catch { return bad('invalid UTF-8'); }
}

/** The same rules on a value built in memory (an event a site hands over, a body about to be hashed):
 *  plain arrays and objects, strings §9.5 allows, safe integers, depth at most 32. */
export function checkTree(v: unknown, depth = 1): void {
  if (depth > MAX_DEPTH) bad(`nested deeper than ${MAX_DEPTH}`);
  if (v === null || typeof v === 'boolean') return;
  if (typeof v === 'string') { const f = stringFault(v); if (f) bad(f); return; }
  if (typeof v === 'number') { if (!Number.isSafeInteger(v) || Object.is(v, -0)) bad('numbers are safe integers'); return; }
  if (Array.isArray(v)) { for (const x of v) checkTree(x, depth + 1); return; }
  if (typeof v === 'object') {
    for (const [k, x] of Object.entries(v as object)) { if (x === undefined) continue; const f = stringFault(k); if (f) bad(`a key ${f}`); checkTree(x, depth + 1); }
    return;
  }
  bad(typeof v);
}
