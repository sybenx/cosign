import { parseJson } from './bytes.ts';

// The co-signer's event checks that need no history: future dates (core §5.7 item 4) and the
// stateless destructive rule (§5.8). Pure.

export interface Ev { kind: number; created_at: number; tags: string[][]; content?: string; pubkey?: string }

export const MAX_AHEAD_S = 600;
export const MASS_TARGETS = 5;
export const BURST_WINDOW_S = 600;

export const isReplaceable = (k: number) => k === 0 || k === 3 || (k >= 10000 && k < 20000) || (k >= 30000 && k < 40000);

/** §5.7 item 4: replaceable and addressable kinds, and deletions, at most 10 minutes ahead. */
export const futureDateOk = (e: Ev, now: number) => !(isReplaceable(e.kind) || e.kind === 5) || e.created_at - now <= MAX_AHEAD_S;

/** §5.8: a tag counts only with at least two elements, empty strings included (`[]` and `["r"]` are no
 *  tag at all; `["p",""]` counts). */
const counted = (e: Ev) => e.tags.filter((t) => Array.isArray(t) && t.length >= 2);

/** The targets of a deletion: its distinct (`e` or `a`, value) pairs. */
export const deletionTargets = (e: Ev) => (e.kind === 5 ? new Set(counted(e).filter((t) => t[0] === 'e' || t[0] === 'a').map((t) => JSON.stringify([t[0], t[1]]))).size : 0);

/** §9.5's whitespace set for kind 0 fields (JavaScript's `\s`, written out so every port uses the same):
 *  U+0009–000D, U+0020, U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF. */
const NOT_WS = /[^\u0009-\u000d\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/;
export const nonEmptyField = (v: unknown) => typeof v === 'string' && NOT_WS.test(v);

/** §5.8: does this event need a lock approval or a passed hold? `recentUnapproved` is the number of
 *  deletion targets this server co-signed for the account without approval in the last 10 minutes. */
export function destructive(e: Ev, recentUnapproved = 0): boolean {
  const k = e.kind;
  if (k === 62) return true;
  // Key families §4: accept, family, release and leaked events are all Held.
  if (k === 1244 || k === 1245 || k === 1246 || k === 1247) return true;
  if (k === 5) {
    const n = deletionTargets(e);
    return n >= MASS_TARGETS || recentUnapproved + n > MASS_TARGETS;
  }
  if (k === 0) {
    const c = profileObject(e.content ?? '');
    return !c || !['name', 'display_name', 'about', 'picture'].some((f) => nonEmptyField(c[f]));
  }
  // Byte-exact and case-sensitive: "WSS://" is not a relay URL here.
  if (k === 10002 && !counted(e).some((t) => t[0] === 'r' && (t[1].startsWith('wss://') || t[1].startsWith('ws://')))) return true;
  // "Empty content" is the zero-length string; whitespace or `{}` is not empty.
  if (k === 3 || (k >= 10000 && k <= 10030) || (k >= 30000 && k <= 30030)) return counted(e).every((t) => t[0] === 'd') && (e.content ?? '') === '';
  return false;
}

/** Per-account deletion burst counter at one server: counts only, no event history (§2 item 6). */
export class BurstCounter {
  private log: { at: number; n: number }[] = [];
  recent(now: number) { this.log = this.log.filter((x) => now - x.at < BURST_WINDOW_S); return this.log.reduce((a, x) => a + x.n, 0); }
  add(now: number, n: number) { if (n > 0) this.log.push({ at: now, n }); }
}

/** §5.8 and §9.5 "Kind 0": the content as a JSON object, or null if it isn't one or breaks one of the
 *  first five rules (UTF-8, RFC 8259, no key twice, no lone surrogate or stray control character, depth).
 *  Numbers are checked against the grammar only, so no form or size fails the parse. */
export function profileObject(text: string): Record<string, unknown> | null {
  let v: unknown;
  try { v = parseJson(text, { numbers: 'grammar' }); } catch { return null; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

