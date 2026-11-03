// The co-signer's event checks that need no history: future dates (core §5.7 item 4) and the
// stateless destructive rule (§5.8). Pure.

export interface Ev { kind: number; created_at: number; tags: string[][]; content?: string; pubkey?: string }

export const MAX_AHEAD_S = 600;
export const MASS_TARGETS = 5;
export const BURST_WINDOW_S = 600;

export const isReplaceable = (k: number) => k === 0 || k === 3 || (k >= 10000 && k < 20000) || (k >= 30000 && k < 40000);

/** §5.7 item 4: replaceable and addressable kinds, and deletions, at most 10 minutes ahead. */
export const futureDateOk = (e: Ev, now: number) => !(isReplaceable(e.kind) || e.kind === 5) || e.created_at - now <= MAX_AHEAD_S;

/** The `e`/`a` targets of a deletion. */
export const deletionTargets = (e: Ev) => (e.kind === 5 ? e.tags.filter((t) => t[0] === 'e' || t[0] === 'a').length : 0);

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
    return !c || !['name', 'display_name', 'about', 'picture'].some((f) => typeof c[f] === 'string' && /\S/.test(c[f]));
  }
  if (k === 10002 && !e.tags.some((t) => t[0] === 'r' && /^wss?:\/\//.test(t[1] ?? ''))) return true;
  if (k === 3 || (k >= 10000 && k <= 10030) || (k >= 30000 && k <= 30030)) return e.tags.every((t) => t[0] === 'd') && (e.content ?? '') === '';
  return false;
}

/** Per-account deletion burst counter at one server: counts only, no event history (§2 item 6). */
export class BurstCounter {
  private log: { at: number; n: number }[] = [];
  recent(now: number) { this.log = this.log.filter((x) => now - x.at < BURST_WINDOW_S); return this.log.reduce((a, x) => a + x.n, 0); }
  add(now: number, n: number) { if (n > 0) this.log.push({ at: now, n }); }
}

/** §5.8 (13.8): a kind 0 content as a JSON object, or null if it isn't one or repeats a key at any level. */
export function profileObject(text: string): Record<string, unknown> | null {
  let v: unknown;
  try { v = JSON.parse(text); } catch { return null; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  return hasDuplicateKey(text) ? null : (v as Record<string, unknown>);
}

/** Scan valid JSON for an object that names one key twice (JSON.parse silently keeps the last). */
function hasDuplicateKey(text: string): boolean {
  const stack: (Set<string> | null)[] = [];
  let i = 0, expectKey = false;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const str = JSON.parse(text.slice(i, j + 1));
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
