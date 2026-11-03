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
  if (k === 5) {
    const n = deletionTargets(e);
    return n >= MASS_TARGETS || recentUnapproved + n > MASS_TARGETS;
  }
  if (k === 0) {
    let c: any;
    try { c = JSON.parse(e.content ?? ''); } catch { return true; }
    if (!c || typeof c !== 'object') return true;
    return !['name', 'display_name', 'about', 'picture'].some((f) => typeof c[f] === 'string' && c[f].length > 0);
  }
  if (k === 10002 && !e.tags.some((t) => t[0] === 'r')) return true;
  if (k === 3 || (k >= 10000 && k <= 10030) || (k >= 30000 && k <= 30030)) return e.tags.every((t) => t[0] === 'd');
  return false;
}

/** Per-account deletion burst counter at one server: counts only, no event history (§2 item 6). */
export class BurstCounter {
  private log: { at: number; n: number }[] = [];
  recent(now: number) { this.log = this.log.filter((x) => now - x.at < BURST_WINDOW_S); return this.log.reduce((a, x) => a + x.n, 0); }
  add(now: number, n: number) { if (n > 0) this.log.push({ at: now, n }); }
}
