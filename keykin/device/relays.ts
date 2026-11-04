// Doors §2's counted relays: the account's live recorded relays (the epoch record's plus the current seat holders'),
// leaving out one that failed 10 tries over at least 7 days, each made while other counted relays answered (so a
// device's own downtime never drops one). A relay that refused writes with `blocked:` or `restricted:` on three
// tries over at least 12 hours counts only for fetches. A left-out relay is retried weekly (fetched, or written to)
// and counts again once it answers. Pure bookkeeping: what to ask, and what an answer means.
//
// Failures and refusals count from the first one since the relay last answered, so a relay that stays dead is
// dropped however often the device tries (review 19 H3); a timeout, `rate-limited:`, `auth-required:` or any other
// passing refusal never counts against a relay (review 19 H4), and `duplicate:` is an OK.
//
// Not yet: a relay that accepts writes but never serves them back (it counts); the NIP-42 sign-in before a read or
// a write (`auth-required:` is treated as passing).

const FAILS = 10, FAIL_SPAN_S = 7 * 86400, REFUSALS = 3, REFUSAL_SPAN_S = 12 * 3600, RETRY_S = 7 * 86400;

interface Health { fails: number; firstFail: number | null; refusals: number; firstRefusal: number | null; dropped: number | null; writeRefused: number | null }

export class RelayHealth {
  #h = new Map<string, Health>();
  #of(u: string): Health { let h = this.#h.get(u); if (!h) { h = { fails: 0, firstFail: null, refusals: 0, firstRefusal: null, dropped: null, writeRefused: null }; this.#h.set(u, h); } return h; }

  /** The counted relays among the recorded ones. */
  counted(recorded: string[]): string[] { return [...new Set(recorded)].filter((u) => this.#h.get(u)?.dropped == null); }
  /** What a publish writes to: the counted relays, a fetch-only one only on its weekly retry. */
  writable(recorded: string[], now = Infinity): string[] {
    return this.counted(recorded).filter((u) => { const w = this.#h.get(u)?.writeRefused; return w == null || now - w >= RETRY_S; });
  }
  /** What a fetch asks: the counted relays and dropped ones due their weekly retry. */
  toFetch(recorded: string[], now: number): string[] {
    return [...new Set(recorded)].filter((u) => { const d = this.#h.get(u)?.dropped; return d == null || now - d >= RETRY_S; });
  }
  /** A fetch's answers: a relay that answered counts again; one that didn't, while another counted relay answered,
   *  has failed a try. */
  fetched(asked: string[], answered: string[], recorded: string[], now: number) {
    const ok = new Set(answered), counted = new Set(this.counted(recorded));
    const othersAnswered = (u: string) => answered.some((a) => a !== u && counted.has(a));
    for (const u of asked) {
      const h = this.#of(u);
      if (ok.has(u)) { h.fails = 0; h.firstFail = null; h.dropped = null; continue; }
      if (h.dropped != null) { h.dropped = now; continue; }            // a weekly retry that failed waits another week
      if (!othersAnswered(u)) continue;
      h.fails++; h.firstFail ??= now;
      if (h.fails >= FAILS && now - h.firstFail >= FAIL_SPAN_S) h.dropped = now;
    }
  }
  /** A publish's answers: `blocked:`/`restricted:` refusals count towards making the relay fetch-only; an OK (or
   *  `duplicate:`) clears them. */
  published(results: Map<string, true | string>, now: number) {
    for (const [u, r] of results) {
      const h = this.#of(u);
      if (r === true || /^duplicate:/.test(r)) { h.refusals = 0; h.firstRefusal = null; h.writeRefused = null; continue; }
      if (!/^(blocked|restricted):/.test(r)) continue;
      if (h.writeRefused != null) { h.writeRefused = now; continue; }  // a weekly retry refused again
      h.refusals++; h.firstRefusal ??= now;
      if (h.refusals >= REFUSALS && now - h.firstRefusal >= REFUSAL_SPAN_S) h.writeRefused = now;
    }
  }
  isDropped(u: string) { return this.#h.get(u)?.dropped != null; }
  dump() { return [...this.#h]; }
  load(x: any) {
    this.#h = new Map((Array.isArray(x) ? x : []).filter((p: any) => Array.isArray(p) && typeof p[0] === 'string' && p[1] && typeof p[1] === 'object' && typeof p[1].fails === 'number')
      .map(([u, h]: [string, any]) => [u, { fails: h.fails, firstFail: h.firstFail ?? null, refusals: h.refusals ?? 0, firstRefusal: h.firstRefusal ?? null, dropped: h.dropped ?? null, writeRefused: typeof h.writeRefused === 'number' ? h.writeRefused : null }]));
  }
  clear() { this.#h.clear(); }
}

/** More than half of `set` among `answered` (an empty set never has a majority). */
export const majority = (answered: Iterable<string>, set: string[]) => { const a = new Set(answered); return set.length > 0 && set.filter((u) => a.has(u)).length * 2 > set.length; };
