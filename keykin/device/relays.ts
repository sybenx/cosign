// Doors §2's counted relays: the account's live recorded relays (the epoch record's plus the current seat holders'),
// leaving out one that failed 10 tries over at least 7 days, each made while other counted relays answered (so a
// device's own downtime never drops one), and one that refused with `blocked:` or `restricted:` on three tries over
// at least 12 hours. A dropped relay is retried weekly and counts again once it answers (and is fetched from before
// it is written to). One that refuses writes but answers reads counts only for fetches. Pure bookkeeping: what to
// ask, and what an answer means.
//
// Not yet: a relay that accepts writes but never serves them back (it counts); the NIP-42 sign-in before a read
// (a relay that answers reads with CLOSED after AUTH is a refusal here only if it says blocked: or restricted:).

const FAILS = 10, FAIL_SPAN_S = 7 * 86400, REFUSALS = 3, REFUSAL_SPAN_S = 12 * 3600, RETRY_S = 7 * 86400;

interface Health { fails: number[]; refusals: number[]; dropped: number | null; writeRefused: boolean }

export class RelayHealth {
  #h = new Map<string, Health>();
  #of(u: string): Health { let h = this.#h.get(u); if (!h) { h = { fails: [], refusals: [], dropped: null, writeRefused: false }; this.#h.set(u, h); } return h; }

  /** The counted relays among the recorded ones. */
  counted(recorded: string[]): string[] { return [...new Set(recorded)].filter((u) => this.#h.get(u)?.dropped == null); }
  /** The counted relays a publish counts on (not those refusing writes). */
  writable(recorded: string[]): string[] { return this.counted(recorded).filter((u) => !this.#h.get(u)?.writeRefused); }
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
      if (ok.has(u)) { h.fails = []; h.refusals = []; h.dropped = null; continue; }
      if (h.dropped != null) { h.dropped = now; continue; }            // a weekly retry that failed waits another week
      if (!othersAnswered(u)) continue;
      h.fails.push(now); if (h.fails.length > FAILS) h.fails.shift();
      if (h.fails.length >= FAILS && now - h.fails[0] >= FAIL_SPAN_S) h.dropped = now;
    }
  }
  /** A publish's answers: `blocked:`/`restricted:` refusals count towards dropping, other write refusals make the
   *  relay fetch-only; an OK clears both. */
  published(results: Map<string, true | string>, now: number) {
    for (const [u, r] of results) {
      const h = this.#of(u);
      if (r === true) { h.refusals = []; h.writeRefused = false; continue; }
      if (r === 'down') continue;
      if (/^(blocked|restricted):/.test(r)) {
        h.refusals.push(now); if (h.refusals.length > REFUSALS) h.refusals.shift();
        if (h.refusals.length >= REFUSALS && now - h.refusals[0] >= REFUSAL_SPAN_S) h.dropped = now;
      } else if (!/too large|size|big/i.test(r)) h.writeRefused = true;
    }
  }
  isDropped(u: string) { return this.#h.get(u)?.dropped != null; }
  dump() { return [...this.#h]; }
  load(x: any) { this.#h = new Map(Array.isArray(x) ? x : []); }
  clear() { this.#h.clear(); }
}

/** More than half of `set` among `answered` (an empty set never has a majority). */
export const majority = (answered: Iterable<string>, set: string[]) => { const a = new Set(answered); return set.length > 0 && set.filter((u) => a.has(u)).length * 2 > set.length; };
