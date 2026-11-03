// When a device counts a seated server as dead and shows the F1 card (core §6.7.6 F1, §6.7.7; Server
// profile §5): it has been quiet for 7 days; or it sent a host-signed shutdown notice (or a host-signed
// `refused: expired`); or, for a day, it has answered `deleted` (one that doesn't verify) or "unknown
// account" while its peers still serve the account. A `deleted` that verifies is not F1: the device
// destroys the account (Account admin §3). Pure: the device feeds it what each server answered.

import { detachedDigest } from './codes.ts';
import { schnorrVerify, schnorrSign, type KeyPair } from './event.ts';

export const QUIET_S = 7 * 86400;
export const DENIAL_S = 86400;

/** What one server's answer to a request for the account told the device. */
export type Seen = 'serving' | 'silent' | 'denied';

/** Server profile §5: `notice {shutdown, seq, host}`, host-signed. `shutdown: null` cancels, and a higher
 *  `seq` replaces a lower one. (The signed bytes: this implementation's choice, spec item 47.) */
export const shutdownDigest = (g: string, n: { shutdown: number | null; seq: number; host: string }) => detachedDigest('shutdown', g, { shutdown: n.shutdown, seq: n.seq, host: n.host });
export const signShutdown = (g: string, host: KeyPair, shutdown: number | null, seq: number) =>
  ({ type: 'notice', shutdown, seq, host: host.pub, host_sig: schnorrSign(shutdownDigest(g, { shutdown, seq, host: host.pub }), host.sk) });

interface Watch { lastServing: number; deniedSince: number | null; shutdown: { seq: number; at: number | null } | null; expiredRefusal: boolean }

export class F1Watch {
  #s = new Map<string, Watch>();
  readonly g: string;
  constructor(g: string) { this.g = g; }
  #get(host: string, now: number) { let w = this.#s.get(host); if (!w) { w = { lastServing: now, deniedSince: null, shutdown: null, expiredRefusal: false }; this.#s.set(host, w); } return w; }

  /** A seated server's host, from the time it was seated (quiet is counted from then). */
  seat(host: string, now: number) { this.#get(host, now); }
  forget(host: string) { this.#s.delete(host); }

  /** What `host` answered at `now`. */
  saw(host: string, seen: Seen, now: number) {
    const w = this.#get(host, now);
    if (seen === 'serving') { w.lastServing = now; w.deniedSince = null; }
    else if (seen === 'denied') w.deniedSince ??= now;
  }

  /** A shutdown notice, kept only if signed by that host and newer than the last. */
  notice(n: any): boolean {
    if (typeof n?.host !== 'string' || !Number.isSafeInteger(n.seq) || !(n.shutdown === null || Number.isSafeInteger(n.shutdown))) return false;
    if (!schnorrVerify(n.host_sig, shutdownDigest(this.g, n), n.host)) return false;
    const w = this.#s.get(n.host);
    if (!w || (w.shutdown && w.shutdown.seq >= n.seq)) return false;
    w.shutdown = { seq: n.seq, at: n.shutdown };
    return true;
  }
  /** A host-signed `refused: expired` (Server profile §4) counts like a shutdown notice. */
  expired(host: string) { const w = this.#s.get(host); if (w) w.expiredRefusal = true; }

  /** Why `host` counts as dead at `now`, or null. */
  dead(host: string, now: number): 'quiet' | 'shutdown' | 'denied' | null {
    const w = this.#s.get(host);
    if (!w) return null;
    if ((w.shutdown && w.shutdown.at !== null) || w.expiredRefusal) return 'shutdown';
    if (now - w.lastServing >= QUIET_S) return 'quiet';
    // A day of denial, with a peer serving the account once that day had passed.
    if (w.deniedSince !== null && now - w.deniedSince >= DENIAL_S
      && [...this.#s].some(([h, x]) => h !== host && x.lastServing >= w.deniedSince! + DENIAL_S)) return 'denied';
    return null;
  }

  /** The card: which seats to move (F1 for one, F2 for two, F3 for all). */
  card(seats: { seat: string; host: string }[], now: number): { seat: string; host: string; why: string }[] {
    return seats.flatMap((s) => { const why = this.dead(s.host, now); return why ? [{ ...s, why }] : []; });
  }
}
