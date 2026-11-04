// When a device counts a seated server as dead and shows the F1 card (core §6.7.6 F1, §6.7.7; Server
// profile §5): it has been quiet for 7 days; or it sent a host-signed shutdown notice; or, for a day, it has answered `deleted` (one that doesn't verify) or "unknown
// account" while its peers still serve the account. A `deleted` that verifies is not F1: the device
// destroys the account (Account admin §3). Pure: the device feeds it what each server answered.
// A host-signed `refused: expired` counts like a shutdown notice too (Server profile §4); it waits for
// spec item 47 to fix its signed form. A server that answers but won't co-sign is F4's case, not this one.

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

interface Watch { seatedAt: number; lastHeard: number; lastServing: number | null; deniedSince: number | null; shutdown: { seq: number; at: number | null } | null; seat: string }

export class F1Watch {
  #s = new Map<string, Watch>();
  readonly g: string;
  constructor(g: string) { this.g = g; }

  /** A seated server: its host and the member key of its seat. Being seated is not serving (review 8 M3). */
  seat(host: string, seatKey: string, now: number) {
    const w = this.#s.get(host);
    if (w) { w.seat = seatKey; return; }
    this.#s.set(host, { seatedAt: now, lastHeard: now, lastServing: null, deniedSince: null, shutdown: null, seat: seatKey });
  }
  forget(host: string) { this.#s.delete(host); }

  /** What `host` answered at `now`. A denial is an answer too, so quiet counts from either (review 8 M2). */
  saw(host: string, seen: Seen, now: number) {
    const w = this.#s.get(host);
    if (!w) return;
    if (seen === 'serving') { w.lastServing = now; w.lastHeard = now; w.deniedSince = null; }
    else if (seen === 'denied') { w.lastHeard = now; w.deniedSince ??= now; }
  }

  /** A shutdown notice, kept only if sent by that seat's own member key (the seal's key, so nobody else
   *  can replay an old one: review 8 M4), signed by its host and newer than the last kept. */
  notice(n: any, from: string): boolean {
    if (typeof n?.host !== 'string' || !Number.isSafeInteger(n.seq) || !(n.shutdown === null || Number.isSafeInteger(n.shutdown))) return false;
    const w = this.#s.get(n.host);
    if (!w || w.seat !== from) return false;
    if (!schnorrVerify(n.host_sig, shutdownDigest(this.g, n), n.host)) return false;
    if (w.shutdown && w.shutdown.seq >= n.seq) return false;
    w.shutdown = { seq: n.seq, at: n.shutdown };
    return true;
  }

  /** Why `host` counts as dead at `now`, or null. */
  dead(host: string, now: number): 'quiet' | 'shutdown' | 'denied' | null {
    const w = this.#s.get(host);
    if (!w) return null;
    if (w.shutdown && w.shutdown.at !== null) return 'shutdown';
    if (now - w.lastHeard >= QUIET_S) return 'quiet';
    // A day of denial, with a peer serving the account once that day had passed.
    if (w.deniedSince !== null && now - w.deniedSince >= DENIAL_S
      && [...this.#s].some(([h, x]) => h !== host && x.lastServing !== null && x.lastServing >= w.deniedSince! + DENIAL_S)) return 'denied';
    return null;
  }

  /** The card: which seats to move (F1 for one, F2 for two, F3 for all). */
  card(seats: { seat: string; host: string }[], now: number): { seat: string; host: string; why: string }[] {
    return seats.flatMap((s) => { const why = this.dead(s.host, now); return why ? [{ ...s, why }] : []; });
  }
}
