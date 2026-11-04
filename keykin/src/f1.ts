// When a device counts a seated server as dead and shows the F1 card (core §6.7.6 F1, §6.7.7; Server
// profile §4.1, §5, draft 8): it has been quiet for 7 days; or a live answer to `notice_get` carries a
// shutdown date no more than 30 days ahead; or, for a day, it has answered `deleted` (one that doesn't
// verify) or "unknown account" while its peers still serve the account. A `deleted` that verifies is
// not F1: the device destroys the account (Account admin §3). A pushed notice only prompts a
// `notice_get`. A server that answers but won't co-sign is F4's case (core item 48 a). Pure.

import { detachedDigest } from './codes.ts';
import { schnorrVerify, schnorrSign, type KeyPair } from './event.ts';

export const QUIET_S = 7 * 86400;
export const DENIAL_S = 86400;
export const NOTICE_AHEAD_S = 30 * 86400;
export const NOTICE_ASK_S = 3600;
export const NOTICE_ANSWER_S = 120 + 30;

/** What one server's answer to a request for the account told the device. */
export type Seen = 'serving' | 'silent' | 'denied';

// --- Server profile §4.1: host-signed notices, answers and refusals ---------------------------
export interface Notice { shutdown: number | null; seq: number; host: string; member: string }
export const noticeDigest = (g: string, n: Notice) => detachedDigest('shutdown', g, { shutdown: n.shutdown, seq: n.seq, host: n.host, member: n.member });
export const answerDigest = (g: string, n: Notice, re: string) => detachedDigest('shutdown-answer', g, { shutdown: n.shutdown, seq: n.seq, host: n.host, member: n.member, re });
export const refusedDigest = (g: string, r: { re: string; code: string; host: string }) => detachedDigest('refused', g, { re: r.re, code: r.code, host: r.host });

/** A shutdown notice as the host pushes it (`null` cancels; `seq = max(now, last + 1)`). */
export const signNotice = (g: string, host: KeyPair, n: Omit<Notice, 'host'>) =>
  ({ type: 'notice', ...n, host: host.pub, host_sig: schnorrSign(noticeDigest(g, { ...n, host: host.pub }), host.sk) });
/** The live answer to `notice_get` `re`: the latest notice for the seat, or `null` with `seq` 0. */
export const signAnswer = (g: string, host: KeyPair, n: Omit<Notice, 'host'>, re: string) =>
  ({ type: 'notice', re, ...n, host: host.pub, host_sig: schnorrSign(answerDigest(g, { ...n, host: host.pub }, re), host.sk) });
/** A host-signed refusal of `enroll` `re` (only the pick's answer is host-signed). */
export const signRefusal = (g: string, host: KeyPair, re: string, code: 'refused: closing' | 'refused: full') =>
  ({ type: 'error', re, code, host: host.pub, host_sig: schnorrSign(refusedDigest(g, { re, code, host: host.pub }), host.sk) });
/** A device takes a refusal only from the host it asked, for its own `enroll`, with a checking signature;
 *  it makes the pick fall through and never brings the F1 card. */
export const checkRefusal = (g: string, r: any, askedHost: string, enrollId: string) =>
  r?.type === 'error' && r.host === askedHost && r.re === enrollId && ['refused: closing', 'refused: full'].includes(r.code) && schnorrVerify(r.host_sig, refusedDigest(g, r), r.host);

const noticeShape = (n: any) => typeof n?.host === 'string' && typeof n?.member === 'string' && Number.isSafeInteger(n.seq) && n.seq >= 0 && (n.shutdown === null || Number.isSafeInteger(n.shutdown));

interface Watch { seatedAt: number; lastHeard: number; lastServing: number | null; deniedSince: number | null; seat: string
  // The latest live answer kept, the request outstanding (with the best answer to it so far), the last ask.
  kept: { seq: number; at: number | null } | null; asking: { id: string; until: number; best: { seq: number; at: number | null } | null } | null; askedAt: number | null }

export class F1Watch {
  #s = new Map<string, Watch>();
  readonly g: string;
  constructor(g: string) { this.g = g; }

  /** A seated server: its host and the member key of its seat. Being seated is not serving (review 8 M3). */
  seat(host: string, seatKey: string, now: number) {
    const w = this.#s.get(host);
    if (w) { w.seat = seatKey; return; }
    this.#s.set(host, { seatedAt: now, lastHeard: now, lastServing: null, deniedSince: null, seat: seatKey, kept: null, asking: null, askedAt: null });
  }
  forget(host: string) { this.#s.delete(host); }

  /** What `host` answered at `now`. A denial is an answer too, so quiet counts from either (review 8 M2). */
  saw(host: string, seen: Seen, now: number) {
    const w = this.#s.get(host);
    if (!w) return;
    if (seen === 'serving') { w.lastServing = now; w.lastHeard = now; w.deniedSince = null; }
    else if (seen === 'denied') { w.lastHeard = now; w.deniedSince ??= now; }
  }

  /** A pushed notice (no `re`): only a reason to ask. True when the device should send `notice_get` now:
   *  for a seat it has, signed by that host for that seat's member key, with a `seq` above the one kept,
   *  at most once an hour per seat. */
  pushed(n: any, now: number): boolean {
    if (!noticeShape(n) || n.re !== undefined) return false;
    const w = this.#s.get(n.host);
    if (!w || w.seat !== n.member || !schnorrVerify(n.host_sig, noticeDigest(this.g, n), n.host)) return false;
    if (w.kept && n.seq <= w.kept.seq) return false;
    return w.askedAt === null || now - w.askedAt >= NOTICE_ASK_S;
  }
  /** The device sends `notice_get` `id` to `host`'s seat: answers count only to it, for its lifetime. */
  asked(host: string, id: string, now: number) {
    const w = this.#s.get(host);
    if (!w) return;
    w.asking = { id, until: now + NOTICE_ANSWER_S, best: null }; w.askedAt = now;
  }
  /** A live answer, sealed by `from`. Taken only for the outstanding request, from that seat's member
   *  key, for that seat's host and member, with the answer signature; the highest `seq` among answers to
   *  one request wins, and it replaces whatever was kept. */
  answer(n: any, from: string, now: number): boolean {
    if (!noticeShape(n) || typeof n.re !== 'string') return false;
    const w = this.#s.get(n.host);
    if (!w || w.seat !== from || n.member !== from || !w.asking || w.asking.id !== n.re || now > w.asking.until) return false;
    if (!schnorrVerify(n.host_sig, answerDigest(this.g, n, n.re), n.host)) return false;
    if (w.asking.best && w.asking.best.seq >= n.seq) return false;
    w.asking.best = { seq: n.seq, at: n.shutdown };
    w.kept = w.asking.best;
    return true;
  }
  /** What the device shows on Backup for this seat: a closing date, if the latest answer has one. */
  closing(host: string) { return this.#s.get(host)?.kept?.at ?? null; }

  dump() { return [...this.#s].map(([h, w]) => [h, { ...w, asking: null }]); }
  load(x: [string, Watch][]) { this.#s = new Map(x); }

  /** Why `host` counts as dead at `now`, or null. */
  dead(host: string, now: number): 'quiet' | 'shutdown' | 'denied' | null {
    const w = this.#s.get(host);
    if (!w) return null;
    // A live answer's date counts when no more than 30 days ahead; a past date counts.
    if (w.kept && w.kept.at !== null && w.kept.at <= now + NOTICE_AHEAD_S) return 'shutdown';
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

// --- Core §6.7.9 (non-normative): "S3 hasn't helped sign this week" ---------------------------
// A server that answers but won't co-sign is never dead for F1 (core §10, item 48 a): the person may move
// it by hand (F4). The device shows one quiet line on Backup when, over 7 days, the server left at least
// 3 `sign` requests on 2 different days unanswered for their whole lifetime (no valid partial, even late,
// and no `error`) while another server co-signed each of them. Never a card, a dot or a trigger.

export const HELP_WINDOW_S = 7 * 86400;
const day = (t: number) => Math.floor(t / 86400);

export class SignWatch {
  #misses = new Map<string, Map<string, number>>();      // host → request id → when its lifetime ended
  #helped = new Map<string, Set<number>>();              // host → days with a valid partial since the last miss
  #hidden = new Map<string, number>();
  #of<T>(m: Map<string, T>, host: string, make: () => T) { let x = m.get(host); if (!x) { x = make(); m.set(host, x); } return x; }

  /** A `sign` request to `host` whose lifetime ended at `at` with nothing from it. It counts only if
   *  another server co-signed the same request; an `error` answer is never reported here. */
  unanswered(host: string, id: string, at: number, anotherCosigned: boolean) {
    if (!anotherCosigned) return;
    this.#of(this.#misses, host, () => new Map()).set(id, at);
    this.#helped.set(host, new Set());
  }
  /** A valid partial from `host` for request `id` at `at`, in time or late: a late one takes back that miss. */
  partial(host: string, id: string, at: number) {
    this.#misses.get(host)?.delete(id);
    const days = this.#of(this.#helped, host, () => new Set());
    days.add(day(at));
    // It goes away once the server gives a valid partial on two days.
    if (days.size >= 2) this.#misses.delete(host);
  }
  dump() { return { misses: [...this.#misses].map(([h, m]) => [h, [...m]]), helped: [...this.#helped].map(([h, d]) => [h, [...d]]), hidden: [...this.#hidden] }; }
  load(x: any) { this.#misses = new Map(x.misses.map(([h, m]: any) => [h, new Map(m)])); this.#helped = new Map(x.helped.map(([h, d]: any) => [h, new Set(d)])); this.#hidden = new Map(x.hidden); }
  /** The person hides the line for a week. */
  hide(host: string, now: number) { this.#hidden.set(host, now + HELP_WINDOW_S); }
  /** Whether Backup shows the line for `host` now. */
  line(host: string, now: number): boolean {
    if ((this.#hidden.get(host) ?? 0) > now) return false;
    const recent = [...(this.#misses.get(host)?.values() ?? [])].filter((t) => now - t <= HELP_WINDOW_S);
    return recent.length >= 3 && new Set(recent.map(day)).size >= 2;
  }
}
