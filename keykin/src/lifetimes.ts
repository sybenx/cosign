// Request lifetime classes and replays (core §5.3, §5.6). Pure.

import { sha, jcsBytes, bytesToHex } from './bytes.ts';

export type Cls = 'sign' | 'ask' | 'member';
export const LIFETIME_S: Record<Cls, number> = { sign: 60, ask: 120, member: 7 * 86400 };
export const SKEW_S = 30;

/** Which classes a request type may carry (§5.6). "Approvals" are the pair messages; "deliveries"
 *  `deliver` and the redeal deliveries. Types outside the table: those a sender repeats until answered
 *  are `member`; every other request is `ask` (core 13.12). */
const ALLOWED: Record<string, Cls[]> = {
  sign: ['sign', 'ask'], commit: ['sign', 'ask'], ecdh: ['sign', 'ask'],
  challenge: ['ask'], pair_request: ['ask'], pair_sign: ['ask'],
  hold: ['member'], release_request: ['member'], deliver: ['member'],
};
const MEMBER = ['account_delete', 'deleted', 'helper_stop', 'helper_resume', 'cancel', 'withdraw', 'upload', 'upload_held', 'push_register', 'push_unregister', 'notify_register', 'paper_reissue',
  'delta', 'paper_ck', 'dk_seed', 'release_seed', 'paper_item', 'welcome', 'repair_sigma', 'change', 'ack'];
export const allowedClasses = (type: string): Cls[] => (Object.hasOwn(ALLOWED, type) ? ALLOWED[type] : MEMBER.includes(type) ? ['member'] : ['ask']);

/** Null when fresh; otherwise the refusal code. `sentAt` is the rumor's `created_at`; `inboxAge`
 *  the inbox's `age` (§8.2), whichever makes the request older wins. */
export function checkLifetime(type: string, cls: string, sentAt: number, now: number, inboxAge = 0): string | null {
  if (!Object.hasOwn(LIFETIME_S, cls) || !allowedClasses(type).includes(cls as Cls)) return 'bad_class';
  if (sentAt - now > SKEW_S) return 'dated_ahead';
  const age = Math.max(now - sentAt, inboxAge);
  if (age > LIFETIME_S[cls as Cls] + SKEW_S) return 'expired';
  return null;
}

/** The canonical body hash §5.3 compares: SHA-256 of the RFC 8785 body. */
export const bodyHash = (body: unknown) => bytesToHex(sha(jcsBytes(body)));

/** Answered `(sender, id)` pairs until their lifetime passes (§5.6), with the answer kept for a
 *  byte-identical retry (§5.3). Answers are kept, never nonces. A server persists this. */
export class ReplayCache {
  private seen = new Map<string, { hash: string; answer: unknown; until: number }>();
  private capPerSender: number;
  constructor(capPerSender = 10_000) { this.capPerSender = capPerSender; }
  private prune(now: number) { for (const [k, v] of this.seen) if (v.until < now) this.seen.delete(k); }
  /** `{fresh: true}` for a new request; `{answer}` for an identical retry; throws-free `{reused}` otherwise. */
  check(sender: string, id: string, hash: string, now: number): { fresh: true } | { answer: unknown } | { reused: true } | { full: true } {
    this.prune(now);
    const v = this.seen.get(`${sender}:${id}`);
    if (v) return v.hash === hash && v.answer !== undefined ? { answer: v.answer } : { reused: true };
    let n = 0;
    for (const k of this.seen.keys()) if (k.startsWith(sender + ':')) n++;
    if (n >= this.capPerSender) return { full: true };
    return { fresh: true };
  }
  /** Claim before answering (so a concurrent duplicate is `id_reused`), then record the answer. */
  claim(sender: string, id: string, hash: string, cls: Cls, now: number, sentAt = now) {
    // Kept until the request could no longer be fresh: a request dated ahead stays fresh longer.
    this.seen.set(`${sender}:${id}`, { hash, answer: undefined, until: Math.max(now, sentAt) + LIFETIME_S[cls] + SKEW_S });
  }
  answer(sender: string, id: string, answer: unknown) {
    const v = this.seen.get(`${sender}:${id}`); if (v) v.answer = answer;
  }
  dump() { return [...this.seen.entries()]; }
  load(entries: [string, { hash: string; answer: unknown; until: number }][]) { this.seen = new Map(entries); }
}
