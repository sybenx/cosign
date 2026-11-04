// Server profile §3's abuse defaults, as pure counters. One rule above all: no limit may refuse a request
// the core requires a server to answer, so the never-counted types are never counted, and requests from
// keys that aren't members yet are limited only per HTTPS source IP (never per account: `g` is public,
// and anyone could empty a victim's bucket). Over relays, where the IP is the relay's, the answer to a
// flood is NIP-13 proof of work (`powBits`), not refusal.

export const LIMITS = {
  creationsPerIpPerDay: 10,
  creationsPerHour: 1000,
  memberPerKeyPerMinute: 120,
  junkPerIpPerMinute: 30,
  newcomerPerIpPerMinute: 60,
  pushesPerAddressPerHour: 60,
};

/** Never counted (Server profile §3). `challenge` and `release_request` count as never only from the
 *  current backup key; the caller says whether the sender is it. */
const NEVER = new Set(['cancel', 'withdraw', 'change', 'changes_get', 'upload', 'upload_held', 'inbox_get', 'inbox_ack', 'forward_get', 'seated?']);
const NEVER_FROM_BACKUP = new Set(['challenge', 'release_request']);

class Window {
  #hits = new Map<string, number[]>();
  readonly span: number; readonly max: number;
  constructor(span: number, max: number) { this.span = span; this.max = max; }
  take(key: string, now: number): boolean {
    const h = (this.#hits.get(key) ?? []).filter((t) => now - t < this.span);
    if (h.length >= this.max) { this.#hits.set(key, h); return false; }
    h.push(now); this.#hits.set(key, h);
    if (this.#hits.size > 100_000) for (const [k, v] of this.#hits) if (!v.some((t) => now - t < this.span)) this.#hits.delete(k);
    return true;
  }
}

export class Limits {
  readonly o: typeof LIMITS;
  #creIp: Window; #creAll: Window; #member: Window; #junk: Window; #newcomer: Window; #push: Window;
  constructor(o: Partial<typeof LIMITS> = {}) {
    this.o = { ...LIMITS, ...o };
    this.#creIp = new Window(86400, this.o.creationsPerIpPerDay); this.#creAll = new Window(3600, this.o.creationsPerHour);
    this.#member = new Window(60, this.o.memberPerKeyPerMinute); this.#junk = new Window(60, this.o.junkPerIpPerMinute);
    this.#newcomer = new Window(60, this.o.newcomerPerIpPerMinute); this.#push = new Window(3600, this.o.pushesPerAddressPerHour);
  }
  /** An account creation (only `create`; a seat is never one). The IP, when it came over HTTPS. */
  creation(now: number, ip?: string) { return (ip === undefined || this.#creIp.take(ip, now)) && this.#creAll.take('all', now); }
  /** A request from a verified member, the backup key or a peer server, counted per sender key. */
  member(from: string, type: string, now: number, fromBackup = false) {
    if (NEVER.has(type) || (fromBackup && NEVER_FROM_BACKUP.has(type))) return true;
    return this.#member.take(from, now);
  }
  /** A request from a key that isn't a member yet: per HTTPS source IP only. */
  newcomer(now: number, ip?: string) { return ip === undefined || this.#newcomer.take(ip, now); }
  /** Unverifiable junk (undecryptable, unknown account, malformed), per HTTPS source IP. */
  junk(ip: string, now: number) { return this.#junk.take(ip, now); }
  /** A push to one address; wait notices are always sent. */
  push(url: string, now: number, wait: boolean) { return wait || this.#push.take(url, now); }
}

/** NIP-13: the number of leading zero bits of an event id. */
export function powBits(idHex: string): number {
  let n = 0;
  for (const ch of idHex) { const v = parseInt(ch, 16); if (v === 0) { n += 4; continue; } return n + Math.clz32(v) - 28; }
  return n;
}
