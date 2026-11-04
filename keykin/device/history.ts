// Device policy §1: what the device keeps to judge an event. Its own history (only events with `pubkey == g`
// whose signature verifies; the newest of each replaceable and addressable event, the last 25 versions of each
// judged list and the profile, each grant's pre-site version pinned), kept on the device only; and the policy
// records every device syncs in its metadata snapshots (device/metadata.ts): which grant got each event signed,
// the deletions each grant made (for the daily budget and the burst), what each grant removed from and added to
// each list (the removal logs), the pre-site and last-approved version of each list per grant.
//
// Not yet: retention by whether an event is current (records live as long as their month, 13 months); a grant's
// pre-site version kept 90 days after its end (it lives as long as the history does).

import { verifyEvent, type NostrEvent } from '../src/event.ts';
import { isReplaceable } from '../src/destructive.ts';

/** A replaceable or addressable event's address: kind, and `d` for addressable kinds. */
export const addrOf = (e: { kind: number; tags: string[][] }): string | null => {
  const k = e.kind;
  if (!Number.isSafeInteger(k)) return null;
  if (k === 0 || k === 3 || (k >= 10000 && k < 20000)) return `${k}`;
  if (k >= 30000 && k < 40000) return `${k}:${e.tags.find((t) => t[0] === 'd')?.[1] ?? ''}`;
  return null;
};
/** An `a` tag's value (`kind:pubkey:d`) as an address of the account's, or null if it names another key. */
export function addrOfA(a: string, g: string): string | null {
  const i = a.indexOf(':'), j = a.indexOf(':', i + 1);
  if (i < 0 || j < 0) return null;
  const k = Number(a.slice(0, i));
  if (!Number.isSafeInteger(k) || String(k) !== a.slice(0, i) || a.slice(i + 1, j).toLowerCase() !== g) return null;
  return k >= 30000 && k < 40000 ? `${k}:${a.slice(j + 1)}` : `${k}`;
}

/** Device policy §2's kind table. */
export const PROFILE = 0;
export const RELAY_LISTS = new Set([10002, 10050]);
export const FOLLOW_MUTE = new Set([3, 10000]);
export const OTHER_LISTS = new Set([10001, 10003, 10004, 10005, 10006, 10007, 10009, 10012, 10013, 10015, 10020, 10030, 10063, 10101, 10102,
  30000, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30015, 30030, 39089]);
export const WALLET = new Set([17375, 37375, 7375, 7376, 7374, 10019]);
/** The judged kinds: profile, lists, sets and wallets. */
export const judged = (k: number) => k === PROFILE || RELAY_LISTS.has(k) || FOLLOW_MUTE.has(k) || OTHER_LISTS.has(k) || WALLET.has(k);
export const isList = (k: number) => RELAY_LISTS.has(k) || FOLLOW_MUTE.has(k) || OTHER_LISTS.has(k);

const VERSIONS = 25, OTHER_VERSIONS = 2, MAX_ADDRS = 1000, MAX_EVENTS = 3000;

/** The device's own history of the account's events. */
export class History {
  readonly g: () => string;
  /** Versions per address, oldest first: the last 25 of a judged kind, the last 2 of any other. */
  versions = new Map<string, NostrEvent[]>();
  /** Regular events by id (for deletion targets and "Post again"), at most 3,000, the oldest dropped first. */
  events = new Map<string, NostrEvent>();
  /** Pinned versions (a grant's pre-site version): never pushed out by later ones. */
  pinned = new Map<string, NostrEvent>();
  /** The newest deletion naming each event id or address: Undo dates itself after it (§3). */
  deletedAt = new Map<string, number>();
  constructor(g: () => string) { this.g = g; }

  /** Take an event signed for the account, from this device or a relay: only if it is the account's and verifies
   *  (live finding #8). Returns whether it was taken. */
  take(e: NostrEvent, checked = false): boolean {
    if (!e || e.pubkey !== this.g() || (!checked && !verifyEvent(e))) return false;
    if (e.kind === 5) for (const t of e.tags) if ((t[0] === 'e' || t[0] === 'a') && typeof t[1] === 'string') {
      const key = t[0] === 'e' ? t[1].toLowerCase() : addrOfA(t[1], this.g()); if (key) this.deletedAt.set(key, Math.max(this.deletedAt.get(key) ?? 0, e.created_at));
    }
    const a = isReplaceable(e.kind) ? addrOf(e) : null;
    if (!a) {
      if (this.events.has(e.id)) return true;
      this.events.set(e.id, e);
      while (this.events.size > MAX_EVENTS) this.events.delete(this.events.keys().next().value!);
      return true;
    }
    const vs = this.versions.get(a) ?? [];
    if (vs.some((v) => v.id === e.id)) return true;
    vs.push(e); vs.sort((x, y) => x.created_at - y.created_at || (x.id < y.id ? -1 : 1));
    const keep = judged(e.kind) ? VERSIONS : OTHER_VERSIONS;
    while (vs.length > keep) vs.shift();
    this.versions.delete(a); this.versions.set(a, vs);
    while (this.versions.size > MAX_ADDRS) this.versions.delete(this.versions.keys().next().value!);
    return true;
  }
  /** The newest version the device knows at an address (relays break ties on the lowest id). */
  current(addr: string): NostrEvent | null {
    const vs = this.versions.get(addr) ?? [];
    const pins = [...this.pinned.values()].filter((p) => addrOf(p) === addr);
    let best: NostrEvent | null = null;
    for (const v of [...vs, ...pins]) if (!best || v.created_at > best.created_at || (v.created_at === best.created_at && v.id < best.id)) best = v;
    return best;
  }
  /** Every version known at an address, kept or pinned. */
  all(addr: string): NostrEvent[] {
    const m = new Map<string, NostrEvent>();
    for (const v of this.versions.get(addr) ?? []) m.set(v.id, v);
    for (const p of this.pinned.values()) if (addrOf(p) === addr) m.set(p.id, p);
    return [...m.values()].sort((x, y) => x.created_at - y.created_at);
  }
  /** The newest version at an address dated at or before `t`, or else the oldest known. */
  at(addr: string, t: number): NostrEvent | null {
    const vs = this.all(addr); if (!vs.length) return null;
    return [...vs].reverse().find((v) => v.created_at <= t) ?? vs[0];
  }
  get(id: string): NostrEvent | null {
    const lc = id.toLowerCase();
    return this.events.get(lc) ?? this.pinned.get(lc) ?? [...this.versions.values()].flat().find((v) => v.id === lc) ?? null;
  }
  pin(e: NostrEvent) { this.pinned.set(e.id, e); }
  dump() { return { versions: [...this.versions], events: [...this.events.values()], pinned: [...this.pinned.values()], deletedAt: [...this.deletedAt] }; }
  load(x: any) {
    if (!x) return;
    this.versions = new Map(x.versions ?? []); this.events = new Map((x.events ?? []).map((e: NostrEvent) => [e.id, e]));
    this.pinned = new Map((x.pinned ?? []).map((e: NostrEvent) => [e.id, e])); this.deletedAt = new Map(x.deletedAt ?? []);
  }
  clear() { this.versions.clear(); this.events.clear(); this.pinned.clear(); this.deletedAt.clear(); }
}

/** A deletion a grant (or the member app) got signed: when, how many targets as the core counts them, and flags. */
export interface Del { at: number; owner: string; n: number; single: boolean; wallet: boolean; approved: boolean }
const lk2 = (owner: string, list: string) => `${owner}\u0000${list}`;
const PER_OWNER = 2000, DEL_KEEP_S = 2 * 86400;

/** Device policy §1's records, synced in the metadata snapshots alongside Doors §1's evidence. */
export class Ledger {
  /** Which grant `${by}:${id}`, or `member`, each event was signed for. */
  signed = new Map<string, string>();
  dels: Del[] = [];
  /** The removal logs, and what each grant added (for "Undo everything *site* did"): owner‖list → item → when. */
  removed = new Map<string, Map<string, number>>();
  added = new Map<string, Map<string, number>>();
  /** Per owner‖list: the version just before the grant's first change, and the last version the person approved. */
  presite = new Map<string, string>();
  approved = new Map<string, [string, number]>();

  sign(id: string, owner: string) { if (!this.signed.has(id) && this.#count(owner) < PER_OWNER) this.signed.set(id, owner); }
  del(d: Del) { this.dels.push(d); }
  log(which: 'removed' | 'added', owner: string, list: string, items: Iterable<string>, at: number) {
    const m = this[which], k = lk2(owner, list), s = m.get(k) ?? new Map<string, number>();
    for (const it of items) if (s.size < PER_OWNER) s.set(it, at);
    if (s.size) m.set(k, s);
  }
  removals(owner: string, list: string) { return this.removed.get(lk2(owner, list)) ?? new Map<string, number>(); }
  additions(owner: string, list: string) { return this.added.get(lk2(owner, list)) ?? new Map<string, number>(); }
  presiteOf(owner: string, list: string) { return this.presite.get(lk2(owner, list)) ?? null; }
  setPresite(owner: string, list: string, id: string) { const k = lk2(owner, list); if (!this.presite.has(k)) this.presite.set(k, id); }
  approvedOf(owner: string, list: string) { return this.approved.get(lk2(owner, list)) ?? null; }
  approve(owner: string, list: string, id: string, at: number) { const k = lk2(owner, list), p = this.approved.get(k); if (!p || p[1] <= at) this.approved.set(k, [id, at]); }
  /** The lists a grant changed (for "Undo everything *site* did"). */
  listsOf(owner: string): string[] {
    const out = new Set<string>();
    for (const m of [this.removed, this.added]) for (const k of m.keys()) { const i = k.indexOf('\u0000'); if (k.slice(0, i) === owner) out.add(k.slice(i + 1)); }
    return [...out];
  }
  /** Deletion targets in the last 10 minutes, without an approval, from every owner (the core's burst). */
  burst(now: number) { return this.dels.filter((d) => !d.approved && now - d.at < 600).reduce((a, d) => a + d.n, 0); }
  #count(owner: string) { let n = 0; for (const o of this.signed.values()) if (o === owner) n++; return n; }
  prune(now: number) { this.dels = this.dels.filter((d) => now - d.at < DEL_KEEP_S); }
  size() { return this.signed.size + this.dels.length + [...this.removed.values(), ...this.added.values()].reduce((a, m) => a + m.size, 0) + this.presite.size + this.approved.size; }
  /** The oldest records first, when a month must fit its parts. */
  trim(n: number) {
    for (const k of [...this.signed.keys()].slice(0, n)) this.signed.delete(k);
    this.dels = this.dels.slice(Math.min(n, this.dels.length));
    for (const m of [this.removed, this.added]) for (const [k, s] of m) { for (const it of [...s.keys()].slice(0, n)) s.delete(it); if (!s.size) m.delete(k); }
  }
  /** As published: arrays of plain values, in a fixed order. */
  data() {
    const split = (k: string) => { const i = k.indexOf('\u0000'); return [k.slice(0, i), k.slice(i + 1)]; };
    return {
      signed: [...this.signed],
      dels: this.dels.map((d) => [d.at, d.owner, d.n, (d.single ? 1 : 0) | (d.wallet ? 2 : 0) | (d.approved ? 4 : 0)]),
      removed: [...this.removed].flatMap(([k, s]) => [...s].map(([it, at]) => [...split(k), it, at])),
      added: [...this.added].flatMap(([k, s]) => [...s].map(([it, at]) => [...split(k), it, at])),
      presite: [...this.presite].map(([k, id]) => [...split(k), id]),
      approved: [...this.approved].map(([k, [id, at]]) => [...split(k), id, at]),
    };
  }
  /** Merge published records in; `mine(owner)` says which owners the maker may write (review 17 L5), and a malformed
   *  entry costs only itself. */
  take(x: any, mine: (o: unknown) => boolean) {
    const arr = (v: unknown) => (Array.isArray(v) ? v : []);
    const str = (v: unknown) => typeof v === 'string' && v.length <= 1024;
    const int = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0;
    const HEX = /^[0-9a-f]{64}$/;
    for (const r of arr(x?.signed)) if (Array.isArray(r) && HEX.test(String(r[0])) && mine(r[1])) this.signed.set(r[0], r[1]);
    for (const r of arr(x?.dels)) if (Array.isArray(r) && int(r[0]) && mine(r[1]) && int(r[2]) && int(r[3]))
      this.dels.push({ at: r[0], owner: r[1], n: r[2], single: !!(r[3] & 1), wallet: !!(r[3] & 2), approved: !!(r[3] & 4) });
    for (const w of ['removed', 'added'] as const) for (const r of arr(x?.[w])) if (Array.isArray(r) && mine(r[0]) && str(r[1]) && str(r[2]) && int(r[3])) {
      const k = lk2(r[0], r[1]), s = this[w].get(k) ?? new Map<string, number>(); s.set(r[2], Math.max(s.get(r[2]) ?? 0, r[3])); this[w].set(k, s);
    }
    for (const r of arr(x?.presite)) if (Array.isArray(r) && mine(r[0]) && str(r[1]) && HEX.test(String(r[2]))) { const k = lk2(r[0], r[1]); if (!this.presite.has(k)) this.presite.set(k, r[2]); }
    for (const r of arr(x?.approved)) if (Array.isArray(r) && mine(r[0]) && str(r[1]) && HEX.test(String(r[2])) && int(r[3])) this.approve(r[0], r[1], r[2], r[3]);
  }
  clear() { this.signed.clear(); this.dels = []; this.removed.clear(); this.added.clear(); this.presite.clear(); this.approved.clear(); }
}
