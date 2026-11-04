// Push payloads and the server inbox (core §8.1–§8.2). Pure.

import { sha, jcsBytes, refuse, utf8ToBytes, utf8Strict, strictJson, fromB64u } from './bytes.ts';
import { p256 } from '@noble/curves/nist.js';
import { schnorrSign, schnorrVerify, tag, type KeyPair, type NostrEvent } from './event.ts';
import { LIFETIME_S, type Cls } from './lifetimes.ts';

export const PUSH_BODY = 2400;                     // reference encrypted length (≤ 2,560)
export const PUSH_OVERHEAD = 86 + 17;              // RFC 8291 aes128gcm header + delimiter and tag
export const PUSH_PLAIN = PUSH_BODY - PUSH_OVERHEAD;

/** A signed push payload, padded to one fixed plaintext length (so every encrypted body is the same size). */
export function pushPayload(host: KeyPair, cls: Cls | 'notice', id: string, wrap?: unknown): Uint8Array {
  const base: any = { v: 1, cls, id, srv: host.pub };
  if (wrap !== undefined) base.wrap = wrap;
  base.sig = schnorrSign(sha(jcsBytes(base)), host.sk);
  let text = JSON.stringify(base);
  if (utf8ToBytes(text).length > PUSH_PLAIN && wrap !== undefined) return pushPayload(host, cls, id);  // wrap only if it fits
  if (utf8ToBytes(text).length > PUSH_PLAIN) refuse('too_large');
  const out = new Uint8Array(PUSH_PLAIN).fill(0x20);  // JSON allows trailing whitespace: pad with spaces
  out.set(utf8ToBytes(text));
  return out;
}
export function readPush(bytes: Uint8Array, hostKeys: Set<string>): any {
  const p = strictJson(utf8Strict(bytes));
  if (!hostKeys.has(p.srv)) refuse('unknown_server');
  const { sig, ...rest } = p;
  if (!schnorrVerify(sig, sha(jcsBytes(rest)), p.srv)) refuse('bad_signature');
  return p;
}

export interface InboxItem { iid: string; at: number; to: string; from: string; wrap: NostrEvent; kind: 'delivery' | 'wait' | 'notice' | 'message'; cls: Cls; bytes: number }

export const INBOX_ITEMS = 512, INBOX_BYTES = 4 * 1024 * 1024, PER_PAIR = 32;

/** One account's inbox at one server. Deliveries stay until acknowledged (§7.1); wait notices until
 *  their wait ends; ordinary notices and messages expire with their class and are dropped first. */
export class Inbox {
  items: InboxItem[] = [];
  #n = 0;
  deliver(o: { from: string; to: string; wrap: NostrEvent; kind: InboxItem['kind']; cls: Cls; at: number; isMember: (k: string) => boolean; isRemoved: (k: string) => boolean; isBackup: (k: string) => boolean }): string {
    if (o.isRemoved(o.from)) refuse('removed', 'deliver from a removed member');
    if (!o.isMember(o.from)) refuse('not_member', 'deliver only from a current member');
    if (!o.isMember(o.to)) refuse('not_member', '`to` must be a current member');
    if (o.isBackup(o.to)) refuse('backup_never_fetches');
    if (tag(o.wrap, 'p') !== o.to) refuse('bad_p', 'the wrap\'s p tag must be `to`');
    const waiting = this.items.filter((x) => x.from === o.from && x.to === o.to).length;
    if (waiting >= PER_PAIR) refuse('inbox_full');
    const bytes = JSON.stringify(o.wrap).length;
    const iid = (++this.#n).toString(16).padStart(8, '0') + Math.random().toString(16).slice(2, 10);
    this.items.push({ iid, at: o.at, to: o.to, from: o.from, wrap: o.wrap, kind: o.kind, cls: o.cls, bytes });
    this.cap(o.at);
    if (!this.items.some((x) => x.iid === iid)) refuse('inbox_full');
    return iid;
  }
  /** Expire, then drop ordinary notices and messages oldest first until under the caps. */
  cap(at: number) {
    this.items = this.items.filter((x) => x.kind === 'delivery' || x.kind === 'wait' || at - x.at <= LIFETIME_S[x.cls]);
    const over = () => this.items.length > INBOX_ITEMS || this.items.reduce((a, x) => a + x.bytes, 0) > INBOX_BYTES;
    while (over()) {
      const k = this.items.findIndex((x) => x.kind === 'notice' || x.kind === 'message');
      if (k < 0) break;
      this.items.splice(k, 1);
    }
  }
  get(to: string, at: number) { this.cap(at); return this.items.filter((x) => x.to === to).map((x) => ({ iid: x.iid, age: at - x.at, wrap: x.wrap })); }
  ack(to: string, iids: string[]) { this.items = this.items.filter((x) => !(x.to === to && iids.includes(x.iid))); }
  /** A removed member: drop its deliveries, keeping only its removal notice (kept 7 days). */
  dropFor(key: string, removalNotice?: InboxItem['iid']) { this.items = this.items.filter((x) => x.to !== key || x.iid === removalNotice); }
  endWait(iid: string) { this.items = this.items.filter((x) => x.iid !== iid); }
  dump() { return { items: this.items, n: this.#n }; }
  load(x: { items: InboxItem[]; n: number }) { this.items = [...x.items]; this.#n = x.n; }
}

/** One push address (§8.1): its wake class, the gateway URL and the browser-style keys RFC 8291 encrypts to. */
export interface PushAddress { cls: 'sign' | 'ask' | 'notice'; url: string; p256dh: string; auth: string }

/** §8.1's `addresses`, checked: one per wake class, an https URL, a 65-byte P-256 point and a 16-byte auth
 *  secret, both base64url. */
export function parseAddresses(v: unknown): PushAddress[] {
  if (!Array.isArray(v) || v.length > 3) refuse('malformed', 'addresses');
  const seen = new Set<string>();
  return (v as unknown[]).map((a: any) => {
    if (!a || typeof a !== 'object' || !['sign', 'ask', 'notice'].includes(a.cls) || seen.has(a.cls)) refuse('malformed', 'one address per class');
    seen.add(a.cls);
    let url: URL;
    try { url = new URL(a.url); } catch { return refuse('malformed', 'url'); }
    if (url.protocol !== 'https:' || typeof a.url !== 'string') refuse('malformed', 'an https url');
    const k = fromB64u(a.p256dh), auth = fromB64u(a.auth);
    if (k.length !== 65 || k[0] !== 4 || auth.length !== 16) refuse('malformed', 'p256dh and auth');
    // A point on the curve, or every later push to it would fail (review 9 M2).
    try { p256.Point.fromBytes(k).assertValidity(); } catch { refuse('malformed', 'p256dh is not a P-256 point'); }
    return { cls: a.cls, url: a.url, p256dh: a.p256dh, auth: a.auth };
  });
}

/** Push addresses per member (§8.1): the newest set by the rumor's `created_at` replaces the old;
 *  never copied to another server. */
export class PushRegistry {
  #by = new Map<string, { at: number; addrs: PushAddress[] }>();
  register(member: string, at: number, addrs: unknown) {
    const parsed = parseAddresses(addrs);
    const cur = this.#by.get(member);
    if (cur && cur.at > at) return false;
    this.#by.set(member, { at, addrs: parsed }); return true;
  }
  unregister(member: string) { this.#by.delete(member); }
  get(member: string) { return this.#by.get(member)?.addrs ?? null; }
  for(member: string, cls: PushAddress['cls']) { return this.get(member)?.find((a) => a.cls === cls) ?? null; }
  /** Drop an address that answered 404/410. */
  dead(member: string, url: string) { const a = this.#by.get(member); if (a) a.addrs = a.addrs.filter((x) => x.url !== url); }
  dump() { return [...this.#by]; }
  load(x: [string, { at: number; addrs: PushAddress[] }][]) { this.#by = new Map(x); }
}
