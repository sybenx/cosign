// Push payloads and the server inbox (core §8.1–§8.2). Pure.

import { sha, jcsBytes, refuse, utf8ToBytes } from './bytes.ts';
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
  const p = JSON.parse(new TextDecoder().decode(bytes));
  if (!hostKeys.has(p.srv)) refuse('unknown_server');
  const { sig, ...rest } = p;
  if (!schnorrVerify(sig, sha(jcsBytes(rest)), p.srv)) refuse('bad_signature');
  return p;
}

export interface Addresses { sign?: string; ask?: string; notice?: string }
export interface InboxItem { iid: string; at: number; to: string; from: string; wrap: NostrEvent; kind: 'delivery' | 'wait' | 'notice' | 'message'; cls: Cls; bytes: number }

export const INBOX_ITEMS = 512, INBOX_BYTES = 4 * 1024 * 1024, PER_PAIR = 32;

/** One account's inbox at one server. Deliveries stay until acknowledged (§7.1); wait notices until
 *  their wait ends; ordinary notices and messages expire with their class and are dropped first. */
export class Inbox {
  items: InboxItem[] = [];
  #n = 0;
  deliver(o: { from: string; to: string; wrap: NostrEvent; kind: InboxItem['kind']; cls: Cls; at: number; isMember: (k: string) => boolean; isRemoved: (k: string) => boolean; isBackup: (k: string) => boolean }): string {
    if (o.isRemoved(o.from)) refuse('removed', 'deliver from a removed member');
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
}

/** Push addresses per wake class (§8.1); the newest set by the rumor's `created_at` replaces the old. */
export class PushRegistry {
  #by = new Map<string, { at: number; addrs: Addresses }>();
  register(member: string, at: number, addrs: Addresses) {
    const cur = this.#by.get(member);
    if (cur && cur.at > at) return false;
    this.#by.set(member, { at, addrs }); return true;
  }
  unregister(member: string) { this.#by.delete(member); }
  get(member: string) { return this.#by.get(member)?.addrs ?? null; }
  /** Drop an address that answered 404/410. */
  dead(member: string, url: string) {
    const a = this.#by.get(member); if (!a) return;
    for (const k of Object.keys(a.addrs) as (keyof Addresses)[]) if (a.addrs[k] === url) delete a.addrs[k];
  }
}
