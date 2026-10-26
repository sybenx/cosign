// Sealed member-to-member messages over relays, the same shape the servers speak
// (server/net.ts): an ephemeral kind 28001 event, NIP-44 encrypted to the member it is for,
// split into 24 KB parts when a message is bigger than one (NIP-44 stops at 64 KB).
//
// Nothing here knows what a message means. A member's mailbox key seals and opens; the
// device library above decides what to do with what comes out.

import { Relay } from 'nostr-tools/relay';
import { finalizeEvent, getPublicKey, verifyEvent, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

export const KIND_MEMBER = 28001;
const PART = 24_000;
const now = () => Math.floor(Date.now() / 1000);

export const pubOf = (sk: string) => getPublicKey(hexToBytes(sk));

function sealTo(sk: string, toPk: string, msg: unknown): Event {
  const ck = nip44.v2.utils.getConversationKey(hexToBytes(sk), toPk);
  return finalizeEvent({ kind: KIND_MEMBER, created_at: now(), tags: [['p', toPk]], content: nip44.v2.encrypt(JSON.stringify(msg), ck) }, hexToBytes(sk));
}

export function sealParts(sk: string, toPk: string, msg: unknown): Event[] {
  const text = JSON.stringify(msg);
  if (text.length <= PART) return [sealTo(sk, toPk, msg)];
  const id = bytesToHex(randomBytes(8)), n = Math.ceil(text.length / PART);
  return Array.from({ length: n }, (_, i) => sealTo(sk, toPk, { type: 'part', id, i, n, data: text.slice(i * PART, (i + 1) * PART) }));
}

function openFrom(sk: string, e: Event): any | null {
  try { return JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(hexToBytes(sk), e.pubkey))); } catch { return null; }
}

class Parts {
  private open = new Map<string, { at: number; got: string[]; left: number }>();
  take(fromPk: string, m: any): any | null {
    if (m?.type !== 'part') return m;
    const k = `${fromPk}:${m.id}`;
    for (const [key, v] of this.open) if (Date.now() - v.at > 120_000) this.open.delete(key);
    const p = this.open.get(k) ?? { at: Date.now(), got: new Array(m.n), left: m.n };
    if (p.got[m.i] === undefined) { p.got[m.i] = String(m.data); p.left--; }
    this.open.set(k, p);
    if (p.left > 0) return null;
    this.open.delete(k);
    try { return JSON.parse(p.got.join('')); } catch { return null; }
  }
}

/** This device's mailbox: listens for messages sealed to it, sends sealed ones. */
export class Mailbox {
  private conns = new Map<string, Relay | null>();
  private seen = new Set<string>();
  private parts = new Parts();
  private closed = false;
  /** Sent before any relay was up: they go out as soon as one is. */
  private queue: Event[] = [];
  readonly pk: string;

  constructor(private sk: string, readonly relays: string[], private onMessage: (msg: any, fromPk: string, sentAt: number) => void) {
    this.pk = pubOf(sk);
    for (const url of relays) void this.connect(url);
  }

  private async connect(url: string) {
    if (this.closed) return;
    this.conns.set(url, null);
    try {
      const r = await Relay.connect(url);
      r.onclose = () => { this.conns.set(url, null); if (!this.closed) setTimeout(() => this.connect(url), 3000); };
      this.conns.set(url, r);
      // Member traffic is live: only what was sent in the last minute.
      r.subscribe([{ kinds: [KIND_MEMBER], '#p': [this.pk], since: now() - 60 }], { onevent: e => this.receive(e) });
      for (const e of this.queue) r.publish(e).catch(() => {});
      this.queue = [];
    } catch {
      if (!this.closed) setTimeout(() => this.connect(url), 3000);
    }
  }

  private receive(e: Event) {
    if (this.seen.has(e.id) || !verifyEvent(e)) return;
    this.seen.add(e.id);
    const msg = this.parts.take(e.pubkey, openFrom(this.sk, e));
    if (msg) this.onMessage(msg, e.pubkey, e.created_at);
  }

  get connected() { return [...this.conns.values()].some(r => r?.connected); }

  /** Resolves once a relay is up, or after `ms`. */
  async ready(ms = 4000) {
    const until = Date.now() + ms;
    while (!this.connected && Date.now() < until) await new Promise(r => setTimeout(r, 100));
  }

  send(toPk: string, msg: object) {
    const up = [...this.conns.values()].filter(r => r?.connected) as Relay[];
    for (const e of sealParts(this.sk, toPk, msg)) {
      if (!up.length) { this.queue.push(e); continue; }
      // A relay that has stopped answering never settles its publish, so each one is given
      // a few seconds and then let go: nothing here waits on a relay to say it took a message.
      for (const r of up) void Promise.race([r.publish(e), new Promise(done => setTimeout(done, 5000))]).catch(() => {});
    }
  }

  close() { this.closed = true; for (const r of this.conns.values()) r?.close(); }
}
