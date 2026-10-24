// Relays, and sealed member-to-member messages.
//
// Everything travels over public Nostr relays. No member opens a port to any
// other, so a server behind NAT, a phone on mobile data and a laptop all reach
// each other the same way. Member traffic is an ephemeral event (relays don't
// store it) whose content is NIP-44 encrypted to the recipient and whose
// signature says who sent it.

import { Relay } from 'nostr-tools/relay';
import { finalizeEvent, verifyEvent, getPublicKey, type Event } from 'nostr-tools/pure';
import type { Filter } from 'nostr-tools/filter';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

export const KIND_MEMBER = 28001;
export const KIND_NIP46 = 24133;

const now = () => Math.floor(Date.now() / 1000);
/** One spelling per relay, so a site's "wss://x/" and our "wss://x" share a connection. */
export const normRelay = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase();

// Where to actually connect for a relay, when that differs from its public address: a
// server running beside its relay (COSIGN_RELAY_MAP="wss://syb.lol=ws://relay:13131")
// reaches it inside the compose network, but tells phones and sites the public one.
const relayMap = new Map((process.env.COSIGN_RELAY_MAP ?? '').split(',').filter(x => x.includes('='))
  .map(x => x.split('=', 2).map(normRelay) as [string, string]));
export const dial = (url: string) => relayMap.get(normRelay(url)) ?? url;

export class Pool {
  private conns = new Map<string, Relay | null>();
  private seen = new Set<string>();
  private filters: Filter[] = [];
  urls: string[];
  private onEvent: (e: Event, relay: string) => void;
  private log: (t: string) => void;
  constructor(urls: string[], onEvent: (e: Event, relay: string) => void, log: (t: string) => void = () => {}) {
    this.urls = [...urls]; this.onEvent = onEvent; this.log = log;
  }

  start(filters: Filter[]) {
    this.filters = filters;
    for (const url of this.urls) this.connect(url);
  }

  /** Listen on more relays too (a site's own). Resolves once they're up, or after `ms`. */
  async add(urls: string[], ms = 6000) {
    const want = [...new Set(urls.map(normRelay))];
    for (const u of want) if (!this.conns.has(u)) { this.urls.push(u); this.connect(u); }
    const until = Date.now() + ms;
    while (want.some(u => !this.conns.get(u)) && Date.now() < until) await new Promise(r => setTimeout(r, 200));
  }

  private async connect(url: string) {
    this.conns.set(url, null);
    try {
      const r = await Relay.connect(dial(url));
      r.onclose = () => { this.conns.set(url, null); setTimeout(() => this.connect(url), 5000); };
      this.conns.set(url, r);
      // Ask only for what was sent in the last minute: member traffic is live.
      const filters = this.filters.map(f => ({ ...f, since: now() - 60 }));
      r.subscribe(filters, {
        onevent: (e: Event) => {
          if (this.seen.has(e.id)) return;
          this.seen.add(e.id);
          if (this.seen.size > 5000) this.seen = new Set([...this.seen].slice(-2500));
          if (!verifyEvent(e)) return;
          this.onEvent(e, url);
        },
      });
      this.log(`relay up: ${url}`);
    } catch {
      setTimeout(() => this.connect(url), 5000);
    }
  }

  publish(e: Event) {
    for (const [url, r] of this.conns) {
      if (!r) continue;
      r.publish(e).catch(err => this.log(`publish to ${url} failed: ${err?.message ?? err}`));
    }
  }

  status() {
    return [...this.conns].map(([url, r]) => ({ url, up: !!r && r.connected }));
  }
}

/** Seal a JSON message to another member. */
export function sealTo(sk: string, toPk: string, msg: unknown, kind = KIND_MEMBER): Event {
  const ck = nip44.v2.utils.getConversationKey(hexToBytes(sk), toPk);
  return finalizeEvent(
    { kind, created_at: now(), tags: [['p', toPk]], content: nip44.v2.encrypt(JSON.stringify(msg), ck) },
    hexToBytes(sk),
  );
}

// NIP-44 takes at most 64 KB, and a follow list of a thousand people is more. A message
// that big goes in parts small enough for any relay, and is put back together on arrival.
const PART = 24_000;

/** Seal a member message, in as many events as it takes. */
export function sealParts(sk: string, toPk: string, msg: unknown): Event[] {
  const text = JSON.stringify(msg);
  if (text.length <= PART) return [sealTo(sk, toPk, msg)];
  const id = bytesToHex(randomBytes(8)), n = Math.ceil(text.length / PART);
  return Array.from({ length: n }, (_, i) => sealTo(sk, toPk, { type: 'part', id, i, n, data: text.slice(i * PART, (i + 1) * PART) }));
}

/** Collects parts; gives back the whole message once the last one is in. */
export class Parts {
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

/** Open a sealed message. Returns null when it isn't for us or doesn't decrypt. */
export function openFrom(sk: string, e: Event): any | null {
  try {
    const ck = nip44.v2.utils.getConversationKey(hexToBytes(sk), e.pubkey);
    return JSON.parse(nip44.v2.decrypt(e.content, ck));
  } catch {
    return null;
  }
}

export const pubOf = (sk: string) => getPublicKey(hexToBytes(sk));
