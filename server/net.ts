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
import { hexToBytes } from '@noble/hashes/utils.js';

export const KIND_MEMBER = 28001;
export const KIND_NIP46 = 24133;

const now = () => Math.floor(Date.now() / 1000);
/** One spelling per relay, so a site's "wss://x/" and our "wss://x" share a connection. */
export const normRelay = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase();

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
      const r = await Relay.connect(url);
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
