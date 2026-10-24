// Relays, and sealed member-to-member messages (core/seal.ts).
//
// Everything travels over public Nostr relays. No member opens a port to any
// other, so a server behind NAT, a phone on mobile data and a laptop all reach
// each other the same way. One pool can carry many groups: one subscription per
// relay, its filters naming every key the host listens for.

import { Relay, type Subscription } from 'nostr-tools/relay';
import { verifyEvent, type Event } from 'nostr-tools/pure';
import type { Filter } from 'nostr-tools/filter';
import { normRelay } from './core/seal.ts';
import { pinnedWebSocket, type Pinned } from './egress.ts';
import { AbstractRelay } from 'nostr-tools/abstract-relay';

/** Open a relay: as named, or at the one address the egress check gave (`to`). */
export async function openRelay(url: string, to: 'any' | Pinned): Promise<Relay> {
  if (to === 'any') return Relay.connect(url);
  const r = new AbstractRelay(url, { verifyEvent, websocketImplementation: pinnedWebSocket(to) });
  await r.connect();
  return r as unknown as Relay;
}

// The sealing itself has no I/O, so it lives with the core; everything that used it from here still can.
export { KIND_MEMBER, KIND_NIP46, normRelay, sealTo, sealParts, Parts, openFrom, pubOf } from './core/seal.ts';

const now = () => Math.floor(Date.now() / 1000);

// Where to actually connect for a relay, when that differs from its public address: a
// server running beside its relay (COSIGN_RELAY_MAP="wss://syb.lol=ws://relay:13131")
// reaches it inside the compose network, but tells phones and sites the public one.
const relayMap = new Map((process.env.COSIGN_RELAY_MAP ?? '').split(',').filter(x => x.includes('='))
  .map(x => x.split('=', 2).map(normRelay) as [string, string]));
export const dial = (url: string) => relayMap.get(normRelay(url)) ?? url;

export class Pool {
  private conns = new Map<string, Relay | null>();
  private subs = new Map<string, Subscription>();
  private seen = new Set<string>();
  private filters: Filter[] = [];
  urls: string[];
  private onEvent: (e: Event, relay: string) => void;
  private log: (t: string) => void;
  /** A server's check on where it may connect (egress.ts), asked at every connect; and how many relays at most. */
  /** Where it may connect for a relay: null (not at all), 'any' (as named), or the address it checked (egress.ts). */
  guard?: (url: string) => Promise<null | 'any' | Pinned>;
  max = Infinity;
  constructor(urls: string[], onEvent: (e: Event, relay: string) => void, log: (t: string) => void = () => {}) {
    this.urls = [...urls]; this.onEvent = onEvent; this.log = log;
  }

  start(filters: Filter[]) {
    this.filters = filters;
    for (const url of this.urls) this.connect(url);
  }

  /** Listen for something else from now on (a group the host just took on): every relay asks again. */
  setFilters(filters: Filter[]) {
    this.filters = filters;
    for (const [url, r] of this.conns) if (r) this.subscribe(url, r);
  }

  /** Listen on more relays too (a site's own). Resolves once they're up, or after `ms`. */
  async add(urls: string[], ms = 6000) {
    const want = [...new Set(urls.map(normRelay))];
    for (const u of want) if (!this.conns.has(u)) {
      if (this.conns.size >= this.max) { this.log(`not adding ${u}: already at ${this.max} relays`); continue; }
      this.urls.push(u); this.connect(u);
    }
    const until = Date.now() + ms;
    while (want.some(u => !this.conns.get(u)) && Date.now() < until) await new Promise(r => setTimeout(r, 200));
  }

  private async connect(url: string) {
    this.conns.set(url, null);
    // Not somewhere this server may go (now: what a name points to can change).
    const to = this.guard ? await this.guard(url).catch(() => null) : 'any';
    if (!to) { this.log(`refused relay ${url}`); setTimeout(() => this.connect(url), 600_000); return; }
    try {
      const r = await openRelay(dial(url), to);
      r.onclose = () => { this.conns.set(url, null); setTimeout(() => this.connect(url), 5000); };
      this.conns.set(url, r);
      this.subscribe(url, r);
      this.log(`relay up: ${url}`);
    } catch {
      setTimeout(() => this.connect(url), 5000);
    }
  }

  private subscribe(url: string, r: Relay) {
    this.subs.get(url)?.close();
    // Ask only for what was sent in the last minute: member traffic is live.
    const filters = this.filters.map(f => ({ ...f, since: now() - 60 }));
    this.subs.set(url, r.subscribe(filters, {
      onevent: (e: Event) => {
        if (this.seen.has(e.id)) return;
        this.seen.add(e.id);
        if (this.seen.size > 5000) this.seen = new Set([...this.seen].slice(-2500));
        if (!verifyEvent(e)) return;
        this.onEvent(e, url);
      },
    }));
  }

  /** To every relay that's up, or only to those of `only` (one group's). */
  publish(e: Event, only?: string[]) {
    const to = only && new Set(only.map(normRelay));
    for (const [url, r] of this.conns) {
      if (!r || (to && !to.has(normRelay(url)))) continue;
      r.publish(e).catch(err => this.log(`publish to ${url} failed: ${err?.message ?? err}`));
    }
  }

  status(only?: string[]) {
    const of = only && new Set(only.map(normRelay));
    return [...this.conns].filter(([url]) => !of || of.has(normRelay(url))).map(([url, r]) => ({ url, up: !!r && r.connected }));
  }
}

