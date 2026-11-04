// Members over real Nostr relays (core §9): every message is a NIP-59 wrap, kind 21059 (live,
// never stored), split into parts over 24,000 bytes, re-sent until answered. Each process hosts
// its own nodes; a node is reachable when it is subscribed on the shared relays.
// Local test relays only (`nak serve`); nothing here knows any live server.

import { Relay } from 'nostr-tools/relay';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { wrap, unwrap, split, Reassembler, powBits, KIND_WRAP_LIVE } from '../src/transport.ts';
import type { KeyPair, NostrEvent } from '../src/event.ts';
import { unreachable, type Node, type Transport, type Filter, type Events } from './net.ts';

export interface RelayNetOpts { relays: string[]; timeoutMs?: number; resendMs?: number; log?: (s: string) => void }

const CHUNK = 400;                 // keys per subscription: one `#p` list, not one subscription per key (review 10 C1)

export class RelayNet implements Transport {
  o: Required<RelayNetOpts>;
  /** One connection per relay URL, null while it is down (reconnected with backoff, review 10 H1). */
  conns = new Map<string, Relay | null>();
  /** Where Web Push requests go (server/push.ts in the runtime). */
  pushes?: { push(p: { url: string; authorization: string; body: Uint8Array; at: number }): unknown };
  hosted = new Map<string, { node: Node; parts: Reassembler; answered: Map<string, { at: number; answer: any | null }> }>();
  pending = new Map<string, (body: any) => void>();         // `${to}:${id}` → resolve
  seen = new Set<string>();
  offset = 0;
  #chunks: string[][] = [];                                    // hosted keys, in subscription-sized lists
  #subs = new Map<string, ({ close(): void } | null)[]>();     // url → one subscription per chunk
  #closed = false;
  constructor(o: RelayNetOpts) { this.o = { timeoutMs: 8000, resendMs: 2000, ...o, log: o.log ?? (() => {}) }; }
  get now() { return Math.floor(Date.now() / 1000) + this.offset; }
  alive(pub: string) { void pub; return true; }                // over relays nobody knows; a send times out instead
  advance(s: number) { this.offset += s; }

  /** Connect to every relay; one that is down is retried in the background, it never stops the start. */
  async connect() {
    await Promise.allSettled(this.o.relays.map((u) => this.#dial(u, 0)));
    if (![...this.conns.values()].some(Boolean)) this.o.log('no relay reachable yet; retrying');
  }
  async #dial(url: string, attempt: number): Promise<void> {
    if (this.#closed) return;
    try {
      const r = await Relay.connect(url);
      r.onclose = () => { this.conns.set(url, null); this.#subs.delete(url); if (!this.#closed) setTimeout(() => void this.#dial(url, 1), 1000); };
      this.conns.set(url, r);
      this.#subs.set(url, []);
      this.#chunks.forEach((_, k) => this.#subscribe(url, k));
      for (const w of this.#watches) this.#watchOn(url, w);
    } catch {
      this.conns.set(url, null);
      const wait = Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5));
      if (!this.#closed) setTimeout(() => void this.#dial(url, attempt + 1), wait).unref?.();
    }
  }
  /** Which relays are connected, for /health. */
  status() { return this.o.relays.map((url) => ({ url, up: !!this.conns.get(url) })); }
  close() { this.#closed = true; for (const subs of this.#subs.values()) subs.forEach((x) => x?.close()); for (const c of this.conns.values()) c?.close(); for (const c of this.#extraConn.values()) c.close(); }

  #subscribe(url: string, k: number) {
    const c = this.conns.get(url), subs = this.#subs.get(url);
    if (!c || !subs) return;
    subs[k]?.close();
    const keys = this.#chunks[k];
    subs[k] = keys.length ? c.subscribe([{ kinds: [KIND_WRAP_LIVE], '#p': keys, since: this.now - 5 }], {
      onevent: (e) => { const to = (e as NostrEvent).tags.find((t) => t[0] === 'p')?.[1]; if (to && this.hosted.has(to)) void this.onWrap(to, e as NostrEvent); },
    }) : null;
  }
  #resubscribe(k: number) { for (const url of this.conns.keys()) this.#subscribe(url, k); }

  // --- raw events (Doors §3.3: NIP-46 requests and replies, watching) ---------------------------
  // A grant names its own relays: events go to and come from those, on connections opened on demand
  // (review 11 H3), beside the transport's own. Each watch keeps its own seen set, so two watches in one
  // process never split an event between them (review 11 M2).
  #extra = new Map<string, Promise<Relay | null>>();      // a dial in progress is shared, never raced
  static readonly EXTRA_MAX = 32;
  #watches = new Set<{ f: Filter; cb: (e: any) => void; relays: string[]; subs: Map<string, { close(): void }>; seen: Set<string> }>();
  #extraConn = new Map<string, Relay>();
  #relayFor(url: string): Promise<Relay | null> {
    if (this.conns.has(url)) return Promise.resolve(this.conns.get(url) ?? null);
    if (!/^wss?:\/\/[^\s]+$/.test(url) || url.length > 256) return Promise.resolve(null);
    const known = this.#extra.get(url);
    if (known) return known;
    if (this.#extra.size >= RelayNet.EXTRA_MAX) return Promise.resolve(null);
    const p = Relay.connect(url).then((r) => {
      r.onclose = () => { this.#extra.delete(url); this.#extraConn.delete(url); };
      this.#extraConn.set(url, r);
      for (const w of this.#watches) if (w.relays.includes(url)) this.#watchOn(url, w);
      return r;
    }, () => { this.#extra.delete(url); return null; });
    this.#extra.set(url, p);
    return p;
  }
  #watchOn(url: string, w: { f: Filter; cb: (e: any) => void; subs: Map<string, { close(): void }>; seen: Set<string> }) {
    const c = this.conns.get(url) ?? this.#extraConn.get(url); if (!c) return;
    w.subs.get(url)?.close();
    w.subs.set(url, c.subscribe([{ ...w.f, ...(w.f.since === undefined ? { since: this.now - 5 } : {}) } as any], {
      onevent: (e) => { if (w.seen.has(e.id)) return; w.seen.add(e.id); if (w.seen.size > 20_000) w.seen.clear(); w.cb(e); },
    }));
  }
  events: Events = {
    publishEvent: async (e: any, relays?: string[]) => {
      const targets = new Set<Relay>([...this.conns.values()].filter(Boolean) as Relay[]);
      for (const u of relays ?? []) { const r = await this.#relayFor(u); if (r) targets.add(r); }
      await Promise.allSettled([...targets].map((c) => c.publish(e)));
    },
    watch: (f: Filter, cb: (e: any) => void, relays: string[] = []) => {
      const w = { f, cb, relays, subs: new Map<string, { close(): void }>(), seen: new Set<string>() };
      this.#watches.add(w);
      for (const url of this.conns.keys()) this.#watchOn(url, w);
      for (const url of relays) if (!this.conns.has(url)) void this.#relayFor(url).then((r) => { if (r) this.#watchOn(url, w); });
      return { close: () => { this.#watches.delete(w); for (const s of w.subs.values()) s.close(); } };
    },
  };

  /** Host a node: its key joins a subscription on every relay. */
  add<N extends Node>(node: N): N {
    const pub = node.kp.pub;
    this.hosted.set(pub, { node, parts: new Reassembler(), answered: new Map() });
    if (!this.#chunks.some((c) => c.includes(pub))) {
      let k = this.#chunks.findIndex((c) => c.length < CHUNK);
      if (k < 0) { this.#chunks.push([]); k = this.#chunks.length - 1; }
      this.#chunks[k].push(pub);
      this.#resubscribe(k);
    }
    return node;
  }
  rekey(oldPub: string, node: Node) { this.kill(oldPub); this.add(node); }
  kill(pub: string) {
    this.hosted.delete(pub);
    const k = this.#chunks.findIndex((c) => c.includes(pub));
    if (k >= 0) { this.#chunks[k] = this.#chunks[k].filter((x) => x !== pub); this.#resubscribe(k); }
  }

  private async publish(from: KeyPair, to: string, body: any, pow?: number) {
    for (const part of split(body)) {
      const w = wrap(from.sk, to, part, { pow });
      await Promise.allSettled([...this.conns.values()].filter(Boolean).map((c) => c!.publish(w)));
    }
  }

  private async onWrap(me: string, e: NostrEvent) {
    const r = await this.take(me, e);
    if (r) await this.publish(r.from, r.to, r.answer);
  }

  /** One wrap addressed to hosted key `me`, however it arrived: an answer to something we sent is
   *  delivered; a request is answered once per (sender, id), a re-send getting the same answer (§5.3).
   *  Returns the answer to send back, or null. `meta.ip` is the HTTPS source, for the limits. */
  async take(me: string, e: NostrEvent, meta: { ip?: string; pow?: number } = {}): Promise<{ from: KeyPair; to: string; answer: any } | null> {
    if (this.seen.has(e.id)) return null;
    this.seen.add(e.id);
    if (this.seen.size > 200_000) this.seen.clear();
    const h = this.hosted.get(me);
    if (!h) return null;
    let o;
    try { o = unwrap(h.node.kp.sk, e); } catch { return null; }
    let body;
    try { body = h.parts.take(o.from, o.body, this.now); } catch { return null; }
    if (!body) return null;
    if (body.re !== undefined && body.__answer) {
      const k = `${o.from}:${body.re}`;
      const res = this.pending.get(k);
      if (res) { this.pending.delete(k); delete body.__answer; res(body); }
      return null;
    }
    const key = `${o.from}:${body.id}`;
    const prev = h.answered.get(key);
    if (prev) return prev.answer ? { from: h.node.kp, to: o.from, answer: prev.answer } : null;
    h.answered.set(key, { at: Date.now(), answer: null });
    let ans;
    try { ans = await h.node.handle(o.from, body, o.sentAt, { pow: powBits(e.id), ...meta }); } catch (err) { ans = { type: 'error', code: 'internal', detail: String(err) }; }
    if (ans === undefined || ans === null) return null;
    const answer = { ...ans, re: body.id, __answer: true };
    h.answered.set(key, { at: Date.now(), answer });
    for (const [k, v] of h.answered) if (Date.now() - v.at > 600_000) h.answered.delete(k);
    return { from: h.node.kp, to: o.from, answer };
  }
  /** The wraps that carry `body` from `from` to `to` (parts when it is large), for an HTTPS reply. */
  wrapsFor(from: KeyPair, to: string, body: any): NostrEvent[] { return split(body).map((part) => wrap(from.sk, to, part)); }

  /** Send and wait for the answer, re-sending until answered or timed out. */
  async send(from: KeyPair, to: string, body: any, opt: { timeoutMs?: number; pow?: number } = {}): Promise<any> {
    const ans = await this.#send(from, to, body, opt);
    // A server under a flood asks for proof of work: once more, with a fresh id and the work it named.
    if (ans?.code === 'pow' && !opt.pow && Number.isSafeInteger(ans.pow) && ans.pow <= 28) return this.#send(from, to, { ...body, id: bytesToHex(randomBytes(16)) }, { ...opt, pow: ans.pow });
    return ans;
  }
  async #send(from: KeyPair, to: string, body: any, opt: { timeoutMs?: number; pow?: number } = {}): Promise<any> {
    const limit = opt.timeoutMs ?? this.o.timeoutMs;
    if (!this.hosted.has(from.pub)) return unreachable();
    const b = { ...body, id: body.id ?? bytesToHex(randomBytes(16)) };
    const k = `${to}:${b.id}`;
    const done = new Promise<any>((res) => this.pending.set(k, res));
    const start = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<any>((res) => { timer = setTimeout(() => { this.pending.delete(k); res(unreachable()); }, limit); });
    const resend = (async () => {
      while (this.pending.has(k) && Date.now() - start < limit) {
        await this.publish(from, to, b, opt.pow);
        await new Promise((r) => setTimeout(r, this.o.resendMs));
      }
    })();
    const ans = await Promise.race([done, timeout]);
    clearTimeout(timer);
    void resend;
    this.o.log(`${from.pub.slice(0, 6)}→${to.slice(0, 6)} ${b.type} → ${ans?.type}${ans?.code ? ' ' + ans.code : ''}`);
    return ans;
  }
}
