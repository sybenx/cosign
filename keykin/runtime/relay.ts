// Members over real Nostr relays (core §9): every message is a NIP-59 wrap, kind 21059 (live,
// never stored), split into parts over 24,000 bytes, re-sent until answered. Each process hosts
// its own nodes; a node is reachable when it is subscribed on the shared relays.
// Local test relays only (`nak serve`); nothing here knows any live server.

import { Relay } from 'nostr-tools/relay';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { wrap, unwrap, split, Reassembler, KIND_WRAP_LIVE } from '../src/transport.ts';
import type { KeyPair, NostrEvent } from '../src/event.ts';
import { unreachable, type Node, type Transport } from './net.ts';

export interface RelayNetOpts { relays: string[]; timeoutMs?: number; resendMs?: number; log?: (s: string) => void }

export class RelayNet implements Transport {
  o: Required<RelayNetOpts>;
  conns: Relay[] = [];
  /** Where Web Push requests go (server/push.ts in the runtime). */
  pushes?: { push(p: { url: string; authorization: string; body: Uint8Array; at: number }): unknown };
  hosted = new Map<string, { node: Node; sub: { close(): void }[]; parts: Reassembler; answered: Map<string, { at: number; answer: any | null }> }>();
  pending = new Map<string, (body: any) => void>();         // `${to}:${id}` → resolve
  seen = new Set<string>();
  offset = 0;
  constructor(o: RelayNetOpts) { this.o = { timeoutMs: 8000, resendMs: 2000, ...o, log: o.log ?? (() => {}) }; }
  get now() { return Math.floor(Date.now() / 1000) + this.offset; }
  alive(pub: string) { void pub; return true; }                // over relays nobody knows; a send times out instead
  advance(s: number) { this.offset += s; }

  async connect() { this.conns = await Promise.all(this.o.relays.map((u) => Relay.connect(u))); }
  close() { for (const h of this.hosted.values()) h.sub.forEach((s) => s.close()); this.conns.forEach((c) => c.close()); }

  /** Host a node: subscribe to wraps addressed to its key on every relay. */
  add<N extends Node>(node: N): N {
    const h = { node, sub: [] as { close(): void }[], parts: new Reassembler(), answered: new Map() };
    this.hosted.set(node.kp.pub, h);
    for (const c of this.conns)
      h.sub.push(c.subscribe([{ kinds: [KIND_WRAP_LIVE], '#p': [node.kp.pub], since: this.now - 5 }], { onevent: (e) => void this.onWrap(node.kp.pub, e as NostrEvent) }));
    return node;
  }
  rekey(oldPub: string, node: Node) { this.kill(oldPub); this.add(node); }
  kill(pub: string) { const h = this.hosted.get(pub); if (h) { h.sub.forEach((s) => s.close()); this.hosted.delete(pub); } }

  private async publish(from: KeyPair, to: string, body: any) {
    for (const part of split(body)) {
      const w = wrap(from.sk, to, part);
      await Promise.allSettled(this.conns.map((c) => c.publish(w)));
    }
  }

  private async onWrap(me: string, e: NostrEvent) {
    const r = await this.take(me, e);
    if (r) await this.publish(r.from, r.to, r.answer);
  }

  /** One wrap addressed to hosted key `me`, however it arrived: an answer to something we sent is
   *  delivered; a request is answered once per (sender, id), a re-send getting the same answer (§5.3).
   *  Returns the answer to send back, or null. `meta.ip` is the HTTPS source, for the limits. */
  async take(me: string, e: NostrEvent, meta: { ip?: string } = {}): Promise<{ from: KeyPair; to: string; answer: any } | null> {
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
    try { ans = await h.node.handle(o.from, body, o.sentAt, meta); } catch (err) { ans = { type: 'error', code: 'internal', detail: String(err) }; }
    if (ans === undefined || ans === null) return null;
    const answer = { ...ans, re: body.id, __answer: true };
    h.answered.set(key, { at: Date.now(), answer });
    for (const [k, v] of h.answered) if (Date.now() - v.at > 600_000) h.answered.delete(k);
    return { from: h.node.kp, to: o.from, answer };
  }
  /** The wraps that carry `body` from `from` to `to` (parts when it is large), for an HTTPS reply. */
  wrapsFor(from: KeyPair, to: string, body: any): NostrEvent[] { return split(body).map((part) => wrap(from.sk, to, part)); }

  /** Send and wait for the answer, re-sending until answered or timed out. */
  async send(from: KeyPair, to: string, body: any, opt: { timeoutMs?: number } = {}): Promise<any> {
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
        await this.publish(from, to, b);
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
