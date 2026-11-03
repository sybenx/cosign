// An in-memory relay: every message is a real NIP-59 wrap (kind 21059), so the simulation
// exercises the envelope too. Synchronous request/answer; a dead node answers nothing.

import { wrap, unwrap } from '../src/transport.ts';
import type { KeyPair, NostrEvent } from '../src/event.ts';

export interface Node { kp: KeyPair; handle(from: string, body: any, sentAt: number): any }
/** What nodes send through: the in-memory Bus here, or runtime/relay.ts over real relays. */
export interface Transport { now: number; alive(pub: string): boolean; send(from: KeyPair, to: string, body: any, o?: { timeoutMs?: number }): Promise<any>; kill?(pub: string): void }

export class Bus implements Transport {
  now: number;
  nodes = new Map<string, Node>();
  dead = new Set<string>();
  /** Every wrap that crossed the bus, for the never-1059 check. */
  wire: NostrEvent[] = [];
  log: string[] = [];
  constructor(now = 1_800_000_000) { this.now = now; }
  add(n: Node) { this.nodes.set(n.kp.pub, n); return n; }
  kill(pub: string) { this.dead.add(pub); }
  revive(pub: string) { this.dead.delete(pub); }
  alive = (pub: string) => this.nodes.has(pub) && !this.dead.has(pub);
  advance(s: number) { this.now += s; }
  /** Seal `body` from `from` to `to`, deliver, and open the answer. */
  async send(from: KeyPair, to: string, body: any): Promise<any> {
    if (!this.alive(to) || this.dead.has(from.pub)) return { type: 'error', code: 'unreachable' };
    const w = wrap(from.sk, to, body, { at: this.now });
    this.wire.push(w);
    const node = this.nodes.get(to)!;
    const o = unwrap(node.kp.sk, w);
    this.log.push(`${from.pub.slice(0, 6)}→${to.slice(0, 6)} ${body.type}`);
    const ans = await node.handle(o.from, o.body, o.sentAt);
    if (ans === undefined || ans === null) return null;
    const back = wrap(node.kp.sk, from.pub, ans, { at: this.now });
    this.wire.push(back);
    return unwrap(from.sk, back).body;
  }
}
