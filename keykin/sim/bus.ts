// An in-memory relay: every message is a real NIP-59 wrap (kind 21059), so the simulation
// exercises the envelope too. Synchronous request/answer; a dead node answers nothing.

import { wrap, unwrap, powBits } from '../src/transport.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { KeyPair, NostrEvent } from '../src/event.ts';

export { TRANSPORT_FAILED, unreachable, type Node, type Transport, type PushOut } from '../runtime/net.ts';
import { unreachable, matches, type Node, type Transport, type PushOut, type Filter, type Events } from '../runtime/net.ts';

export class Bus implements Transport {
  now: number;
  nodes = new Map<string, Node>();
  dead = new Set<string>();
  /** Every wrap that crossed the bus, for the never-1059 check. */
  wire: NostrEvent[] = [];
  log: string[] = [];
  /** Events published to relays (only the signpost, §9.4). */
  published: NostrEvent[] = [];
  /** Web Push requests servers sent (core §8.2), as a gateway receives them. */
  pushes: PushOut[] = [];
  /** An in-memory relay for raw events (Doors §3.3): every published event reaches every matching watch. */
  #watches = new Set<{ f: Filter; cb: (e: any) => void }>();
  events: Events = {
    publishEvent: async (e: any) => { this.published.push(e); for (const w of [...this.#watches]) if (matches(w.f, e)) w.cb(e); },
    watch: (f: Filter, cb: (e: any) => void) => { const w = { f, cb }; this.#watches.add(w); return { close: () => void this.#watches.delete(w) }; },
    query: async (f: Filter) => ({ events: this.published.filter((e) => matches(f, e)), answered: 1, asked: 1 }),
  };
  constructor(now = 1_800_000_000) { this.now = now; }
  add(n: Node) { this.nodes.set(n.kp.pub, n); return n; }
  kill(pub: string) { this.dead.add(pub); }
  /** A server's member key arrives with its enrol reply (Server profile §4): readdress it. */
  rekey(oldPub: string, node: Node) { this.nodes.delete(oldPub); this.nodes.set(node.kp.pub, node); }
  revive(pub: string) { this.dead.delete(pub); }
  alive = (pub: string) => this.nodes.has(pub) && !this.dead.has(pub);
  advance(s: number) { this.now += s; }
  /** Seal `body` from `from` to `to`, deliver, and open the answer. */
  async send(from: KeyPair, to: string, body: any, opt: { pow?: number; timeoutMs?: number } = {}): Promise<any> {
    const ans = await this.#send(from, to, body, opt);
    // As RelayNet: a server under a flood asks for proof of work; once more, with a fresh id and the work.
    if (ans?.code === 'pow' && !opt.pow && Number.isSafeInteger(ans.pow) && ans.pow <= 28) return this.#send(from, to, { ...body, id: body.id ? bytesToHex(randomBytes(16)) : undefined }, { pow: ans.pow });
    return ans;
  }
  async #send(from: KeyPair, to: string, body: any, opt: { pow?: number }): Promise<any> {
    if (!this.alive(to) || this.dead.has(from.pub)) return unreachable();
    const w = wrap(from.sk, to, body, { at: this.now, pow: opt.pow });
    this.wire.push(w);
    const node = this.nodes.get(to)!;
    const o = unwrap(node.kp.sk, w);
    this.log.push(`${from.pub.slice(0, 6)}→${to.slice(0, 6)} ${body.type}`);
    const ans = await node.handle(o.from, o.body, o.sentAt, { pow: powBits(w.id) });
    if (ans === undefined || ans === null) return null;
    const back = wrap(node.kp.sk, from.pub, ans, { at: this.now });
    this.wire.push(back);
    return unwrap(from.sk, back).body;
  }
}
