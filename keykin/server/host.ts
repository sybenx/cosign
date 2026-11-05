// One server process (Server profile §2, §4): a host key, monthly enrol secrets, and a seat node per
// account. The host key is the front door: `create` and the DKG rounds from a device go to a node kept
// in memory for that device; `enroll` mints a reply and stores nothing but a capped, expiring note of it
// (review 10 C1). A message to an issued reply's member key brings up a seat node from keys derived
// again from the enrol secret, and a seat is written to sealed storage only once it holds something
// (an account, an upload or a tombstone). Nonces and a DKG in flight are never written (§5.2).

import { newKey, pubOf, type KeyPair } from '../src/event.ts';
import { bytesToHex, hexToBytes, randomBytes, strictJson, refuse } from '../src/bytes.ts';
import { enrolSecretAlive, enrollReply, deriveMemberSk, deriveVapidSk } from '../src/serverprofile.ts';
import { ServerNode } from './node.ts';
import { Limits } from './limits.ts';
import type { Node, Transport } from '../runtime/net.ts';

export interface Store { save(k: string, t: string): void; load(k: string): string | null; list(): string[]; destroy(k: string): void }
/** What a host announces in its enrol replies. `allowHttpPush`: accept plain-http push addresses (a
 *  local test gateway only). `pow`: NIP-13 bits asked of newcomers over relays under a flood. */
export interface HostProfile { https: string; relays: string[]; operator: string; name: string; allowHttpPush?: boolean; pow?: number }
/** Where hosted nodes become reachable: RelayNet's `add`, or the Bus's. */
export interface Hosting { add(node: Node): unknown; kill?(pub: string): void }
/** What a request arrived with: the HTTPS source address, or the wrap's NIP-13 bits over relays. */
export interface Meta { ip?: string; pow?: number }

const SESSION_S = 3600, SESSIONS_MAX = 1000;
const PENDING_S = 30 * 86400, PENDING_MAX = 10_000;      // a reply is unexpired for 30 days (Server profile §4)
const FLOOD_PER_MINUTE = 60, POW_DEFAULT = 16;
const FRONT = new Set(['create', 'dkg_1', 'dkg_2', 'dkg_3', 'enroll']);
const month = (t: number) => new Date(t * 1000).toISOString().slice(0, 7);

export class Host {
  key: KeyPair;
  secrets: { id: string; secret: string; made: number }[] = [];
  nodes = new Map<string, ServerNode>();                          // member key → seat
  /** Issued replies not yet seated: public data only, the keys derived again when needed. */
  pending = new Map<string, { reply: any; at: number }>();
  #sessions = new Map<string, { node: ServerNode; at: number }>(); // device key → creation in flight
  #newcomers: number[] = [];                                       // relay-borne front-door requests, for the flood test
  readonly net: Transport; readonly hosting: Hosting; readonly store: Store; readonly profile: HostProfile;
  limits = new Limits();
  log: (s: string) => void = () => {};
  #limited = (body: any) => ({ type: 'error', re: body?.id, code: 'rate_limited' });

  constructor(o: { net: Transport; hosting: Hosting; store: Store; profile: HostProfile }) {
    this.net = o.net; this.hosting = o.hosting; this.store = o.store; this.profile = o.profile;
    const saved = this.store.load('host');
    if (saved) {
      const x = strictJson(saved);
      this.key = { sk: hexToBytes(x.sk), pub: pubOf(hexToBytes(x.sk)) }; this.secrets = x.secrets;
      for (const p of x.pending ?? []) this.pending.set(p.reply.member_key, p);
    } else { this.key = newKey(); this.#saveHost(); }
  }
  get now() { return this.net.now; }
  #saveHost() {
    this.store.save('host', JSON.stringify({ v: 1, sk: bytesToHex(this.key.sk), secrets: this.secrets, pending: [...this.pending.values()] }));
  }

  /** This month's enrol secret, made on first use; secrets past 13 months are destroyed (Server profile §4). */
  secret(): { id: string; secret: Uint8Array } {
    const id = month(this.now);
    const kept = this.secrets.filter((x) => enrolSecretAlive(x.made, this.now));
    let changed = kept.length !== this.secrets.length;
    this.secrets = kept;
    let s = this.secrets.find((x) => x.id === id);
    if (!s) { s = { id, secret: bytesToHex(randomBytes(32)), made: this.now }; this.secrets.push(s); changed = true; }
    if (changed) this.#saveHost();
    return { id, secret: hexToBytes(s.secret) };
  }
  #secretById(id: string) { const s = this.secrets.find((x) => x.id === id && enrolSecretAlive(x.made, this.now)); return s ? hexToBytes(s.secret) : null; }

  #key = (n: ServerNode) => `seat-${n.kp.pub.slice(0, 32)}`;
  /** A seat is written only once it holds something: an account, an inert upload, or a tombstone. */
  save(n: ServerNode) {
    if (n.co || n.tombstone || n.uploads.size) this.store.save(this.#key(n), n.snapshot({ withHost: false }));
  }

  /** Host a seat node: reachable at its member key, its requests counted (Server profile §3), saved
   *  after every answer, and re-hosted if it re-keys (an `enroll` in a creation gives its member key). */
  #host(n: ServerNode) {
    const host = this;
    const proxy: Node = {
      get kp() { return n.kp; },
      async handle(from: string, body: any, sentAt: number, meta?: Meta) {
        // The front door's messages only at the front door (review 10 L3).
        if (FRONT.has(body?.type) && n.co) return { type: 'error', re: body?.id, code: 'unsupported' };
        const m = n.co?.m;
        const known = !!m && (m.members.has(from) || m.backupKey === from) && !m.removed.has(from);
        const ok = known ? host.limits.member(from, body?.type, host.now, m!.backupKey === from) : host.#newcomer(meta);
        if (ok !== true) return ok === 'pow' ? host.#powAsk(body) : host.#limited(body);
        const a = await n.handle(from, body, sentAt);
        if (a?.code === 'internal') delete a.detail;            // no paths or traces to callers (review 10 L4)
        host.save(n);
        if (n.co || n.uploads.size) host.#seated(n.kp.pub);
        return a;
      },
    };
    this.nodes.set(n.kp.pub, n);
    this.#proxies.set(n.kp.pub, proxy);
    this.hosting.add(proxy);
  }
  #seated(memberKey: string) { if (this.pending.delete(memberKey)) this.#saveHost(); }

  #node(): ServerNode {
    const n = new ServerNode(this.net, this.profile.name);
    n.host = this.key;
    n.profile = { secretId: '', https: this.profile.https, relays: this.profile.relays, operator: this.profile.operator || this.key.pub, allowHttpPush: !!this.profile.allowHttpPush };
    n.pushLimit = (url, wait) => this.limits.push(url, this.now, wait);
    return n;
  }
  /** A node for a creation in flight: it re-keys when it enrols, and is hosted at its member key then. */
  #fresh(): ServerNode {
    const s = this.secret();
    const n = this.#node();
    n.enrolSecret = new Uint8Array(s.secret); n.profile.secretId = s.id;
    const self = this;
    // Methods bound to the transport itself: its private fields don't answer through a Proxy.
    n.bus = new Proxy(this.net, { get(t, p) {
      if (p === 'rekey') return (_old: string, node: ServerNode) => { self.#host(node); self.save(node); };
      const v = (t as any)[p];
      return typeof v === 'function' ? v.bind(t) : v;
    } });
    return n;
  }
  /** A seat for an issued reply, its keys derived again from the enrol secret it names. */
  #fromReply(reply: any): ServerNode | null {
    const secret = this.#secretById(reply.secret_id);
    if (!secret) return null;
    const n = this.#node();
    n.kp = { sk: deriveMemberSk(secret, reply.g, reply.nonce), pub: reply.member_key };
    n.vapidSk = deriveVapidSk(secret, reply.g, reply.nonce);
    n.enrollR = reply; n.profile.secretId = reply.secret_id;
    if (pubOf(n.kp.sk) !== reply.member_key) return null;
    return n;
  }

  /** Newcomers (Server profile §3): per HTTPS IP; over relays, NIP-13 proof of work once flooded. */
  #newcomer(meta?: Meta): true | false | 'pow' {
    if (meta?.ip !== undefined) return this.limits.newcomer(this.now, meta.ip);
    const now = this.now;
    this.#newcomers = this.#newcomers.filter((t) => now - t < 60);
    this.#newcomers.push(now);
    if (this.#newcomers.length <= FLOOD_PER_MINUTE) return true;
    return (meta?.pow ?? 0) >= (this.profile.pow ?? POW_DEFAULT) ? true : 'pow';
  }
  #powAsk = (body: any) => ({ type: 'error', re: body?.id, code: 'pow', pow: this.profile.pow ?? POW_DEFAULT });

  /** The front door, at the host key. */
  readonly front: Node = {
    kp: undefined as unknown as KeyPair,
    handle: async (from: string, body: any, sentAt: number, meta?: Meta) => {
      if (!FRONT.has(body?.type)) return { type: 'error', re: body?.id, code: 'unsupported' };
      // Only `create` is an account creation; enrolment and the DKG rounds are newcomers' requests.
      const ok = body.type === 'create' && meta?.ip !== undefined ? this.limits.creation(this.now, meta.ip) : this.#newcomer(meta);
      if (ok !== true) return ok === 'pow' ? this.#powAsk(body) : this.#limited(body);
      if (body.type === 'create' && !this.limits.creation(this.now)) return this.#limited(body);
      for (const [k, x] of this.#sessions) if (this.now - x.at > SESSION_S) { this.#sessions.delete(k); if (!x.node.co) this.hosting.kill?.(x.node.kp.pub); }
      const s = this.#sessions.get(from);
      if (body.type === 'enroll' && !s?.node.dkg) return this.#enroll(body);
      if (body.type !== 'create' && !s) return { type: 'error', re: body?.id, code: 'no_dkg' };
      let sess = s;
      if (body.type === 'create') {
        if (this.#sessions.size >= SESSIONS_MAX) return this.#limited(body);
        sess = { node: this.#fresh(), at: this.now };
        this.#sessions.set(from, sess);
      }
      const a = await sess!.node.handle(from, body, sentAt);
      if (body.type === 'enroll') this.#sessions.delete(from);
      return a;
    },
  };
  /** `enroll {g}` outside a creation: a reply, and nothing stored but a note of it (Server profile §4). */
  #enroll(body: any) {
    if (typeof body.g !== 'string' || !/^[0-9a-f]{64}$/.test(body.g)) return { type: 'error', re: body?.id, code: 'malformed' };
    for (const [k, p] of this.pending) if (this.now - p.at > PENDING_S) { this.pending.delete(k); this.hosting.kill?.(k); }
    if (this.pending.size >= PENDING_MAX) return { type: 'error', re: body?.id, code: 'refused: full' };
    const s = this.secret();
    const r = enrollReply(this.key, s.secret, s.id, body.g, bytesToHex(randomBytes(16)), { https: this.profile.https, relays: this.profile.relays, operator: this.profile.operator || this.key.pub, issued: this.now });
    this.pending.set(r.reply.member_key, { reply: r.reply, at: this.now });
    this.#saveHost();
    this.#hostPending(r.reply);
    return { type: 'enroll_reply', reply: r.reply };
  }
  /** An issued reply's key is reachable; its node is built on its first message. */
  #hostPending(reply: any) {
    const host = this;
    let node: ServerNode | null = null;
    // Transports open wraps with the hosted key, so the placeholder holds the derived key (never stored).
    const secret = this.#secretById(reply.secret_id);
    if (!secret) return;
    this.hosting.add({
      kp: { pub: reply.member_key, sk: deriveMemberSk(secret, reply.g, reply.nonce) },
      async handle(from: string, body: any, sentAt: number, meta?: Meta) {
        node ??= host.#fromReply(reply);
        if (!node) return { type: 'error', re: body?.id, code: 'unknown_seat' };
        // From now on the seat's own proxy answers at this key; it saves the seat once it holds something.
        if (!host.nodes.has(reply.member_key)) host.#host(node);
        return host.#proxies.get(reply.member_key)!.handle(from, body, sentAt, meta);
      },
    });
  }
  #proxies = new Map<string, Node>();

  /** Start: every stored seat restored and hosted (one that can't be read is left in storage, logged,
   *  and never stops the others: review 10 C2), every pending reply's key, then the front door. */
  start() {
    Object.defineProperty(this.front, 'kp', { value: this.key });
    this.hosting.add(this.front);
    for (const k of this.store.list().filter((x) => x.startsWith('seat-'))) {
      try {
        const n = ServerNode.restore(this.net, this.store.load(k)!, { host: this.key });
        n.profile.allowHttpPush = !!this.profile.allowHttpPush;
        n.pushLimit = (url, wait) => this.limits.push(url, this.now, wait);
        this.#host(n);
      } catch (e) { this.log(`seat ${k} not restored: ${(e as Error).message}`); }
    }
    for (const p of this.pending.values()) if (!this.nodes.has(p.reply.member_key)) this.#hostPending(p.reply);
    return this;
  }
  /** An account destroyed or a seat retired for good: its record and key go too (core §7.3). */
  forget(memberKey: string) {
    const n = this.nodes.get(memberKey);
    if (!n) refuse('unknown_seat');
    this.store.destroy(this.#key(n!)); this.nodes.delete(memberKey); this.hosting.kill?.(memberKey);
  }
}
