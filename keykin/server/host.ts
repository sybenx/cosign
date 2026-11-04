// One server process (Server profile §2, §4): a host key, monthly enrol secrets, and a seat node per
// account. The host key is the front door: `create`, the DKG rounds and `enroll` from a device go to a
// fresh seat node for that device, which takes its member key from its enrol reply and is then reached
// at that key. Every node is written to sealed storage after each request it answers (core §2), and
// rebuilt from it on start; nonces and a DKG in flight are never written (§5.2).

import { newKey, pubOf, type KeyPair } from '../src/event.ts';
import { bytesToHex, hexToBytes, randomBytes, strictJson, refuse } from '../src/bytes.ts';
import { enrolSecretAlive } from '../src/serverprofile.ts';
import { ServerNode } from './node.ts';
import { Limits } from './limits.ts';
import type { Node, Transport } from '../runtime/net.ts';

export interface Store { save(k: string, t: string): void; load(k: string): string | null; list(): string[]; destroy(k: string): void }
/** What a host announces in its enrol replies. */
/** `allowHttpPush`: accept plain-http push addresses (a local test gateway only). */
export interface HostProfile { https: string; relays: string[]; operator: string; name: string; allowHttpPush?: boolean }
/** Where hosted nodes become reachable: RelayNet's `add`, or the Bus's. */
export interface Hosting { add(node: Node): unknown; kill?(pub: string): void }

const SESSION_S = 3600;
const month = (t: number) => new Date(t * 1000).toISOString().slice(0, 7);

export class Host {
  key: KeyPair;
  secrets: { id: string; secret: string; made: number }[] = [];
  nodes = new Map<string, ServerNode>();                          // member key → seat
  #sessions = new Map<string, { node: ServerNode; at: number }>(); // device key → node in creation
  readonly net: Transport; readonly hosting: Hosting; readonly store: Store; readonly profile: HostProfile;
  limits = new Limits();
  #limited = (body: any) => ({ type: 'error', re: body?.id, code: 'rate_limited' });

  constructor(o: { net: Transport; hosting: Hosting; store: Store; profile: HostProfile }) {
    this.net = o.net; this.hosting = o.hosting; this.store = o.store; this.profile = o.profile;
    const saved = this.store.load('host');
    if (saved) {
      const x = strictJson(saved);
      this.key = { sk: hexToBytes(x.sk), pub: pubOf(hexToBytes(x.sk)) }; this.secrets = x.secrets;
    } else { this.key = newKey(); this.#saveHost(); }
  }
  get now() { return this.net.now; }
  #saveHost() { this.store.save('host', JSON.stringify({ v: 1, sk: bytesToHex(this.key.sk), secrets: this.secrets })); }

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

  #key = (n: ServerNode) => `seat-${n.kp.pub.slice(0, 32)}`;
  save(n: ServerNode) { this.store.save(this.#key(n), n.snapshot()); }

  /** Host a seat node: reachable at its member key, saved after every answer, and re-hosted if it
   *  re-keys (an `enroll` gives it its member key). */
  #host(n: ServerNode) {
    const host = this;
    const proxy: Node = {
      get kp() { return n.kp; },
      async handle(from: string, body: any, sentAt: number, meta?: { ip?: string }) {
        // Server profile §3: verified members, the backup key and peers per sender key; anyone else
        // (an incoming holder, a removed key, a heir) per HTTPS source IP only, never per account.
        const m = n.co?.m;
        const known = !!m && (m.members.has(from) || m.backupKey === from) && !m.removed.has(from);
        const ok = known ? host.limits.member(from, body?.type, host.now, m!.backupKey === from) : host.limits.newcomer(host.now, meta?.ip);
        if (!ok) return host.#limited(body);
        const a = await n.handle(from, body, sentAt);
        host.save(n);
        return a;
      },
    };
    this.nodes.set(n.kp.pub, n);
    this.hosting.add(proxy);
  }

  #fresh(): ServerNode {
    const s = this.secret();
    const n = new ServerNode(this.net, this.profile.name);
    n.host = this.key; n.enrolSecret = new Uint8Array(s.secret);
    n.profile = { secretId: s.id, https: this.profile.https, relays: this.profile.relays, operator: this.profile.operator || this.key.pub, allowHttpPush: !!this.profile.allowHttpPush };
    // A node re-keys when it enrols: host it under its member key from then on.
    const self = this;
    n.bus = new Proxy(this.net, { get(t, p) { return p === 'rekey' ? (_old: string, node: ServerNode) => { self.#host(node); self.save(node); } : (t as any)[p]; } });
    return n;
  }

  /** The front door, at the host key: creation and enrolment, one session per device. */
  readonly front: Node = {
    kp: undefined as unknown as KeyPair,
    handle: async (from: string, body: any, sentAt: number, meta?: { ip?: string }) => {
      if (!['create', 'dkg_1', 'dkg_2', 'dkg_3', 'enroll'].includes(body?.type)) return { type: 'error', re: body?.id, code: 'unsupported' };
      // Only `create` is an account creation; enrolment and the DKG rounds are newcomers' requests.
      if (!(body.type === 'create' ? this.limits.creation(this.now, meta?.ip) : this.limits.newcomer(this.now, meta?.ip))) return this.#limited(body);
      for (const [k, x] of this.#sessions) if (this.now - x.at > SESSION_S) this.#sessions.delete(k);
      // `create` and the DKG rounds stay with one node per device; `enroll` alone mints a fresh seat.
      let s = this.#sessions.get(from);
      if (!s || body.type === 'create' || (body.type === 'enroll' && !s.node.dkg)) { s = { node: this.#fresh(), at: this.now }; this.#sessions.set(from, s); }
      const a = await s.node.handle(from, body, sentAt);
      if (body.type === 'enroll') this.#sessions.delete(from);
      return a;
    },
  };

  /** Start: every stored seat restored and hosted, then the front door. */
  start() {
    for (const k of this.store.list().filter((x) => x.startsWith('seat-'))) {
      const n = ServerNode.restore(this.net, this.store.load(k)!);
      n.host = this.key; n.profile.allowHttpPush = !!this.profile.allowHttpPush;
      this.#host(n);
    }
    Object.defineProperty(this.front, 'kp', { value: this.key });
    this.hosting.add(this.front);
    return this;
  }
  /** An account destroyed or a seat retired for good: its record and key go too (core §7.3). */
  forget(memberKey: string) {
    const n = this.nodes.get(memberKey);
    if (!n) refuse('unknown_seat');
    this.store.destroy(this.#key(n!)); this.nodes.delete(memberKey); this.hosting.kill?.(memberKey);
  }
}
