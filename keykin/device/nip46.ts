// NIP-46 at its home (Doors §3.3): per-site signer keys that never leave the device that connected the
// site, `bunker://` links and `nostrconnect://` codes, the methods, and the wake path: the home tells one
// watching server its grants (`watch_set`), that server leaves sites' requests in the home's inbox and
// pushes once per burst, and a woken home drains them and answers. Any of the person's devices can be a
// home (the user's decision, 2026-11-03); a phone wakes on push.
//
// The signer key is an ordinary key used only as a mailbox; what a site asks of the account goes through
// the device: `sign_event` through a signing round, encryption through ECDH with a co-signer (core §5.5).
// Grants (scopes, revoke, sync between devices) are the Doors module's §1–§2 and Device policy's
// Confirm/Held, which this doesn't build yet: a grant here allows every method, and an event that needs
// an approval is answered `held:`.

import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { finalizeEvent, verifyEvent as ntVerify } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes, randomBytes, strictJson, KeykinError } from '../src/bytes.ts';
import { newKey, pubOf, type NostrEvent } from '../src/event.ts';
import { msg } from '../src/msg.ts';
import { unwrap } from '../src/transport.ts';
import type { DeviceNode } from './node.ts';

export const KIND_NIP46 = 24133;
const LINK_S = 600, ENDED_KEEP_S = 30 * 86400;

export interface Grant {
  signer: string; signerSk: string; client: string | null; secret: string | null; linkExpires: number | null;
  relays: string[]; site: string; connectedAt: number | null; endedAt: number | null;
}

/** `nostrconnect://<client>?relay=…&secret=…&name=…` (NIP-46). */
export function parseNostrconnect(uri: string) {
  const u = new URL(uri);
  if (u.protocol !== 'nostrconnect:') throw new KeykinError('malformed', 'not a nostrconnect code');
  const client = u.hostname || u.pathname.replace(/^\/+/, '');
  if (!/^[0-9a-f]{64}$/.test(client)) throw new KeykinError('malformed', 'client key');
  const relays = u.searchParams.getAll('relay');
  if (!relays.length || relays.some((r) => !/^wss?:\/\//.test(r))) throw new KeykinError('malformed', 'relays');
  return { client, relays, secret: u.searchParams.get('secret'), name: u.searchParams.get('name') ?? '', perms: u.searchParams.get('perms') ?? '' };
}

export class Nip46Home {
  grants = new Map<string, Grant>();
  /** The server this home asked to watch for it (one per account, Doors §3.3), or null. */
  watching: string | null = null;
  #seen = new Set<string>();
  #listening: { close(): void } | null = null;
  readonly d: DeviceNode;
  constructor(d: DeviceNode) { this.d = d; }
  get #events() { const e = this.d.bus.events; if (!e) throw new KeykinError('unsupported', 'this transport carries no raw events'); return e; }

  #grant(relays: string[], site: string, o: Partial<Grant>): Grant {
    const k = newKey();
    const g: Grant = { signer: k.pub, signerSk: bytesToHex(k.sk), client: null, secret: null, linkExpires: null, relays, site, connectedAt: null, endedAt: null, ...o };
    this.grants.set(g.signer, g);
    this.listen();
    this.d.persist();
    return g;
  }
  /** A `bunker://` link (Doors §3.3): its secret binds to the first client key that uses it, and
   *  expires after 10 minutes if unused. */
  mintBunker(relays: string[], site = ''): string {
    const g = this.#grant(relays, site, { secret: bytesToHex(randomBytes(16)), linkExpires: this.d.now + LINK_S });
    return `bunker://${g.signer}?${relays.map((r) => `relay=${encodeURIComponent(r)}`).join('&')}&secret=${g.secret}`;
  }
  /** A scanned `nostrconnect://` code: the grant is bound to the code's client, and the `connect` reply
   *  carries the code's secret, as clients check it. */
  async acceptNostrconnect(uri: string): Promise<Grant> {
    const c = parseNostrconnect(uri);
    const g = this.#grant(c.relays, c.name, { client: c.client, connectedAt: this.d.now });
    await this.#reply(g, c.client, { id: bytesToHex(randomBytes(8)), result: c.secret ?? 'ack' });
    await this.watchSet();
    return g;
  }
  /** End a grant: its key answers `revoked:` for 30 days, then is forgotten. */
  async end(signer: string) {
    const g = this.grants.get(signer); if (!g) return;
    g.endedAt = this.d.now; this.d.persist(); await this.watchSet();
  }

  /** Answer sites while awake: subscribed to every grant's requests. */
  listen() {
    this.#listening?.close();
    const live = [...this.grants.values()].filter((g) => !g.endedAt || this.d.now - g.endedAt < ENDED_KEEP_S).map((g) => g.signer);
    this.#listening = live.length ? this.#events.watch({ kinds: [KIND_NIP46], '#p': live }, (e) => void this.handle(e)) : null;
  }
  sleep() { this.#listening?.close(); this.#listening = null; }

  /** One request from a site. False when it was nothing to answer (seen already, not ours, unreadable). */
  async handle(e: NostrEvent): Promise<boolean> {
    if (e?.kind !== KIND_NIP46 || this.#seen.has(e.id) || !ntVerify(e as any)) return false;
    this.#seen.add(e.id);
    if (this.#seen.size > 10_000) this.#seen.clear();
    const signer = e.tags.find((t) => t[0] === 'p')?.[1];
    const g = signer ? this.grants.get(signer) : undefined;
    if (!g) return false;
    const sk = hexToBytes(g.signerSk);
    let req: any, mode: 'nip44' | 'nip04' = 'nip44';
    try { req = strictJson(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(sk, e.pubkey))); }
    catch { try { req = strictJson(await nip04.decrypt(sk, e.pubkey, e.content)); mode = 'nip04'; } catch { return false; } }
    if (typeof req?.id !== 'string' || typeof req?.method !== 'string' || !Array.isArray(req.params ?? [])) return false;
    const answer = await this.#answer(g, e.pubkey, req.method, req.params ?? []);
    await this.#reply(g, e.pubkey, { id: req.id, ...answer }, mode);
    return true;
  }

  async #answer(g: Grant, from: string, method: string, params: any[]): Promise<{ result?: string; error?: string }> {
    const now = this.d.now;
    if (g.endedAt) return { error: 'revoked: this site was disconnected' };
    if (method === 'connect') {
      // A link's secret binds to the first client key; that same key may connect again, any other is refused.
      if (g.client === null) {
        if (!g.secret || params[1] !== g.secret || g.linkExpires === null || now > g.linkExpires) return { error: 'not-connected: this link has expired or is wrong; mint a new one' };
        g.client = from; g.connectedAt = now; g.linkExpires = null; this.d.persist(); await this.watchSet();
        return { result: 'ack' };
      }
      return from === g.client ? { result: 'ack' } : { error: 'not-connected: this link belongs to another client; mint a new one' };
    }
    if (from !== g.client) return { error: 'not-connected: connect first' };
    try {
      switch (method) {
        case 'ping': return { result: 'pong' };
        case 'get_public_key': return { result: this.d.g };
        case 'get_relays': return { result: JSON.stringify(Object.fromEntries(g.relays.map((r) => [r, { read: true, write: true }]))) };
        case 'switch_relays': return { result: JSON.stringify(g.relays) };
        case 'logout': await this.end(g.signer); return { result: 'ack' };
        case 'sign_event': {
          const ev = strictJson(String(params[0]));
          const signed = await this.d.sign(ev);
          return { result: JSON.stringify(signed) };
        }
        case 'nip44_encrypt': return { result: await this.d.nip44(String(params[0]), String(params[1]), true) };
        case 'nip44_decrypt': return { result: await this.d.nip44(String(params[0]), String(params[1]), false) };
        case 'nip04_encrypt': return { result: await this.d.nip04(String(params[0]), String(params[1]), true) };
        case 'nip04_decrypt': return { result: await this.d.nip04(String(params[0]), String(params[1]), false) };
        default: return { error: `unsupported: ${method}` };
      }
    } catch (err) {
      const code = (err as KeykinError).code;
      if (code === 'needs_approval' || code === 'hold_not_passed') return { error: 'held: approve on your phone' };
      if (code === 'declined') return { error: 'declined: not allowed for this site' };
      if (code === 'unreachable' || code === 'no_server' || code === 'no_answer') return { error: 'try-later: no server answered' };
      return { error: `declined: ${code ?? 'refused'}` };
    }
  }

  async #reply(g: Grant, to: string, body: object, mode: 'nip44' | 'nip04' = 'nip44') {
    const sk = hexToBytes(g.signerSk), text = JSON.stringify(body);
    const content = mode === 'nip04' ? await nip04.encrypt(sk, to, text) : nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(sk, to));
    const e = finalizeEvent({ kind: KIND_NIP46, created_at: this.d.now, tags: [['p', to]], content }, sk);
    await this.#events.publishEvent(e, g.relays);
  }

  // --- the wake path ---------------------------------------------------------------------------
  /** Ask `server` (a seated server's member key) to watch this home's grants; or re-send the set. */
  async watchSet(server = this.watching) {
    if (!server) return;
    this.watching = server;
    const grants = [...this.grants.values()].filter((g) => !g.endedAt).map((g) => ({ signer: g.signer, client: g.client, relays: g.relays }));
    const a = await this.d.bus.send(this.d.kp, server, msg('watch_set', this.d.g, this.d.epochId, 'ask', { grants }));
    if (a?.type !== 'ack') throw new KeykinError(a?.code ?? 'watch_set_failed');
    this.d.persist();
  }
  /** Woken (a push, or the app opened): drain every site request the watching server kept. Returns how
   *  many it answered now (one it answered while awake is skipped, and acknowledged all the same). */
  async wake(): Promise<number> {
    if (!this.watching) return 0;
    const inbox = await this.d.bus.send(this.d.kp, this.watching, msg('inbox_get', this.d.g, this.d.epochId, 'ask'));
    const done: string[] = []; let n = 0;
    for (const it of inbox?.items ?? []) {
      let o; try { o = unwrap(this.d.kp.sk, it.wrap); } catch { continue; }
      if (o.from !== this.watching || o.body?.type !== 'nip46') continue;
      if (await this.handle(o.body.event)) n++;
      done.push(it.iid);
    }
    if (done.length) await this.d.bus.send(this.d.kp, this.watching, msg('inbox_ack', this.d.g, this.d.epochId, 'ask', { iids: done }));
    return n;
  }

  dump() { return { grants: [...this.grants.values()], watching: this.watching }; }
  load(x: any) { this.grants = new Map((x?.grants ?? []).map((g: Grant) => [g.signer, g])); this.watching = x?.watching ?? null; }
}
export { pubOf };
