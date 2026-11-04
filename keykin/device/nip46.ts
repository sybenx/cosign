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
import { newKey, pubOf, siteEvent, type NostrEvent } from '../src/event.ts';
import { what } from '../src/codes.ts';
import { msg } from '../src/msg.ts';
import { unwrap } from '../src/transport.ts';
import type { DeviceNode } from './node.ts';
import { siteGuard, siteMayDecrypt } from './doors.ts';

export const KIND_NIP46 = 24133;
const LINK_S = 600, ENDED_KEEP_S = 30 * 86400, WINDOW_S = 120;

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
  // Deduplicated and capped at 8 (a server watches at most 8 per grant: review 11 M4).
  const relays = [...new Set(u.searchParams.getAll('relay'))].slice(0, 8);
  if (!relays.length || relays.some((r) => !/^wss?:\/\/[^\s]+$/.test(r) || r.length > 256)) throw new KeykinError('malformed', 'relays');
  return { client, relays, secret: u.searchParams.get('secret'), name: u.searchParams.get('name') ?? '', perms: u.searchParams.get('perms') ?? '' };
}

export class Nip46Home {
  grants = new Map<string, Grant>();
  /** The server this home asked to watch for it (one per account, Doors §3.3), or null. */
  watching: string | null = null;
  #seen = new Map<string, number>();     // request id → its created_at, while within the window
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
    await this.watchSet().catch(() => {});
    return g;
  }
  /** End a grant: its key answers `revoked:` for 30 days, then is forgotten. */
  async end(signer: string) {
    const g = this.grants.get(signer); if (!g) return;
    g.endedAt = this.d.now; this.d.persist(); await this.watchSet().catch(() => {});
  }

  /** Answer sites while awake: subscribed to every grant's requests. */
  listen() {
    this.#listening?.close();
    // An ended grant answers `revoked:` for 30 days, then it and its key are forgotten (review 11 L3).
    for (const [k, g] of this.grants) if (g.endedAt && this.d.now - g.endedAt >= ENDED_KEEP_S) this.grants.delete(k);
    const live = [...this.grants.values()];
    const relays = [...new Set(live.flatMap((g) => g.relays))];
    this.#listening = live.length ? this.#events.watch({ kinds: [KIND_NIP46], '#p': live.map((g) => g.signer) }, (e) => { this.handle(e).catch(() => {}); }, relays) : null;
  }
  sleep() { this.#listening?.close(); this.#listening = null; }

  /** One request from a site. False when it was nothing to answer (seen already, not ours, unreadable). */
  async handle(e: NostrEvent): Promise<boolean> {
    // Only fresh requests (±2 minutes), each answered once even across a restart (review 11 M5).
    if (e?.kind !== KIND_NIP46 || this.#seen.has(e.id) || Math.abs(this.d.now - e.created_at) > WINDOW_S || !ntVerify(e as any)) return false;
    this.#seen.set(e.id, e.created_at);
    for (const [id, at] of this.#seen) if (this.d.now - at > WINDOW_S) this.#seen.delete(id);
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
        g.client = from; g.connectedAt = now; g.linkExpires = null; this.d.persist();
        // Best effort: the site is answered whether or not the watching server is reachable (review 11 M3).
        this.watchSet().catch(() => { this.watchPending = true; });
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
          siteGuard({ kind: ev?.kind, tags: Array.isArray(ev?.tags) ? ev.tags : [] }, this.d.g, this.#backupKeys());
          try { return { result: JSON.stringify(await this.d.sign(ev)) }; }
          catch (err) {
            // Held (Doors §3.3, Device policy §4, review 11 L4): kept on this home for the person, who
            // approves it with the lock or lets a hold's wait pass; the result is published, not returned.
            if ((err as KeykinError).code !== 'needs_approval') throw err;
            const h = { id: bytesToHex(randomBytes(8)), signer: g.signer, event: siteEvent({ ...ev, created_at: ev?.created_at ?? now }, this.d.g), at: now, wait: null as string | null };
            this.held.set(h.id, h); this.d.persist();
            return { error: 'held: approve on your phone' };
          }
        }
        case 'nip44_encrypt': return { result: await this.d.nip44(String(params[0]), String(params[1]), true) };
        case 'nip44_decrypt': siteMayDecrypt(String(params[0]), this.d.g); return { result: await this.d.nip44(String(params[0]), String(params[1]), false) };
        case 'nip04_encrypt': return { result: await this.d.nip04(String(params[0]), String(params[1]), true) };
        case 'nip04_decrypt': siteMayDecrypt(String(params[0]), this.d.g); return { result: await this.d.nip04(String(params[0]), String(params[1]), false) };
        default: return { error: `unsupported: ${method}` };
      }
    } catch (err) {
      const code = (err as KeykinError).code;
      if (code === 'needs_approval' || code === 'hold_not_passed') return { error: 'held: approve on your phone' };
      if (code === 'declined') return { error: `declined: ${(err as Error).message.replace(/^declined: /, '') || 'not allowed for this site'}` };
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
  // --- held events (Doors §3.3, Device policy §4) ----------------------------------------------
  /** Site events waiting for the person: shown on the home, approved with the lock or by a hold. */
  held = new Map<string, { id: string; signer: string; event: any; at: number; wait: string | null }>();
  /** Approve with the lock: sign it unchanged, and publish it to the grant's relays and the account's. */
  async approveHeld(id: string): Promise<NostrEvent> {
    const h = this.held.get(id); if (!h) throw new KeykinError('unknown_held');
    const { id: _id, ...ev } = h.event;
    const evId = h.event.id;
    if (!this.d.lock) throw new KeykinError('needs_approval', 'this device has no lock: start a hold instead');
    const signed = await this.d.sign(ev, { approval: { lock: { member: this.d.kp.pub, assertion: this.d.lock.assert(this.d.g, what.sign(evId)) } } as any });
    await this.#publishHeld(h, signed);
    return signed;
  }
  /** Lockless: start a hold at every server (core §5.8); `releaseHeld` once its wait has passed. */
  async holdHeld(id: string): Promise<string> {
    const h = this.held.get(id); if (!h) throw new KeykinError('unknown_held');
    let wait: string | null = null;
    for (const s of this.d.servers()) {
      const a = await this.d.bus.send(this.d.kp, s.key, msg('hold', this.d.g, this.d.epochId, 'member', { event: h.event }));
      if (a?.kind === 'hold') wait = a.wait;
    }
    if (!wait) throw new KeykinError('no_server', 'no server started the hold');
    h.wait = wait; this.d.persist();
    return wait;
  }
  async releaseHeld(id: string): Promise<NostrEvent> {
    const h = this.held.get(id); if (!h?.wait) throw new KeykinError('unknown_held');
    const { id: _id, ...ev } = h.event;
    const signed = await this.d.sign(ev, { hold: h.wait });
    await this.#publishHeld(h, signed);
    return signed;
  }
  declineHeld(id: string) { this.held.delete(id); this.d.persist(); }
  async #publishHeld(h: { id: string; signer: string }, signed: NostrEvent) {
    const g = this.grants.get(h.signer);
    await this.#events.publishEvent(signed, [...new Set([...(g?.relays ?? []), ...(this.d.rec?.relays ?? [])])]);
    this.held.delete(h.id); this.d.persist();
  }

  /** A watch_set that didn't reach its server; sent again on the next wake. */
  watchPending = false;
  /** Ask `server` (a seated server's member key) to watch this home's grants; or re-send the set. */
  async watchSet(server = this.watching) {
    if (!server) return;
    this.watching = server;
    const grants = [...this.grants.values()].filter((g) => !g.endedAt).map((g) => ({ signer: g.signer, client: g.client, relays: g.relays }));
    const a = await this.d.bus.send(this.d.kp, server, msg('watch_set', this.d.g, this.d.epochId, 'ask', { grants }));
    if (a?.type !== 'ack') { this.watchPending = true; throw new KeykinError(a?.code ?? 'watch_set_failed'); }
    this.watchPending = false;
    this.d.persist();
  }
  /** Woken (a push, or the app opened): drain every site request the watching server kept. Returns how
   *  many it answered now (one it answered while awake is skipped, and acknowledged all the same). */
  async wake(): Promise<number> {
    if (!this.watching) return 0;
    if (this.watchPending) await this.watchSet().catch(() => {});
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

  /** Every backup key the account has had: the signpost names come from them. */
  #backupKeys() { const m = this.d.m!; return [...new Set([m.backupKey, ...m.accepted.filter((p) => p.type === 'paper').map((p) => (p.c.change as any).paper.key)].filter(Boolean) as string[])]; }

  dump() { return { grants: [...this.grants.values()], watching: this.watching, seen: [...this.#seen], held: [...this.held.values()] }; }
  load(x: any) {
    this.grants = new Map((x?.grants ?? []).map((g: Grant) => [g.signer, g])); this.watching = x?.watching ?? null; this.#seen = new Map(x?.seen ?? []);
    this.held = new Map((x?.held ?? []).map((h: any) => [h.id, h]));
  }
}
export { pubOf };
