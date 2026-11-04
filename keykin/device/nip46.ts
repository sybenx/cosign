// NIP-46 at its home (Doors §3.3): per-site signer keys that never leave the device that connected the
// site, `bunker://` links and `nostrconnect://` codes, the methods, and the wake path: the home tells one
// watching server its grants (`watch_set`), that server leaves sites' requests in the home's inbox and
// pushes once per burst, and a woken home drains them and answers. Any of the person's devices can be a
// home (the user's decision, 2026-11-03); a phone wakes on push.
//
// The signer key is an ordinary key used only as a mailbox; what a site asks of the account goes through
// the device: `sign_event` through a signing round, encryption through ECDH with a co-signer (core §5.5).
// Scopes are the Doors module's §1–§2; every event a site asks for is judged by Device policy §2 (device/policy.ts)
// first: Silent, a Confirm card on this home, a single deletion's 10-second Undo, or Held (answered `held:`).

import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { finalizeEvent, verifyEvent as ntVerify } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes, randomBytes, strictJson, KeykinError } from '../src/bytes.ts';
import { newKey, pubOf, siteEvent, type NostrEvent } from '../src/event.ts';
import { what } from '../src/codes.ts';
import { msg } from '../src/msg.ts';
import { unwrap } from '../src/transport.ts';
import type { DeviceNode } from './node.ts';
import { siteGuard } from './doors.ts';
import { scopesForEvent, scopeForDecrypt, expired, type Scope } from './grants.ts';

export const KIND_NIP46 = 24133;
/** Doors §2: a home answers sites only on news at most this old. */
const FRESH_S = 30;
const LINK_S = 600, ENDED_KEEP_S = 30 * 86400, WINDOW_S = 120;
const HELD_PER_GRANT = 8, HELD_MAX = 64, HELD_TTL_S = 7 * 86400;
/** A replaceable or addressable event's list: kind, and `d` for addressable kinds. */
export const listKey = (e: any): string | null => {
  const k = e?.kind;
  if (!Number.isSafeInteger(k)) return null;
  if (k === 0 || k === 3 || (k >= 10000 && k < 20000)) return `${k}`;
  if (k >= 30000 && k < 40000) return `${k}:${(e.tags ?? []).find((t: string[]) => t[0] === 'd')?.[1] ?? ''}`;
  return null;
};

export interface Grant {
  signer: string; signerSk: string; client: string | null; secret: string | null; linkExpires: number | null;
  relays: string[]; site: string; connectedAt: number | null; endedAt: number | null;
  /** The grant store's entry once a client is bound (Doors §1: its scopes, its sync), and what the link offered. */
  entry?: string; offered?: Scope[];
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

  /** Scopes a site asked for and the person hasn't answered yet, by signer: shown on the home. */
  asks = new Map<string, Set<Scope>>();
  /** The person allowed `scope` for a site (Doors §1: asked the first time it is needed). */
  allowScope(signer: string, scope: Scope) {
    const g = this.grants.get(signer); if (!g?.entry) throw new KeykinError('unknown_grant');
    this.d.grants.widen(g.entry, [scope]); this.asks.get(signer)?.delete(scope); this.d.persist(); this.d.publishGrantsSoon();
  }
  #bind(g: Grant, client: string) {
    g.client = client; g.connectedAt = this.d.now;
    g.entry = this.d.grants.make({ site: client, says: g.site, door: 'nip46', connection: client, relays: g.relays, signer: g.signer, scopes: g.offered ?? ['sign-in', 'post'] }).id;
    this.d.publishGrantsSoon();
  }
  #has(g: Grant, scope: Scope): boolean {
    const e = g.entry ? this.d.grants.own.get(g.entry) : undefined;
    // An expired grant grants nothing (review 16 M4).
    if (e && e.scopes.includes(scope) && !expired(e, this.d.now, this.d.grants.lastUsed.get(e.id))) { this.d.grants.used(e.id); return true; }
    const a = this.asks.get(g.signer) ?? new Set<Scope>(); a.add(scope); this.asks.set(g.signer, a); this.d.persist();
    return false;
  }
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
  mintBunker(relays: string[], site = '', scopes: Scope[] = ['sign-in', 'post']): string {
    const g = this.#grant(relays, site, { secret: bytesToHex(randomBytes(16)), linkExpires: this.d.now + LINK_S, offered: scopes });
    return `bunker://${g.signer}?${relays.map((r) => `relay=${encodeURIComponent(r)}`).join('&')}&secret=${g.secret}`;
  }
  /** A scanned `nostrconnect://` code: the grant is bound to the code's client, and the `connect` reply
   *  carries the code's secret, as clients check it. */
  async acceptNostrconnect(uri: string, scopes: Scope[] = ['sign-in', 'post']): Promise<Grant> {
    const c = parseNostrconnect(uri);
    const g = this.#grant(c.relays, c.name, { offered: scopes });
    this.#bind(g, c.client); this.d.persist();
    await this.#reply(g, c.client, { id: bytesToHex(randomBytes(8)), result: c.secret ?? 'ack' });
    await this.watchSet().catch(() => {});
    return g;
  }
  /** End a grant: its key answers `revoked:` for 30 days, then is forgotten. */
  async end(signer: string) {
    const g = this.grants.get(signer); if (!g) return;
    g.endedAt = this.d.now;
    if (g.entry) { this.d.grants.end(this.d.kp.pub, g.entry); this.d.publishGrantsSoon(); }
    this.asks.delete(signer);
    // Its held events go with it: nothing a site asked for is signed after it was disconnected (review 12 H1).
    for (const [k, h] of this.held) if (h.signer === signer) this.held.delete(k);
    this.d.persist(); await this.watchSet().catch(() => {});
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
    this.answeredCount++;
    return true;
  }

  async #answer(g: Grant, from: string, method: string, params: any[]): Promise<{ result?: string; error?: string }> {
    const now = this.d.now;
    if (g.endedAt) return { error: 'revoked: this site was disconnected' };
    if (method === 'connect') {
      // A link's secret binds to the first client key; that same key may connect again, any other is refused.
      if (g.client === null) {
        if (!g.secret || params[1] !== g.secret || g.linkExpires === null || now > g.linkExpires) return { error: 'not-connected: this link has expired or is wrong; mint a new one' };
        this.#bind(g, from); g.linkExpires = null; this.d.persist();
        // Best effort: the site is answered whether or not the watching server is reachable (review 11 M3).
        this.watchSet().catch(() => { this.watchPending = true; });
        return { result: 'ack' };
      }
      return from === g.client ? { result: 'ack' } : { error: 'not-connected: this link belongs to another client; mint a new one' };
    }
    if (from !== g.client) return { error: 'not-connected: connect first' };
    // Doors §1: each request needs its scope; one the site wasn't granted is asked on this home, once.
    const ask = (scope: Scope) => ({ error: `permission: ${scope} needs your OK on your phone` });
    // Doors §2: never on old news. A home that hasn't caught up within 30 seconds does first (a site signed out
    // elsewhere is then refused here).
    if (method !== 'ping' && this.d.now - this.d.lastFetchAt > FRESH_S) { try { await this.d.fetch(); } catch { /* answers what needs no round */ } }
    // A grant ended on another device (a tombstone, a removal) ends here too.
    if (g.entry && !this.d.grants.own.has(g.entry)) { await this.end(g.signer); return { error: 'revoked: this site was disconnected' }; }
    try {
      switch (method) {
        case 'ping': return { result: 'pong' };
        case 'get_public_key': return this.#has(g, 'sign-in') ? { result: this.d.g } : ask('sign-in');
        case 'get_relays': return { result: JSON.stringify(Object.fromEntries(g.relays.map((r) => [r, { read: true, write: true }]))) };
        case 'switch_relays': return { result: JSON.stringify(g.relays) };
        case 'logout': await this.end(g.signer); return { result: 'ack' };
        case 'sign_event': {
          const ev = strictJson(String(params[0]));
          siteGuard({ kind: ev?.kind, tags: Array.isArray(ev?.tags) ? ev.tags : [] }, this.d.g, this.#backupKeys(), this.d.protectedIds);
          const needs = scopesForEvent(Number(ev?.kind), Array.isArray(ev?.tags) ? ev.tags : [], null);
          if (needs === 'declined') return { error: 'declined: a deletion by token, or a token for no host, is never a site\'s to get signed' };
          for (const n of needs) if (!this.#has(g, n)) return ask(n);
          // Device policy §4: while a hold for this list is pending, this site's changes to it wait (review 12 H3).
          const lk = listKey(ev);
          if (lk && [...this.held.values()].some((x) => x.wait && x.signer === g.signer && listKey(x.event) === lk)) return { error: 'try-later: a held change to this list is waiting' };
          // Device policy §2: judged first. A Confirm waits for the person's answer on this home, a single deletion
          // 10 seconds for an Undo; Held goes to the person at once.
          const owner = `${this.d.kp.pub}:${g.entry}`;
          const event = siteEvent({ ...ev, created_at: ev?.created_at ?? now }, this.d.g);
          const gate = await this.d.guard.gate(event, owner, (g.entry ? this.d.grants.own.get(g.entry)?.scopes : undefined) ?? []);
          if ('error' in gate) return { error: gate.error };
          let held = gate.ok === 'held';
          // Signed for this grant: the evidence records who got each ciphertext signed (review 17 M1).
          if (!held) try { return { result: JSON.stringify(await this.d.sign(event, { owner })) }; }
          catch (err) {
            if ((err as KeykinError).code !== 'needs_approval') throw err;
            // A server's demand the device's own check doesn't explain: Held only when two servers demand it (§2).
            if (((err as any).demands ?? 0) < 2) return { error: 'try-later: a server asked for an approval; try again later' };
            held = true;
          }
          {
            // Held (Doors §3.3, Device policy §4, review 11 L4): kept on this home for the person, who
            // approves it with the lock or lets a hold's wait pass; the result is published, not returned.
            this.#expireHeld();
            // One entry per event, at most 8 per site and 64 in all (review 12 H2).
            if (![...this.held.values()].some((x) => x.event.id === event.id)) {
              if ([...this.held.values()].filter((x) => x.signer === g.signer).length >= HELD_PER_GRANT || this.held.size >= HELD_MAX) return { error: 'try-later: too many events waiting for you' };
              const h = { id: event.id, signer: g.signer, event, at: now, wait: null as string | null };
              this.held.set(h.id, h); this.d.persist();
            }
            return { error: 'held: approve on your phone' };
          }
        }
        case 'nip44_encrypt': case 'nip04_encrypt': {
          // Encrypting to the account's own key is `post`; to anyone else, `dms`.
          const peer = String(params[0]);
          if (!this.#has(g, peer.toLowerCase() === this.d.g ? 'post' : 'dms')) return ask(peer.toLowerCase() === this.d.g ? 'post' : 'dms');
          // At most 300 encryptions to self an hour per site: each becomes a metadata record (review 17 H2).
          if (peer.toLowerCase() === this.d.g && !this.#budget(g.signer)) return { error: 'try-later: too many encryptions; wait a while' };
          // An encryption to self is recorded for this grant: evidence for its later decrypts (Device policy §1).
          return { result: method === 'nip44_encrypt' ? await this.d.nip44(peer, String(params[1]), true, { owner: `${this.d.kp.pub}:${g.entry}` }) : await this.d.nip04(peer, String(params[1]), true) };
        }
        case 'nip44_decrypt': case 'nip04_decrypt': {
          const peer = String(params[0]);
          if (!/^[0-9a-fA-F]{64}$/.test(peer)) return { error: 'declined: a peer key is 32 bytes of hex' };
          // With someone else's key, `dms`. To the account itself: decrypted here first, released only under the
          // scope its plaintext needs (lists, wallet, dms for its own NIP-17 copies, private-data otherwise).
          if (peer.toLowerCase() !== this.d.g) {
            if (!this.#has(g, 'dms')) return ask('dms');
            return { result: method === 'nip44_decrypt' ? await this.d.nip44(peer, String(params[1]), false) : await this.d.nip04(peer, String(params[1]), false) };
          }
          // A grant holding none of the to-self scopes is refused before any round (review 16 M9).
          const e = g.entry ? this.d.grants.own.get(g.entry) : undefined;
          if (!e?.scopes.some((x) => ['lists', 'wallet', 'private-data', 'dms'].includes(x))) { this.#has(g, 'private-data'); return { error: 'permission: needs your OK on your phone' }; }
          const plain = method === 'nip44_decrypt' ? await this.d.nip44(this.d.g, String(params[1]), false) : await this.d.nip04(this.d.g, String(params[1]), false);
          const need = scopeForDecrypt(this.d.g, peer.toLowerCase(), plain, method === 'nip44_decrypt' ? { payload: String(params[1]), evidence: this.d.evidence, owner: `${this.d.kp.pub}:${g.entry}` } : {});
          if (need === 'malformed') return { error: 'declined: not a canonical payload' };
          // One message for every class, so a refusal never says what the ciphertext is (review 16 M9).
          return this.#has(g, need) ? { result: plain } : { error: 'permission: needs your OK on your phone' };
        }
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
  /** A held event of a live grant, or refused; one a newer version of its list overtook is dropped. */
  #heldLive(id: string) {
    this.#expireHeld();
    const h = this.held.get(id); if (!h) throw new KeykinError('unknown_held');
    const g = this.grants.get(h.signer);
    if (!g || g.endedAt) { this.held.delete(id); this.d.persist(); throw new KeykinError('revoked', 'the site was disconnected'); }
    // Device policy §4: a newer version of the same list exists, so the held one is dropped, never published.
    const lk = listKey(h.event), newer = lk ? this.d.latestList(lk) : 0;
    if (lk && newer > h.event.created_at) {
      this.held.delete(id); this.d.notices.push({ kind: 'held_dropped', member: h.signer }); this.d.persist();
      throw new KeykinError('superseded', 'the list changed since: the held change was dropped');
    }
    return h;
  }
  #expireHeld() { for (const [k, h] of this.held) if (this.d.now - h.at > HELD_TTL_S) this.held.delete(k); }
  async approveHeld(id: string): Promise<NostrEvent> {
    const h = this.#heldLive(id);
    const { id: _id, ...ev } = h.event;
    const evId = h.event.id;
    if (!this.d.lock) throw new KeykinError('needs_approval', 'this device has no lock: start a hold instead');
    const signed = await this.d.sign(ev, { approval: { lock: { member: this.d.kp.pub, assertion: this.d.lock.assert(this.d.g, what.sign(evId)) } } as any, owner: this.#ownerOf(h.signer) });
    await this.#publishHeld(h, signed);
    return signed;
  }
  /** Lockless: start a hold at every server (core §5.8); `releaseHeld` once its wait has passed. */
  async holdHeld(id: string): Promise<string> {
    const h = this.#heldLive(id);
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
    const h = this.#heldLive(id); if (!h.wait) throw new KeykinError('unknown_held', 'no hold was started');
    const { id: _id, ...ev } = h.event;
    const signed = await this.d.sign(ev, { hold: h.wait, owner: this.#ownerOf(h.signer) });
    await this.#publishHeld(h, signed);
    return signed;
  }
  /** The person declined a held event: it counts as a decline of that site (Device policy §6). */
  declineHeld(id: string) { const h = this.held.get(id); if (h) this.d.guard.declinedBy(this.#ownerOf(h.signer), 'core'); this.held.delete(id); this.d.persist(); }
  #ownerOf(signer: string) { return `${this.d.kp.pub}:${this.grants.get(signer)?.entry}`; }
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
    // A catch-up first (Doors §2: grants' ends before any answer), which also answers what the watching server
    // kept; then anything it kept that the catch-up didn't reach. Returns how many requests were answered.
    const before = this.answeredCount;
    await this.d.fetch();
    const inbox = await this.d.bus.send(this.d.kp, this.watching, msg('inbox_get', this.d.g, this.d.epochId, 'ask'));
    const done: string[] = [];
    for (const it of inbox?.items ?? []) {
      let o; try { o = unwrap(this.d.kp.sk, it.wrap); } catch { continue; }
      if (o.from !== this.watching || o.body?.type !== 'nip46') continue;
      await this.handle(o.body.event);
      done.push(it.iid);
    }
    if (done.length) await this.d.bus.send(this.d.kp, this.watching, msg('inbox_ack', this.d.g, this.d.epochId, 'ask', { iids: done }));
    return this.answeredCount - before;
  }
  #crypt = new Map<string, number[]>();
  #budget(signer: string): boolean {
    const q = (this.#crypt.get(signer) ?? []).filter((t) => this.d.now - t < 3600);
    if (q.length >= 300) { this.#crypt.set(signer, q); return false; }
    q.push(this.d.now); this.#crypt.set(signer, q); return true;
  }
  /** Requests this home answered (for `wake`). */
  answeredCount = 0;

  /** Every backup key the account has had: the signpost names come from them. */
  #backupKeys() { const m = this.d.m!; return [...new Set([m.backupKey, ...m.accepted.filter((p) => p.type === 'paper').map((p) => (p.c.change as any).paper.key)].filter(Boolean) as string[])]; }

  dump() { return { grants: [...this.grants.values()], watching: this.watching, seen: [...this.#seen], held: [...this.held.values()], asks: [...this.asks].map(([k, v]) => [k, [...v]]) }; }
  load(x: any) {
    this.grants = new Map((x?.grants ?? []).map((g: Grant) => [g.signer, g])); this.asks = new Map((x?.asks ?? []).map(([k, v]: [string, Scope[]]) => [k, new Set(v)])); this.watching = x?.watching ?? null; this.#seen = new Map(x?.seen ?? []);
    this.held = new Map((x?.held ?? []).map((h: any) => [h.id, h]));
  }
}
export { pubOf };
