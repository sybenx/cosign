// A device's own NIP-46 front: each site gets a signer key of its own, and only the user's
// devices hold it (COSIGN.md §6.1). A site encrypts its requests to that key, so whoever
// holds it reads them — DM text included. Servers run by anyone else never get it: they
// only see that *something* was sent to it (the event's `p` tag), which is enough to wake a
// phone by push and nothing more.
//
// No I/O of its own, like ./group.ts: the device hands it what it needs. The reference is
// this file; the Android library's `Bunker.kt` follows it, and test/fake-phone.ts runs it.
//
// The device is the coordinator for everything a site asks (§5.1): `sign` and `ecdh` are
// its own rounds with one of the servers, under the site's grant, exactly as for an app on
// the phone (NIP-55). This file only speaks NIP-46.

import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { cbc } from '@noble/ciphers/aes.js';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { KIND_NIP46, normRelay } from './seal.ts';

/** One site's mailbox: its own signer key, and what it may do. */
export interface SiteKey {
  /** The signer key's secret. Never leaves the user's devices (and a server the user runs). */
  sk: string;
  /** Its public half: what the site writes to, and what servers watch to wake a device. */
  pk: string;
  /** Where it was opened from, as the person saw it. */
  origin: string;
  /** Relays this mailbox is read on: the account's, and a nostrconnect site's own. */
  relays: string[];
  /** The site's own key, once it has connected. Its grant, on the servers. */
  client?: string;
  /** A ticket not yet redeemed: its secret and when it stops working. */
  t?: string;
  expires?: number;
  /** May it read and send messages? Undefined until the person has been asked. */
  dm?: boolean;
  added: number;
  /** Which device made it. Another device that holds a copy answers only if this one doesn't. */
  by: string;
  /** Signed out or removed (when): kept a day, so the site hears "revoked" rather than nothing. */
  revoked?: number;
}

export interface BunkerDeps {
  /** The account's public key (x only). */
  groupX: () => string;
  /** The account's relays. */
  relays: () => string[];
  /** This device's member key, as `SiteKey.by`. */
  me: string;
  /** Sign an event for this grant: the device's round with a server. Throws with a reason. */
  sign: (grant: string, ev: { kind: number; created_at: number; tags: string[][]; content: string; pubkey: string }) => Promise<Event>;
  /** The shared x-coordinate with a peer, from the device's shares and a server's. */
  ecdh: (grant: string, peerX: string) => Promise<Uint8Array>;
  /** Ask the person once: may this site read and send messages? */
  askDms: (origin: string) => Promise<boolean>;
  /** A site has connected: tell the servers, so they co-sign for it and watch its mailbox. */
  granted: (k: SiteKey) => void;
  /** A site signed out: the grant goes everywhere. */
  revoked: (k: SiteKey) => void;
  /** The mailboxes changed: save them, subscribe again, and hand copies to other devices. */
  changed: () => void;
  publish: (e: Event) => void;
  now?: () => number;
  log?: (t: string) => void;
}

const HEX32 = /^[0-9a-f]{64}$/;
const relayOk = (r: unknown): r is string => typeof r === 'string' && /^wss?:\/\/\S+$/.test(r) && r.length < 200;

export class Bunker {
  keys: SiteKey[];
  private answers = new Map<string, { at: number; body: string; scheme: 'nip44' | 'nip04'; key: string }>();
  private working = new Set<string>();
  /** Requests another device already answered: seen on the relay, from the same mailbox. */
  private answeredElsewhere = new Set<string>();
  private now: () => number;
  private d: BunkerDeps;

  constructor(keys: SiteKey[], d: BunkerDeps) {
    this.keys = keys;
    this.d = d;
    this.now = d.now ?? (() => Math.floor(Date.now() / 1000));
  }

  // --- Opening a mailbox --------------------------------------------------------------

  /** A sign-in code (QRST `signer-ticket`): a new mailbox, and the ticket that opens it once. */
  ticket(origin: string, ttl = 900): { signer: string; relays: string[]; t: string; expires: number } {
    const sk = bytesToHex(randomBytes(32));
    const k: SiteKey = { sk, pk: getPublicKey(hexToBytes(sk)), origin: origin.slice(0, 200), relays: this.d.relays().map(normRelay), t: bytesToHex(randomBytes(16)), expires: this.now() + ttl, added: this.now(), by: this.d.me };
    this.keys.push(k);
    this.tidy();
    this.d.changed();
    return { signer: k.pk, relays: k.relays, t: k.t!, expires: k.expires! };
  }

  /**
   * A nostrconnect:// code a device scanned: the site named its key, its relays and a secret.
   * The device answers it straight away, from a new mailbox of the site's own.
   */
  nostrconnect(uri: string, origin: string): SiteKey | null {
    let u: URL;
    try { u = new URL(uri.replace(/^nostrconnect:(?!\/\/)/, 'nostrconnect://')); } catch { return null; }
    const client = (u.host || u.pathname.replace(/^\/+/, '')).toLowerCase();
    const relays = [...new Set(u.searchParams.getAll('relay').filter(relayOk).map(normRelay))].slice(0, 4);
    const secret = u.searchParams.get('secret');
    if (u.protocol !== 'nostrconnect:' || !HEX32.test(client) || !relays.length || !secret) return null;
    const had = this.keys.find(k => k.client === client);
    if (had) { // scanned again: that's you letting it back in, so say hello again
      if (had.revoked) { delete had.revoked; this.d.granted(had); this.d.changed(); }
      this.connectReply(had, secret);
      return had;
    }
    const sk = bytesToHex(randomBytes(32));
    const k: SiteKey = { sk, pk: getPublicKey(hexToBytes(sk)), origin: origin.slice(0, 200), relays: [...new Set([...relays, ...this.d.relays().map(normRelay)])], client, added: this.now(), by: this.d.me };
    this.keys.push(k);
    this.d.granted(k);
    this.d.changed();
    this.connectReply(k, secret);
    return k;
  }

  /** NIP-46's answer to a nostrconnect code: the secret back, from the new mailbox, twice. */
  private connectReply(k: SiteKey, secret: string) {
    const body = JSON.stringify({ id: bytesToHex(randomBytes(8)), result: secret });
    this.reply(k, k.client!, 'nip44', body);
    setTimeout(() => this.reply(k, k.client!, 'nip44', body), 3000);
  }

  /** A copy from another of the user's devices (sealed to this one). */
  adopt(k: SiteKey): boolean {
    if (!HEX32.test(k?.sk ?? '') || getPublicKey(hexToBytes(k.sk)) !== k.pk || this.keys.some(x => x.pk === k.pk)) return false;
    this.keys.push({ ...k, relays: (k.relays ?? []).filter(relayOk).map(normRelay).slice(0, 8) });
    this.d.changed();
    return true;
  }

  /** The person removed a site (anywhere): its mailbox goes, here and on every device. */
  forget(client: string) {
    let changed = false;
    for (const k of this.keys) if (k.client === client && !k.revoked) { k.revoked = this.now(); delete k.dm; changed = true; }
    if (changed) { this.tidy(); this.d.changed(); }
  }

  /** Unredeemed tickets go an hour past their expiry; a revoked mailbox, a day after. */
  private tidy() {
    const t = this.now();
    this.keys = this.keys.filter(k => k.revoked ? k.revoked > t - 86_400 : k.client || (k.expires ?? 0) > t - 3600);
  }

  /** The mailboxes to read: kind 24133 to them, and their replies, so a copy can tell another device answered. */
  filters() {
    const pks = this.keys.map(k => k.pk);
    return pks.length ? [{ kinds: [KIND_NIP46], '#p': pks }, { kinds: [KIND_NIP46], authors: pks }] : [];
  }

  /** Every relay any mailbox is read on. */
  relays(): string[] { return [...new Set(this.keys.flatMap(k => k.relays))]; }

  // --- Answering ---------------------------------------------------------------------

  /** A kind 24133 event on one of the mailboxes' relays. */
  async onEvent(e: Event) {
    if (e.kind !== KIND_NIP46 || this.now() - e.created_at > 30) return; // relays replay old requests
    // One of the mailboxes answering: another device got there. Note which request.
    const from = this.keys.find(k => k.pk === e.pubkey);
    if (from) {
      const to = e.tags.find(t => t[0] === 'p')?.[1];
      const body = to ? this.open(from, to, e.content) : null;
      if (body?.req?.id) this.answeredElsewhere.add(`${to}:${body.req.id}`);
      return;
    }
    const to = e.tags.filter(t => t[0] === 'p').map(t => t[1]);
    const k = this.keys.find(x => to.includes(x.pk));
    if (!k) return;
    const opened = this.open(k, e.pubkey, e.content);
    if (!opened?.req?.id || typeof opened.req.method !== 'string') return;
    const { req, scheme } = opened;
    const key = `${e.pubkey}:${req.id}`;
    const cached = this.answers.get(key);
    if (cached) return this.reply(k, e.pubkey, cached.scheme, cached.body);
    if (this.working.has(key)) return;
    // A copy of another device's mailbox waits a moment for that device, which normally answers.
    if (k.by !== this.d.me) {
      await new Promise(r => setTimeout(r, 2500));
      if (this.answeredElsewhere.has(key) || this.answers.has(key)) return;
    }
    this.working.add(key);
    const answer = (body: object) => {
      const text = JSON.stringify({ id: req.id, ...body });
      this.answers.set(key, { at: Date.now(), body: text, scheme, key: k.pk });
      this.working.delete(key);
      this.reply(k, e.pubkey, scheme, text);
      // Most sites ask once and never again, so a lost answer leaves them hanging. Say it twice.
      setTimeout(() => this.reply(k, e.pubkey, scheme, text), 3000);
      for (const [x, v] of this.answers) if (Date.now() - v.at > 120_000) this.answers.delete(x);
    };
    try { answer(await this.handle(k, e.pubkey, req)); }
    catch (err: any) { answer({ error: err?.message ?? String(err) }); }
  }

  private async handle(k: SiteKey, client: string, req: { method: string; params?: unknown[] }): Promise<object> {
    const p = (req.params ?? []).map(x => String(x));
    if (k.revoked) return { error: 'revoked: Access for this site was removed. Connect it again from your phone.' };
    if (req.method === 'connect') {
      if (k.client) return k.client === client ? { result: 'ack' } : { error: 'bad-ticket: This code was already used by another site. Scan a new one.' };
      if (!k.t || p[1] !== k.t || (k.expires ?? 0) < this.now()) return { error: 'bad-ticket: This ticket is not valid. Scan the code again with your phone.' };
      k.client = client; delete k.t; delete k.expires;
      this.d.granted(k);
      this.d.changed();
      this.d.log?.(`${k.origin} connected`);
      return { result: 'ack' };
    }
    if (req.method === 'ping') return { result: 'pong' };
    if (k.client !== client) return { error: 'not-connected: Not connected. Scan this site’s code with your phone.' };
    switch (req.method) {
      case 'logout': {
        k.revoked = this.now(); delete k.dm;
        this.d.revoked(k);
        this.d.changed();
        return { result: 'ack' };
      }
      case 'get_public_key': return { result: this.d.groupX() };
      // Move the site onto the relays this mailbox is read on.
      case 'switch_relays': return { result: JSON.stringify(k.relays) };
      case 'get_relays': return { result: JSON.stringify(Object.fromEntries(k.relays.map(r => [r, { read: true, write: true }]))) };
      case 'sign_event': {
        const t = JSON.parse(p[0] ?? '{}');
        if (!Number.isInteger(t.kind) || typeof t.content !== 'string' || !Array.isArray(t.tags)) return { error: 'bad event' };
        const ev = { kind: t.kind, created_at: Number.isInteger(t.created_at) ? t.created_at : this.now(), tags: t.tags.map((x: unknown[]) => x.map(String)), content: t.content, pubkey: this.d.groupX() };
        return { result: JSON.stringify(await this.d.sign(client, ev)) };
      }
      case 'nip44_encrypt': case 'nip44_decrypt': case 'nip04_encrypt': case 'nip04_decrypt': {
        if (!HEX32.test(p[0] ?? '')) return { error: 'bad peer' };
        if (k.dm === undefined) { k.dm = await this.d.askDms(k.origin); this.d.changed(); }
        if (!k.dm) return { error: 'not-allowed: You didn’t let this site read or send your messages.' };
        const x = await this.d.ecdh(client, p[0]);
        if (req.method.startsWith('nip44')) {
          const ck = extract(sha256, x, utf8ToBytes('nip44-v2'));
          return { result: req.method === 'nip44_encrypt' ? nip44.v2.encrypt(p[1] ?? '', ck) : nip44.v2.decrypt(p[1] ?? '', ck) };
        }
        return { result: aes(x, p[1] ?? '', req.method === 'nip04_decrypt') };
      }
      default: return { error: `unsupported method ${req.method}` };
    }
  }

  // --- The wire ----------------------------------------------------------------------

  /** A request (or another device's answer) in either encryption a NIP-46 client may use. */
  private open(k: SiteKey, other: string, content: string): { req: any; scheme: 'nip44' | 'nip04' } | null {
    const sk = hexToBytes(k.sk);
    try { return { req: JSON.parse(nip44.v2.decrypt(content, nip44.v2.utils.getConversationKey(sk, other))), scheme: 'nip44' }; } catch {}
    try { return { req: JSON.parse(nip04.decrypt(sk, other, content)), scheme: 'nip04' }; } catch {}
    return null;
  }

  private reply(k: SiteKey, client: string, scheme: 'nip44' | 'nip04', body: string) {
    const sk = hexToBytes(k.sk);
    const content = scheme === 'nip44' ? nip44.v2.encrypt(body, nip44.v2.utils.getConversationKey(sk, client)) : nip04.encrypt(sk, client, body);
    this.d.publish(finalizeEvent({ kind: KIND_NIP46, created_at: this.now(), tags: [['p', client]], content }, sk));
  }
}

/** NIP-04's AES-CBC, on a shared x the device finished itself. */
function aes(key: Uint8Array, text: string, decrypt: boolean): string {
  const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
  const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  if (decrypt) { const [ct, iv] = text.split('?iv='); return new TextDecoder().decode(cbc(key, unb64(iv)).decrypt(unb64(ct))); }
  const iv = randomBytes(16);
  return b64(cbc(key, iv).encrypt(new TextEncoder().encode(text))) + '?iv=' + b64(iv);
}
