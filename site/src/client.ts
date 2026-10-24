// The site's side of signing: NIP-46 to your signer, over relays, made to survive them.
//
// A request is published to every relay at once and published again, freshly
// wrapped, until the answer arrives. The signer keeps its answers and sends them again
// to a repeat, so a dropped event in either direction costs a retry, not a timeout.

import { Relay } from 'nostr-tools/relay';
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent, type Event, type EventTemplate } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export const KIND_NIP46 = 24133;

export interface Session {
  /** This site's own key. Its access is what your phone can remove. */
  sk: string;
  /** The key your servers answer as. */
  signer: string;
  /** Relays your servers listen on. */
  relays: string[];
  /** Who you sign as, once known. */
  pubkey?: string;
}

export function newSession(signer: string, relays: string[]): Session {
  return { sk: bytesToHex(generateSecretKey()), signer, relays };
}

const now = () => Math.floor(Date.now() / 1000);

export class SignerClient {
  private conns = new Map<string, Relay | null>();
  private waiting = new Map<string, (r: { result?: string; error?: string }) => void>();
  private seen = new Set<string>();
  private closed = false;
  private readonly key: Uint8Array;
  private readonly me: string;
  private readonly ck: Uint8Array;
  /** Relay connection changes, for a status line. */
  onStatus: (up: number, of: number) => void = () => {};

  readonly session: Session;

  constructor(session: Session) {
    this.session = session;
    this.key = hexToBytes(session.sk);
    this.me = getPublicKey(this.key);
    this.ck = nip44.v2.utils.getConversationKey(this.key, session.signer);
    for (const url of session.relays) void this.open(url);
  }

  private async open(url: string) {
    if (this.closed) return;
    this.conns.set(url, null);
    try {
      const r = await Relay.connect(url);
      r.onclose = () => { this.conns.set(url, null); this.status(); if (!this.closed) setTimeout(() => this.open(url), 3000); };
      this.conns.set(url, r);
      r.subscribe([{ kinds: [KIND_NIP46], '#p': [this.me], authors: [this.session.signer], since: now() - 30 }], {
        onevent: (e: Event) => this.receive(e),
      });
      this.status();
    } catch {
      if (!this.closed) setTimeout(() => this.open(url), 3000);
    }
  }

  private status() {
    this.onStatus([...this.conns.values()].filter(r => r?.connected).length, this.session.relays.length);
  }

  private receive(e: Event) {
    if (this.seen.has(e.id) || !verifyEvent(e)) return;
    this.seen.add(e.id);
    try {
      const r = JSON.parse(nip44.v2.decrypt(e.content, this.ck));
      const done = this.waiting.get(r.id);
      if (done) { this.waiting.delete(r.id); done(r); }
    } catch { /* not for us */ }
  }

  private publish(body: string) {
    // A fresh event every time: strfry refuses an id it has already seen.
    const e = finalizeEvent({ kind: KIND_NIP46, created_at: now(), tags: [['p', this.session.signer]], content: nip44.v2.encrypt(body, this.ck) } as EventTemplate, this.key);
    for (const r of this.conns.values()) if (r?.connected) r.publish(e).catch(() => {});
  }

  /** One NIP-46 call. Re-sent until answered; gives up after `ms`. */
  call(method: string, params: string[], ms = 75_000): Promise<string> {
    const id = bytesToHex(generateSecretKey().slice(0, 8));
    const body = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      let gap = 1500, timer: ReturnType<typeof setTimeout>;
      const started = Date.now();
      const again = () => {
        if (Date.now() - started > ms) { this.waiting.delete(id); return reject(new Error(`${method}: your signer didn't answer`)); }
        this.publish(body);
        timer = setTimeout(again, gap);
        gap = Math.min(gap * 1.6, 8000);
      };
      this.waiting.set(id, r => { clearTimeout(timer); r.error ? reject(new Error(r.error)) : resolve(r.result ?? ''); });
      // Give the sockets a moment on a cold start.
      setTimeout(again, [...this.conns.values()].some(r => r?.connected) ? 0 : 800);
    });
  }

  /** Redeem the ticket your phone handed over. */
  connect(ticket: string) { return this.call('connect', [this.session.signer, ticket], 30_000); }
  async getPublicKey() { return (this.session.pubkey ??= await this.call('get_public_key', [])); }
  async signEvent(t: { kind: number; content: string; tags: string[][]; created_at?: number }): Promise<Event> {
    return JSON.parse(await this.call('sign_event', [JSON.stringify({ created_at: now(), ...t })]));
  }
  nip44 = {
    encrypt: (pk: string, text: string) => this.call('nip44_encrypt', [pk, text]),
    decrypt: (pk: string, text: string) => this.call('nip44_decrypt', [pk, text]),
  };
  nip04 = {
    encrypt: (pk: string, text: string) => this.call('nip04_encrypt', [pk, text]),
    decrypt: (pk: string, text: string) => this.call('nip04_decrypt', [pk, text]),
  };
  // The same, under nostr-tools' BunkerSigner names, so a site can hold either.
  nip44Encrypt = this.nip44.encrypt;
  nip44Decrypt = this.nip44.decrypt;
  nip04Encrypt = this.nip04.encrypt;
  nip04Decrypt = this.nip04.decrypt;

  /** Sign out: your servers drop this site's access, so it leaves your phone's list. Then close. */
  async logout() { try { await this.call('logout', [], 15_000); } finally { this.close(); } }

  close() { this.closed = true; for (const r of this.conns.values()) r?.close(); }
}
