// Web Push out (core §8.2, RFC 8030): the node builds each request (RFC 8291 body, RFC 8292 header);
// this sends it, only to hosts the operator allows, and drops an address that answers 404 or 410.

import type { PushOut } from '../runtime/net.ts';

export class PushSender {
  readonly allow: Set<string>; readonly onGone: (url: string) => void; readonly fetch: typeof globalThis.fetch;
  sent = 0; refused = 0;
  constructor(o: { allow: string[]; onGone?: (url: string) => void; fetch?: typeof globalThis.fetch }) {
    this.allow = new Set(o.allow.map((h) => h.toLowerCase())); this.onGone = o.onGone ?? (() => {}); this.fetch = o.fetch ?? globalThis.fetch;
  }
  /** Allowed: https to a listed host; http only to a `host:port` entry. */
  allowed(url: string) {
    let u: URL; try { u = new URL(url); } catch { return false; }
    if (u.protocol === 'https:') return this.allow.has(u.hostname.toLowerCase());
    // Plain http only to an entry listed with its port (a local test gateway), never to a bare host.
    return u.protocol === 'http:' && u.port !== '' && this.allow.has(u.host.toLowerCase());
  }
  push(p: PushOut) {
    if (!this.allowed(p.url)) { this.refused++; return; }
    this.sent++;
    void this.fetch(p.url, { method: 'POST', body: new Uint8Array(p.body) as BodyInit, redirect: 'manual', headers: { authorization: p.authorization, 'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream', ttl: '86400', urgency: 'high' } })
      .then((r) => { if (r.status === 404 || r.status === 410) this.onGone(p.url); }).catch(() => {});
  }
}
