// The server, as one Durable Object: every group it serves (../../server/core/group.ts,
// the same core as the Node server), its host key and enrollment (core/enroll.ts), and
// the relay devices reach it on. It accepts only events addressed to its own keys and
// sends its own to whoever subscribed; it holds no NIP-46 signer key, so it never answers
// sites, and it dials out only to announce itself.
//
// Storage (../../server/HOSTS.md): every share and member key, and the host key, in Workers
// KV (`SECRETS`); everything else (the group record, sites, archive, history) in this
// object's SQLite, which keeps 30 days of point-in-time history and so must never hold a
// share.

import { DurableObject } from 'cloudflare:workers';
import { finalizeEvent, verifyEvent, type Event } from 'nostr-tools/pure';
import { matchFilters, type Filter } from 'nostr-tools/filter';
import { nip19 } from 'nostr-tools';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import './wasm.ts';
import { openGroup, type Group } from '../../server/core/group.ts';
import type { Io, Loaded } from '../../server/core/io.ts';
import { enrollers, memberSk, newMemberKey } from '../../server/core/enroll.ts';
import { sealParts, openFrom, Parts, pubOf, KIND_MEMBER, KIND_NIP46 } from '../../server/core/seal.ts';
import { isPublicRelay } from '../../site/src/servers.ts';
import { checkClock, trustedNow } from '../../server/clock.ts';
import pkg from '../../server/package.json';

const VERSION: string = (pkg as any).version;
/** Where its announcement goes, so devices find it (COSIGN.md §9.5). */
const DISCOVERY = ['wss://syb.lol', 'wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.damus.io'];
const BUFFER_MS = 120_000;

interface Served { id: string; g: Group; secretJson: string }
interface Sub { filters: Filter[] }

export class CosignHost extends DurableObject {
  private env: any;
  private sql: any;
  private host!: { sk: string; pk: string };
  private groups = new Map<string, Served>();
  /** Recent events this server sent, for a device that subscribes a moment later. */
  private recent: { at: number; e: Event }[] = [];
  private hostParts = new Parts();
  private enrolling = new Set<string>();
  private enrolledAt: number[] = [];
  private startedAt = Date.now();

  constructor(ctx: any, env: any) {
    super(ctx, env);
    this.env = env;
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(() => this.load());
  }

  // --- Storage -------------------------------------------------------------------------

  private async load() {
    this.sql.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS log (g TEXT, kind TEXT, v TEXT)');
    let host = await this.env.SECRETS.get('host', 'json');
    if (!host) {
      const sk = bytesToHex(randomBytes(32));
      host = { sk, pk: pubOf(sk) };
      await this.env.SECRETS.put('host', JSON.stringify(host));
    }
    this.host = host;
    const ids: string[] = JSON.parse(this.get('groups') ?? '[]');
    for (const id of ids) await this.open(id);
    for (const x of this.groups.values()) x.g.start();
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(Date.now() + 5_000);
  }

  private get(k: string): string | null { return (this.sql.exec('SELECT v FROM kv WHERE k = ?', k).toArray()[0] as any)?.v ?? null; }
  private put(k: string, v: string) { this.sql.exec('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, v); }

  /** A state, split: its secret part (this member's key and shares, any signer key) for KV, the rest for SQLite. */
  private split(S: any) {
    const { self, signer, ...rest } = S;
    const { sk, share, shares, ...selfRest } = self ?? {};
    return { secret: JSON.stringify({ sk, share, shares, signer: signer ?? null }), plain: JSON.stringify({ ...rest, self: selfRest }) };
  }

  /** `secretJson`: the secret part in hand (a group just enrolled: KV may not show it back yet). */
  private async open(id: string, given?: string) {
    const plain = JSON.parse(this.get(`g:${id}`) ?? 'null');
    const secretJson = given ?? (await this.env.SECRETS.get(`g:${id}`)) ?? 'null';
    const secret = JSON.parse(secretJson);
    if (!plain || !secret) return;
    const state = { ...plain, self: { ...plain.self, sk: secret.sk, ...(secret.share ? { share: secret.share } : {}), ...(secret.shares ? { shares: secret.shares } : {}) }, signer: secret.signer };
    const rows = (kind: string) => this.sql.exec('SELECT v FROM log WHERE g = ? AND kind = ? ORDER BY rowid', id, kind).toArray().map((r: any) => JSON.parse(r.v));
    const loaded: Loaded = { state, archive: JSON.parse(this.get(`a:${id}`) ?? '{}'), history: rows('entry'), saved: rows('saved') };
    const x: Served = { id, g: null as any, secretJson };
    x.g = openGroup(loaded, this.io(x));
    this.groups.set(id, x);
  }

  private io(x: Served): Io {
    return {
      publish: e => this.send(e),
      listen: async () => {},             // devices come to it; it dials nothing
      publishOut: async () => {},         // it never answers sites, so it never publishes for them
      query: async () => [],              // the archive reaches it from the other servers (sync)
      // Only to a push service it knows (ntfy.sh, plus COSIGN_PUSH_HOSTS), and no redirects.
      push: async url => {
        let u: URL; try { u = new URL(url); } catch { return; }
        const hosts = ['ntfy.sh', ...String(this.env.COSIGN_PUSH_HOSTS ?? '').split(',').map(h => h.trim()).filter(Boolean)];
        if (u.protocol === 'https:' && !u.username && hosts.includes(u.hostname.toLowerCase())) return fetch(url, { method: 'POST', body: 'cosign:approve', headers: { Priority: 'high' }, redirect: 'manual' });
      },
      now: () => Date.now(),
      trustedNow,
      save: {
        state: S => {
          const { secret, plain } = this.split(S);
          this.put(`g:${x.id}`, plain);
          // KV writes are few and far between: only when the secret part changes (join, refresh).
          if (secret !== x.secretJson) { x.secretJson = secret; void this.env.SECRETS.put(`g:${x.id}`, secret); }
        },
        archive: byKey => this.put(`a:${x.id}`, JSON.stringify(byKey)),
        entry: e => this.sql.exec('INSERT INTO log (g, kind, v) VALUES (?, ?, ?)', x.id, 'entry', JSON.stringify(e)),
        saved: e => this.sql.exec('INSERT INTO log (g, kind, v) VALUES (?, ?, ?)', x.id, 'saved', JSON.stringify(e)),
      },
      note: t => console.log(`[${x.g?.name ?? x.id}] ${t}`),
      // "Remove my servers' pieces", after its wait: the share and keys in KV, and every row here.
      forget: async () => {
        this.groups.delete(x.id);
        this.put('groups', JSON.stringify([...this.groups.keys()]));
        await this.env.SECRETS.delete(`g:${x.id}`);
        this.sql.exec('DELETE FROM kv WHERE k = ? OR k = ?', `g:${x.id}`, `a:${x.id}`);
        this.sql.exec('DELETE FROM log WHERE g = ?', x.id);
        console.log(`[${x.id}] deleted`);
      },
    };
  }

  // --- The relay -----------------------------------------------------------------------

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]);
      pair[1].serializeAttachment({ subs: {} });
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (req.headers.get('Accept') === 'application/nostr+json') return Response.json(this.nip11(), { headers: { 'Access-Control-Allow-Origin': '*' } });
    if (url.pathname === '/status') return Response.json(this.status());
    if (url.pathname === '/') return new Response(this.page(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
    return new Response('not found', { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer) {
    let m: any;
    try { m = JSON.parse(typeof data === 'string' ? data : new TextDecoder().decode(data)); } catch { return; }
    if (!Array.isArray(m)) return;
    const att = ws.deserializeAttachment() ?? { subs: {} };
    if (m[0] === 'REQ' && typeof m[1] === 'string') {
      att.subs[m[1]] = { filters: m.slice(2) } satisfies Sub;
      ws.serializeAttachment(att);
      const now = Date.now();
      this.recent = this.recent.filter(r => now - r.at < BUFFER_MS);
      for (const r of this.recent) if (matchFilters(att.subs[m[1]].filters, r.e)) ws.send(JSON.stringify(['EVENT', m[1], r.e]));
      ws.send(JSON.stringify(['EOSE', m[1]]));
    } else if (m[0] === 'CLOSE') {
      delete att.subs[m[1]];
      ws.serializeAttachment(att);
    } else if (m[0] === 'EVENT' && m[1]) {
      const e = m[1] as Event;
      const ok = (yes: boolean, why = '') => ws.send(JSON.stringify(['OK', e.id, yes, why]));
      const to = (e.tags ?? []).filter(t => t[0] === 'p').map(t => t[1]);
      // Its own keys, and the mailboxes on your devices it watches to wake them (COSIGN.md §6.1).
      const mine = to.includes(this.host.pk) || [...this.groups.values()].some(x => to.includes(x.g.pk) || (e.kind === KIND_NIP46 && x.g.signerPks().some(pk => to.includes(pk))));
      if ((e.kind !== KIND_MEMBER && e.kind !== KIND_NIP46) || !mine) return ok(false, 'restricted: this relay only takes messages for its own keys');
      if (!verifyEvent(e)) return ok(false, 'invalid: bad signature');
      ok(true);
      this.onEvent(e, to);
    }
  }

  async webSocketClose(ws: WebSocket) { try { ws.close(); } catch { /* gone */ } }

  /** One of ours, out: to every connection subscribed to it, and kept a moment for those about to. */
  private send(e: Event) {
    this.recent.push({ at: Date.now(), e });
    for (const ws of this.ctx.getWebSockets()) {
      const subs = (ws.deserializeAttachment()?.subs ?? {}) as Record<string, Sub>;
      for (const [id, s] of Object.entries(subs)) if (matchFilters(s.filters, e)) { try { ws.send(JSON.stringify(['EVENT', id, e])); } catch { /* closing */ } break; }
    }
  }

  private onEvent(e: Event, to: string[]) {
    for (const x of this.groups.values()) if (to.includes(x.g.pk) || (e.kind === KIND_NIP46 && x.g.signerPks().some(pk => to.includes(pk)))) x.g.onEvent(e);
    if (e.kind === KIND_MEMBER && to.includes(this.host.pk)) this.onHostMessage(e).catch(err => console.error(err));
  }

  // --- Taking on a new group (core/enroll.ts), as the Node host does --------------------

  private config() {
    const op = String(this.env.COSIGN_OPERATOR ?? '');
    return {
      enroll: this.env.COSIGN_ENROLL === 'open' ? 'open' : 'invite',
      invites: String(this.env.COSIGN_INVITES ?? '').split(',').map(s => s.trim()).filter(Boolean),
      operator: op.startsWith('npub1') ? (nip19.decode(op).data as string) : op,
      url: String(this.env.COSIGN_URL ?? ''),
    };
  }

  private async onHostMessage(e: Event) {
    if (Date.now() / 1000 - e.created_at > 120) return;
    const msg = this.hostParts.take(e.pubkey, openFrom(this.host.sk, e));
    if (!msg || typeof msg.type !== 'string') return;
    const reply = (m: object) => { for (const ev of sealParts(this.host.sk, e.pubkey, m)) this.send(ev); };
    if (msg.type === 'ping') return reply({ type: 'pong', id: msg.id });
    if (!msg.type.startsWith('enroll')) return;
    const cfg = this.config();
    if (cfg.enroll !== 'open' && !cfg.invites.includes(e.pubkey))
      return reply({ type: 'enroll_failed', id: msg.id, reason: 'not-invited: This server only takes on groups for people it invited.' });
    if (msg.type === 'enroll_key') return reply({ type: 'enroll_key', id: msg.id, ...newMemberKey(this.host.sk) });
    if (msg.type !== 'enroll') return;
    // One Durable Object is one machine: so many groups, so many new ones an hour.
    const maxGroups = Number(this.env.COSIGN_MAX_GROUPS ?? 5000), perHour = Number(this.env.COSIGN_ENROLL_PER_HOUR ?? 30);
    while (this.enrolledAt.length && Date.now() - this.enrolledAt[0] > 3600_000) this.enrolledAt.shift();
    if (this.groups.size >= maxGroups) return reply({ type: 'enroll_failed', id: msg.id, reason: 'full: This server takes no more accounts. Try another.' });
    if (this.enrolledAt.length >= perHour) return reply({ type: 'enroll_failed', id: msg.id, reason: 'busy: This server has taken on many accounts this hour. Try again later.' });
    try {
      const sk = memberSk(this.host.sk, String(msg.key ?? ''));
      const pk = pubOf(sk);
      const id = pk.slice(0, 16);
      if (this.groups.has(id)) return reply({ type: 'enrolled', id: msg.id, pk, group: id });
      if (this.enrolling.has(pk)) return;
      this.enrolling.add(pk);
      try {
        const enroller = enrollers[String(msg.how ?? 'dealt')];
        if (!enroller) throw new Error(`unsupported: This server can't enroll by "${msg.how}".`);
        // A public server holds no signer key: it never answers sites (COSIGN.md §9.2).
        const holds = (groupX: string) => [...this.groups.values()].filter(x => x.g.groupX === groupX)
          .flatMap(x => (x.g.state.self.shares ?? [{ idx: x.g.state.self.idx }]).map((s: { idx: number }) => s.idx));
        const state = await enroller({ msg: { ...msg, signer: undefined }, from: e.pubkey, memberSk: sk, holds, now: Date.now() });
        const { secret, plain } = this.split(state);
        await this.env.SECRETS.put(`g:${id}`, secret);
        this.put(`g:${id}`, plain);
        this.put('groups', JSON.stringify([...this.groups.keys(), id]));
        await this.open(id, secret);
        this.enrolledAt.push(Date.now());
        this.groups.get(id)!.g.start();
        console.log(`[host] took on ${state.group.npub ?? 'a key still to be made'} (${id}) for ${e.pubkey.slice(0, 8)}…`);
        reply({ type: 'enrolled', id: msg.id, pk, group: id });
      } finally { this.enrolling.delete(pk); }
    } catch (err: any) {
      reply({ type: 'enroll_failed', id: msg.id, reason: err?.message ?? String(err) });
    }
  }

  // --- Now and then: liveness, the clock, the announcement ---------------------------------

  async alarm() {
    for (const x of this.groups.values()) x.g.tick();
    // Let go of accounts strangers enrolled that never finished being set up (never a finished one).
    for (const x of [...this.groups.values()]) { const why = x.g.stale(); if (why) { console.log(`[${x.id}] letting it go: ${why}`); await x.g.forget(); } }
    // Every 6 h, and as soon as a new version is running (its announcement says which).
    const last = Number(this.get('announced') ?? 0);
    if (Date.now() - last > 6 * 3600_000 || this.get('announcedVersion') !== VERSION) {
      await checkClock(t => console.log(`[clock] ${t}`));
      await this.announce().catch(err => console.error('announce', err));
      this.put('announced', String(Date.now()));
      this.put('announcedVersion', VERSION);
    }
    // On-demand liveness (HOSTS.md): a member's message wakes this object; this is only a slow heartbeat.
    await this.ctx.storage.setAlarm(Date.now() + 10 * 60_000);
  }

  /** Kind 30243, signed by the host key, to the discovery relays: the only time it dials out. */
  private async announce() {
    const cfg = this.config();
    // Not under wrangler dev (ws://127.0.0.1…): an address nobody else can reach is never announced.
    if (!/^[0-9a-f]{64}$/.test(cfg.operator) || !isPublicRelay(cfg.url)) return;
    const e = finalizeEvent({
      kind: 30243, created_at: Math.floor(Date.now() / 1000),
      tags: [['d', 'cosign-server'], ['p', cfg.operator, '', 'operator']],
      content: JSON.stringify({ relays: [cfg.url], https: cfg.url.replace(/^wss:/, 'https:'), enroll: cfg.enroll, version: VERSION }),
    }, hexToBytes(this.host.sk));
    await Promise.allSettled(DISCOVERY.map(async relay => {
      const r = await fetch(relay.replace(/^wss:/, 'https:'), { headers: { Upgrade: 'websocket' } });
      const ws = (r as any).webSocket as WebSocket;
      if (!ws) return;
      ws.accept();
      ws.send(JSON.stringify(['EVENT', e]));
      await new Promise(res => { ws.addEventListener('message', res); setTimeout(res, 4000); });
      ws.close();
    }));
  }

  // --- Its page ---------------------------------------------------------------------------

  private status() {
    const cfg = this.config();
    return {
      version: VERSION, host: this.host.pk, enroll: cfg.enroll, relays: [cfg.url], started: this.startedAt,
      groups: this.groups.size, connections: this.ctx.getWebSockets().length,
    };
  }

  private nip11() {
    return {
      name: 'Cosign server', description: 'A Cosign co-signer (github.com/sybenx/cosign). Takes only messages for its own keys.',
      pubkey: this.host.pk, software: 'https://github.com/sybenx/cosign', version: VERSION, supported_nips: [1, 11, 44],
      limitation: { restricted_writes: true },
    };
  }

  private page() {
    const s = this.status();
    return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Cosign server</title>
<style>body{font:16px/1.5 system-ui,sans-serif;background:#13110f;color:#ede6da;max-width:560px;margin:0 auto;padding:32px 20px}.muted{color:#a69d90}a{color:#7fc8c0}</style>
<h1>Cosign server</h1><p>A co-signer for <a href="https://cosign.aaro.cc/servers">Cosign</a> keys: it holds one share of each key it serves, never enough to sign alone.</p>
<p class=muted>Cosign ${s.version} · ${s.enroll === 'open' ? 'takes new accounts' : 'invite only'} · ${s.groups} key${s.groups === 1 ? '' : 's'} · relay ${s.relays[0]}</p>
<p class=muted>Host key ${s.host}</p>`;
  }
}
