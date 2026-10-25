// A cosign server: a share of someone's key, and the signer their sites talk to; or,
// shared, a share each of many people's keys, in one process.
//
//   node server.ts data/a                  one group, as setup.ts made it (its page on its own port)
//   node server.ts data/a data/b …         several groups in one process
//   node server.ts --root data [data/a …]  a shared server: data/host.json is its own key and
//                                          settings, every group a device enrolls goes in
//                                          data/groups/<id>/, and its page lists them all
//
// Each group runs in the core (core/group.ts), which has no I/O. This file is everything
// around them: one relay pool with one subscription per relay for all of them, their
// files, the clock, push, HTTP, and taking on new groups (core/enroll.ts).

import { readFileSync, readdirSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { SimplePool } from 'nostr-tools/pool';
import { finalizeEvent, type Event } from 'nostr-tools/pure';
import { nip19 } from 'nostr-tools';
import type { Filter } from 'nostr-tools/filter';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, openFrom, Parts, normRelay, pubOf, dial, openRelay, KIND_MEMBER, KIND_NIP46 } from './net.ts';
import type { Relay } from 'nostr-tools/relay';
import { openGroup, type Group } from './core/group.ts';
import type { Io } from './core/io.ts';
import { enrollers, memberSk, newMemberKey } from './core/enroll.ts';
import { loadGroup, groupFiles, isGroupDir, createGroup, writeJson } from './files.ts';
import { groupPage, hostPage, esc } from './page.ts';
import { checkClock, trustedNow } from './clock.ts';
import { relayTarget, pushTarget, pinnedAgent, looksPublic } from './egress.ts';
import { fetch as pinnedFetch } from 'undici';

const args = process.argv.slice(2);
const opt = (name: string) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = args[i + 1]; args.splice(i, 2); return v; };
const root = opt('--root');
const portArg = opt('--port');
const dirs = args;
if (!root && !dirs.length) { console.error('usage: node server.ts data/a [data/b …]   or   node server.ts --root data [data/a …]'); process.exit(1); }

/** Shown on the status page, so you can tell which code a server is running after a deploy. */
const VERSION = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version as string;
const startedAt = Date.now();
const DEFAULT_RELAYS = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];

// --- The host's own key and settings (a shared server only) -------------------------
//
// host.json: the host key (its identity across everyone it serves, and where devices
// write to enroll), the port of its page, its relays, and who may enroll: "open", or
// "invite" with `invites`, device pubkeys. It's read again for each enrollment, so the
// invite list can change without a restart. COSIGN_ENROLL, COSIGN_INVITES and COSIGN_RELAYS,
// if set, win over the file.
//
// With an `operator` (the pubkey of whoever runs it), the host announces itself so
// devices can find it (COSIGN.md §9.5): kind 30243, signed by the host key. The operator
// lists it back from their own key (kind 10243, site/src/servers.ts operatorServers).
// `https`: its public page, if it has one. COSIGN_OPERATOR and COSIGN_HTTPS win here too.

interface HostConfig { sk: string; pk: string; port: number; relays: string[]; enroll: 'open' | 'invite'; invites: string[]; operator?: string; https?: string;
  /** One-time codes from this server's page ("Add this server to your account"): COSIGN.md §9.6. */
  adds?: Record<string, { at: number; used?: number }> }
const hostFile = root ? join(root, 'host.json') : null;
let warnedOperator = false;
function hostConfig(): HostConfig | null {
  if (!hostFile) return null;
  const c = JSON.parse(readFileSync(hostFile, 'utf8')) as HostConfig;
  if (process.env.COSIGN_ENROLL) c.enroll = process.env.COSIGN_ENROLL === 'open' ? 'open' : 'invite';
  if (process.env.COSIGN_INVITES) c.invites = process.env.COSIGN_INVITES.split(',').map(s => s.trim()).filter(Boolean);
  c.invites ??= [];
  if (process.env.COSIGN_OPERATOR) c.operator = process.env.COSIGN_OPERATOR;
  if (process.env.COSIGN_HTTPS) c.https = process.env.COSIGN_HTTPS;
  const relays = process.env.COSIGN_RELAYS?.split(',').map(r => r.trim()).filter(Boolean);
  if (relays?.length) c.relays = relays;
  if (c.operator?.startsWith('npub1')) {
    try { c.operator = nip19.decode(c.operator).data as string; } catch { c.operator = 'bad'; }
  }
  if (c.operator && !/^[0-9a-f]{64}$/.test(c.operator)) { if (!warnedOperator) console.log("COSIGN_OPERATOR isn't a valid npub or hex key; not announcing"); warnedOperator = true; delete c.operator; }
  return c;
}
if (root && hostFile && !existsSync(hostFile)) {
  mkdirSync(join(root, 'groups'), { recursive: true, mode: 0o700 });
  const sk = bytesToHex(randomBytes(32));
  writeJson(hostFile, {
    sk, pk: pubOf(sk), port: Number(portArg ?? process.env.COSIGN_PORT ?? 8711),
    relays: process.env.COSIGN_RELAYS?.split(',').map(r => r.trim()).filter(Boolean) ?? DEFAULT_RELAYS,
    enroll: 'invite', invites: [],
  }, true);
}
const host = hostConfig();

// --- Groups -------------------------------------------------------------------

interface Served { id: string; dir: string; g: Group; label: string;
  /** Relays this group asked to listen on beyond its own (a new device's). */
  extra: Set<string> }
const groups = new Map<string, Served>();
const idOf = (pk: string) => pk.slice(0, 16);
const relaysOf = (x: Served) => [...new Set([...x.g.relays(), ...x.extra])];

const pool = new Pool([], onEvent, t => console.log(`[relays] ${t}`));
// Strangers name relays and push endpoints here: only public places, and not too many (egress.ts).
pool.guard = relayTarget;
pool.max = Number(process.env.COSIGN_MAX_RELAYS ?? 300);

/** Up to 12 of these relays, each opened at the address the egress check gave (or as named, for the operator's). */
async function openOut(relays: string[], ms: number): Promise<Relay[]> {
  const urls = [...new Set(relays.map(normRelay))].slice(0, 12);
  const opened = await Promise.allSettled(urls.map(async u => {
    const to = await relayTarget(u);
    if (!to) throw new Error('not allowed');
    return await Promise.race([
      openRelay(dial(u), to),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), ms)),
    ]);
  }));
  return opened.flatMap(r => r.status === 'fulfilled' ? [r.value] : []);
}

/** How many relays took it. */
async function publishOut(relays: string[], e: Event): Promise<number> {
  const open = await openOut(relays, 5000);
  const r = await Promise.allSettled(open.map(x => Promise.race([x.publish(e), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 6000))])));
  for (const x of open) x.close();
  return r.filter(x => x.status === 'fulfilled').length;
}

async function query(relays: string[], filter: Filter, maxWait: number): Promise<Event[]> {
  const open = await openOut(relays, Math.min(maxWait, 5000));
  const got = new Map<string, Event>();
  await Promise.all(open.map(x => new Promise<void>(resolve => {
    const t = setTimeout(() => { sub.close(); resolve(); }, maxWait);
    const sub = x.subscribe([filter], { onevent: (e: Event) => { got.set(e.id, e); }, oneose: () => { clearTimeout(t); sub.close(); resolve(); } });
  })));
  for (const x of open) x.close();
  return [...got.values()];
}

/** Load one group's directory and give it its Io. It starts (`start()`) once the relays listen for it. */
function serve(dir: string): Served | undefined {
  const loaded = loadGroup(dir);
  const pk = loaded.state.group.members.find((m: any) => m.idx === loaded.state.self.idx)?.pk as string;
  if (!pk) { console.error(`${dir}: no member key for this server; skipped`); return; }
  if (groups.has(idOf(pk))) return groups.get(idOf(pk)); // the same directory twice
  const x = { id: idOf(pk), dir, extra: new Set<string>() } as Served;
  const io: Io = {
    publish: e => pool.publish(e, relaysOf(x)),
    listen: async (relays, ms) => { for (const r of relays) x.extra.add(normRelay(r)); await pool.add(relays, ms); },
    publishOut: async (r, e) => { await publishOut(r, e); }, query,
    push: async url => { const to = await pushTarget(url); if (to) return pinnedFetch(url, { method: 'POST', body: 'cosign:approve', headers: { Priority: 'high' }, redirect: 'manual', dispatcher: pinnedAgent(to) }); },
    now: () => Date.now(),
    trustedNow,
    save: groupFiles(dir),
    note: t => console.log(`[${x.label}] ${t}`),
    debug: process.env.DEBUG ? t => console.log(`[${x.label}] ${t}`) : undefined,
    // "Remove my servers' pieces", after its wait: the whole directory (share, member key, the rest), gone.
    forget: async () => {
      groups.delete(x.id);
      pool.setFilters(filters());
      rmSync(dir, { recursive: true, force: true });
      console.log(`[${x.label}] deleted`);
    },
  };
  x.g = openGroup(loaded, io);
  // One group alone keeps the log it always had; several say which one is talking.
  x.label = root || dirs.length > 1 ? `${x.g.name} ${x.id.slice(0, 6)}` : x.g.name;
  groups.set(x.id, x);
  return x;
}

for (const d of dirs) if (isGroupDir(d)) serve(d); else { console.error(`${d}: no state.json there`); process.exit(1); }
if (root && existsSync(join(root, 'groups')))
  for (const id of readdirSync(join(root, 'groups'))) if (isGroupDir(join(root, 'groups', id))) serve(join(root, 'groups', id));

// --- Relays: one subscription for every group ------------------------------------

/** Every key this host listens for: each group's member key and signer key, and the host key. */
function filters(): Filter[] {
  const members = [...groups.values()].map(x => x.g.pk);
  if (host) members.push(host.pk);
  const signers = [...new Set([...groups.values()].flatMap(x => x.g.signerPk ? [x.g.signerPk] : []))];
  return [{ kinds: [KIND_MEMBER], '#p': members }, ...(signers.length ? [{ kinds: [KIND_NIP46], '#p': signers }] : [])];
}

/** To whichever group it's addressed to (both, for two members of one group here: each decides for itself). */
function onEvent(e: Event) {
  const to = e.tags.filter(t => t[0] === 'p').map(t => t[1]);
  for (const x of groups.values()) {
    if (e.kind === KIND_MEMBER ? to.includes(x.g.pk) : e.kind === KIND_NIP46 && !!x.g.signerPk && to.includes(x.g.signerPk)) x.g.onEvent(e);
  }
  if (host && e.kind === KIND_MEMBER && to.includes(host.pk)) onHostMessage(e).catch(err => console.error(err));
}

// --- Taking on a new group (core/enroll.ts) -----------------------------------------

const hostParts = new Parts();
const enrolling = new Set<string>();
/** When each recent enrollment happened, for the hourly cap. */
const enrolledAt: number[] = [];

async function onHostMessage(e: Event) {
  if (Date.now() / 1000 - e.created_at > 120) return;
  const msg = hostParts.take(e.pubkey, openFrom(host!.sk, e));
  if (!msg || typeof msg.type !== 'string') return;
  const reply = (m: object) => { for (const ev of sealParts(host!.sk, e.pubkey, m)) pool.publish(ev); };
  // A device timing servers before it picks some (site/src/servers.ts pingHost).
  if (msg.type === 'ping') return reply({ type: 'pong', id: msg.id });
  if (!msg.type.startsWith('enroll')) return;
  const cfg = hostConfig()!; // fresh: the invite list and the codes may have changed
  const code = typeof msg.token === 'string' && liveAdd(cfg, msg.token) ? msg.token : null;
  if (cfg.enroll !== 'open' && !cfg.invites.includes(e.pubkey) && !code)
    return reply({ type: 'enroll_failed', id: msg.id, reason: 'not-invited: This server only takes on accounts for people it invited. Open its page for a code.' });
  if (msg.type === 'enroll_key') return reply({ type: 'enroll_key', id: msg.id, ...newMemberKey(cfg.sk) });
  if (msg.type !== 'enroll') return;
  // An open server is still one machine: so many groups, so many new ones an hour.
  const maxGroups = Number(process.env.COSIGN_MAX_GROUPS ?? 5000), perHour = Number(process.env.COSIGN_ENROLL_PER_HOUR ?? 30);
  while (enrolledAt.length && Date.now() - enrolledAt[0] > 3600_000) enrolledAt.shift();
  if (groups.size >= maxGroups) return reply({ type: 'enroll_failed', id: msg.id, reason: 'full: This server takes no more accounts. Try another.' });
  if (enrolledAt.length >= perHour) return reply({ type: 'enroll_failed', id: msg.id, reason: 'busy: This server has taken on many accounts this hour. Try again later.' });
  try {
    const sk = memberSk(cfg.sk, String(msg.key ?? ''));
    const pk = pubOf(sk);
    // Asked again (the device repeats until it hears back): the same answer.
    if (groups.has(idOf(pk))) return reply({ type: 'enrolled', id: msg.id, pk, group: idOf(pk) });
    if (enrolling.has(pk)) return;
    enrolling.add(pk);
    try {
      const enroller = enrollers[String(msg.how ?? 'dealt')];
      if (!enroller) throw new Error(`unsupported: This server can't enroll by "${msg.how}".`);
      const holds = (groupX: string) => [...groups.values()].filter(x => x.g.groupX === groupX)
        .flatMap(x => (x.g.state.self.shares ?? [{ idx: x.g.state.self.idx }]).map((s: { idx: number }) => s.idx));
      const state = await enroller({ msg, from: e.pubkey, memberSk: sk, holds, now: Date.now() });
      const dir = join(root!, 'groups', idOf(pk));
      createGroup(dir, state);
      enrolledAt.push(Date.now());
      const x = serve(dir)!;
      await pool.add(relaysOf(x), 4000);
      pool.setFilters(filters());
      x.g.start();
      if (code) useAddCode(code);
      console.log(`[host] took on ${state.group.npub ?? "a key still to be made"} as ${x.g.name} (${x.id}), for ${e.pubkey.slice(0, 8)}…${code ? ' (by a code from its page)' : ''}`);
      reply({ type: 'enrolled', id: msg.id, pk, group: x.id });
    } finally { enrolling.delete(pk); }
  } catch (err: any) {
    reply({ type: 'enroll_failed', id: msg.id, reason: err?.message ?? String(err) });
  }
}

// --- "Add this server to your account" (COSIGN.md §9.6) --------------------------------
//
// A server people can't find (a home server: unannounced, invite only) is added by its
// own code, shown on its page: `cosign:server?pk=<host key>&r=<relay>…&t=<code>`. The
// code is made here, so it only ever works on this server, and only once: a phone that
// has it may enroll one account, by repair, as with any other server. It's forgotten an
// hour later, used or not.

const ADD_CODE_LIFE = Number(process.env.COSIGN_ADD_CODE_LIFE ?? 3600) * 1000;
const liveAdd = (c: HostConfig, t: string) => { const a = c.adds?.[t]; return !!a && !a.used && Date.now() - a.at < ADD_CODE_LIFE; };

/** The code to show on the page: the unused one if there is one, else a new one. */
function addCode(): string | null {
  const cfg = hostConfig();
  if (!cfg || !hostFile) return null;
  const adds = cfg.adds ?? {};
  for (const [t, a] of Object.entries(adds)) if (!a.used && Date.now() - a.at < ADD_CODE_LIFE) return uriFor(cfg, t);
  const t = bytesToHex(randomBytes(16));
  const kept = Object.fromEntries(Object.entries(adds).filter(([, a]) => Date.now() - a.at < 24 * ADD_CODE_LIFE).slice(-50));
  saveHost({ ...cfg, adds: { ...kept, [t]: { at: Date.now() } } });
  return uriFor(cfg, t);
}
const uriFor = (cfg: HostConfig, t: string) =>
  `cosign:server?pk=${cfg.pk}&t=${t}&` + cfg.relays.slice(0, 4).map(r => `r=${encodeURIComponent(r)}`).join('&');

/** Mark a code used, so it adds one account and no more. */
function useAddCode(t: string) {
  const cfg = hostConfig();
  if (!cfg?.adds?.[t]) return;
  saveHost({ ...cfg, adds: { ...cfg.adds, [t]: { ...cfg.adds[t], used: Date.now() } } });
}

/** Keep the file's own fields (sk, port…) and write back what changed; env overrides are never written. */
function saveHost(next: HostConfig) {
  const onDisk = JSON.parse(readFileSync(hostFile!, 'utf8'));
  writeJson(hostFile!, { ...onDisk, adds: next.adds }, true);
}

// --- Announcing itself (COSIGN.md §9.5) ------------------------------------------------

/** Where announcements go, besides the host's own relays: where devices look for them. */
const DISCOVERY = ['wss://syb.lol', 'wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.damus.io'];
async function announce(): Promise<boolean> {
  const cfg = hostConfig();
  if (!cfg?.operator) return true;
  // A server only reachable on this machine or network (a test's, say) is never announced.
  if (!cfg.relays.some(looksPublic)) { console.log('not announcing: none of its relays is public'); return true; }
  const e = finalizeEvent({
    kind: 30243, created_at: Math.floor(Date.now() / 1000),
    tags: [['d', 'cosign-server'], ['p', cfg.operator, '', 'operator']],
    content: JSON.stringify({ relays: cfg.relays, https: cfg.https ?? null, enroll: cfg.enroll, version: VERSION }),
  }, hexToBytes(cfg.sk));
  return await publishOut([...cfg.relays, ...DISCOVERY], e) > 0;
}
/** Every 6 h, or a minute after a try no relay took. */
async function announceLoop() {
  const ok = await announce().catch(() => false);
  if (!ok) console.log('announcement not taken by any relay; trying again in a minute');
  setTimeout(() => void announceLoop(), ok ? 6 * 3600_000 : 60_000);
}

// --- Status pages ---------------------------------------------------------------

const groupStatus = (x: Served) => ({ ...x.g.status(), version: VERSION, relays: pool.status(relaysOf(x)) });
function hostStatus() {
  return {
    version: VERSION, started: startedAt, host: host?.pk ?? null, enroll: host?.enroll ?? null, relays: pool.status(),
    groups: [...groups.values()].map(x => {
      const s = x.g.status();
      return { id: x.id, me: esc(s.me), npub: s.npub, coordinating: s.coordinating, pairing: s.pairing, signedToday: s.signedToday, members: s.members.length, online: s.members.filter(m => m.online).length, sites: s.sites.length };
    }),
  };
}

type Res = import('node:http').ServerResponse;
const json = (res: Res, v: unknown) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(v)); };
const html = (res: Res, v: string) => { res.setHeader('content-type', 'text/html'); res.end(v); };
async function groupRoute(x: Served, path: string, req: import('node:http').IncomingMessage, res: Res) {
  if (path === 'status') return json(res, groupStatus(x));
  if (path === 'revoke' && req.method === 'POST') {
    let body = ''; req.on('data', c => (body += c)); req.on('end', () => { x.g.revoke(body.trim(), `on ${x.g.name}'s page`); res.end('ok'); }); return;
  }
  if (path === '') return html(res, await groupPage({ name: x.g.name, npub: x.g.state.group.npub, threshold: x.g.state.group.threshold, pairingUri: x.g.pairingUri() }));
  res.statusCode = 404; res.end();
}

const listen = (port: number, handle: (req: import('node:http').IncomingMessage, res: Res) => unknown, label: string) =>
  createServer((req, res) => { Promise.resolve(handle(req, res)).catch(err => { console.error(err); res.statusCode = 500; res.end(); }); })
    .listen(port, process.env.HOST ?? '127.0.0.1', () => console.log(`[${label}] http://localhost:${port}`));

// A shared server's page: the list, and each group at /g/<id>/.
if (host) listen(host.port, async (req, res) => {
  const path = (req.url ?? '/').split('?')[0];
  if (path === '/status') return json(res, hostStatus());
  if (path === '/add-code') return json(res, { uri: addCode() });
  if (path === '/') return html(res, await hostPage({ pk: host.pk, enroll: host.enroll, relays: host.relays, version: VERSION, addUri: addCode() }));
  const m = /^\/g\/([0-9a-f]{16})(\/.*)?$/.exec(path);
  const x = m && groups.get(m[1]);
  if (!x) { res.statusCode = 404; return res.end(); }
  if (!m![2]) { res.statusCode = 302; res.setHeader('location', `/g/${x.id}/`); return res.end(); }
  return groupRoute(x, m![2].slice(1), req, res);
}, 'host');
// A group with a port of its own (as setup.ts makes them) keeps its page there too.
for (const x of groups.values()) {
  const port = x.g.state.port;
  if (port && port !== host?.port) listen(port, (req, res) => groupRoute(x, (req.url ?? '/').split('?')[0].slice(1), req, res), x.label);
}

// --- Go -----------------------------------------------------------------------

for (const x of groups.values()) for (const r of relaysOf(x)) if (!pool.urls.includes(r)) pool.urls.push(r);
for (const r of host?.relays ?? []) if (!pool.urls.includes(normRelay(r))) pool.urls.push(normRelay(r));
pool.start(filters());
for (const x of groups.values()) x.g.start();
setInterval(() => { for (const x of groups.values()) x.g.tick(); }, 10_000);
// Judge "the future" by the network's time, not this machine's clock.
const clockNote = (t: string) => console.log(`[clock] ${t}`);
void checkClock(clockNote);
setInterval(() => void checkClock(clockNote), 30 * 60_000);
// Hourly: let go of accounts strangers enrolled that never finished being set up (never a finished one).
const ageOut = () => { for (const x of [...groups.values()]) { const why = x.g.stale(); if (why) { console.log(`[${x.label}] letting it go: ${why}`); void x.g.forget(); } } };
setInterval(ageOut, Number(process.env.COSIGN_AGE_EVERY ?? 3600_000));
setTimeout(ageOut, 60_000);
if (host?.operator) setTimeout(() => void announceLoop(), 5000);
if (host) console.log(`[host] ${host.pk} · ${groups.size} group${groups.size === 1 ? '' : 's'} · enroll: ${host.enroll}${host.enroll === 'invite' ? ` (${host.invites.length} invited)` : ''}`);
