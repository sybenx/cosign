// Finding servers for a new key (COSIGN.md §9.5): the list lives on Nostr, not on one
// website. A server announces itself (kind 30243, d = "cosign-server", signed by its
// host key, naming its operator); an operator lists its servers (kind 10243). A server
// counts as an operator's only when both name each other. A fresh install starts from
// a seed list, so it works before it has seen any announcement.
//
// Picking: one ping round trip each, then the fastest server of each operator first,
// as many as asked for (three, normally). With fewer operators than that, the rest come
// from operators already picked, and `sharedOperators` says so: the user must be told
// (COSIGN.md §9.5), and a refresh swaps one out when another operator appears.
//
// I/O comes in from outside (`query`, `ping`), so this runs in a page, an extension or
// a test alike; `relayQuery` and `pingHost` are ready-made ones over nostr-tools.

import { verifyEvent, generateSecretKey, getPublicKey, finalizeEvent, type Event, type EventTemplate } from 'nostr-tools/pure';
import { SimplePool } from 'nostr-tools/pool';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex } from '@noble/hashes/utils.js';

export const KIND_SERVER = 30243;
export const KIND_OPERATOR_SERVERS = 10243;
const KIND_MEMBER = 28001;
const D = 'cosign-server';

/** A server, as announced (or as a seed list gives it). `pk` is its host key: where devices write to enroll. */
export interface Server {
  pk: string;
  relays: string[];
  https: string | null;
  enroll: 'open' | 'invite';
  version: string;
  operator: string;
  nip05?: string;
  /** Its operator lists it too (or it came from the seed list, which the client vouches for). */
  verified: boolean;
  /** When it last announced itself, seconds; 0 for a seed not seen announcing. */
  at: number;
}

export interface Seed { pubkey: string; relays: string[]; operator: string }

/** Servers known to be run by distinct people. */
export const SEEDS: Seed[] = [
  // syb.lol, run by the author of Cosign.
  { pubkey: '040e022d19ed8e0ba6d83f6246b9d051f0093e59092ee6bb279730d0e4b191c8', relays: ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'], operator: 'f5073ea24832d8e6246d22ec0b5a75bbf4a12558e3ac67cb07360b3474e5a40e' },
  // cosign-cf.aaro.cc, the Cloudflare Worker server (../../worker), the same operator: its own relay.
  { pubkey: '665dd9c0ececdb5b60868aa6c0860df9f8e9e40c65304a9ffcecc59aa1502420', relays: ['wss://cosign-cf.aaro.cc'], operator: 'f5073ea24832d8e6246d22ec0b5a75bbf4a12558e3ac67cb07360b3474e5a40e' },
];
/** Where announcements are looked for, besides the seeds' own relays and the user's. */
export const DISCOVERY_RELAYS = ['wss://syb.lol', 'wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.damus.io'];

const isHex = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const isRelay = (r: unknown): r is string => typeof r === 'string' && /^wss?:\/\/[^\s]+$/.test(r);
/** A relay a stranger's device could reach: wss://, and not a loopback, private or tailnet name or address (servers won't dial those either). */
export function isPublicRelay(r: unknown): r is string {
  if (typeof r !== 'string' || !/^wss:\/\/[^\s]+$/.test(r)) return false;
  let h: string;
  try { h = new URL(r).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { return false; }
  if (h === 'localhost' || /\.(localhost|local|internal|lan|home|ts\.net)$/.test(h) || !h.includes('.') && !h.includes(':')) return false;
  const v4 = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(h);
  if (v4) { const [a, b] = [Number(v4[1]), Number(v4[2])]; return !(a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224); }
  return !(h.includes(':') && (h === '::1' || /^(fc|fd|fe8|fe9|fea|feb)/.test(h)));
}

/** A server's announcement, to sign with its host key. */
export function announcement(a: { relays: string[]; https: string | null; enroll: 'open' | 'invite'; version: string; operator: string; nip05?: string }, created_at = Math.floor(Date.now() / 1000)): EventTemplate {
  return {
    kind: KIND_SERVER, created_at,
    tags: [['d', D], ['p', a.operator, '', 'operator'], ...(a.nip05 ? [['nip05', a.nip05]] : [])],
    content: JSON.stringify({ relays: a.relays, https: a.https, enroll: a.enroll, version: a.version }),
  };
}

/** An operator's list of its servers' host keys, to sign with the operator's own key. */
export function operatorServers(hostKeys: string[], created_at = Math.floor(Date.now() / 1000)): EventTemplate {
  return { kind: KIND_OPERATOR_SERVERS, created_at, tags: hostKeys.map(pk => ['p', pk]), content: '' };
}

/** A server from its announcement, or null if it isn't a valid one. Not yet `verified`. */
export function parseAnnouncement(e: Event): Server | null {
  if (e.kind !== KIND_SERVER || !e.tags.some(t => t[0] === 'd' && t[1] === D) || !verifyEvent(e)) return null;
  const operator = e.tags.find(t => t[0] === 'p' && t[3] === 'operator')?.[1];
  if (!isHex(operator)) return null;
  let c: any;
  try { c = JSON.parse(e.content); } catch { return null; }
  // Only relays anyone can reach: an announcement naming none (a test server's, say) isn't a server to offer.
  const relays = Array.isArray(c?.relays) ? c.relays.filter(isPublicRelay) : [];
  if (!relays.length) return null;
  const https = typeof c.https === 'string' && /^https:\/\//.test(c.https) ? c.https : null;
  const nip05 = e.tags.find(t => t[0] === 'nip05')?.[1];
  return { pk: e.pubkey, relays, https, enroll: c.enroll === 'open' ? 'open' : 'invite', version: String(c.version ?? ''), operator, ...(nip05 ? { nip05 } : {}), verified: false, at: e.created_at };
}

/** Mark each server whose operator's latest list names it. */
export function verify(servers: Server[], lists: Event[]): Server[] {
  const latest = new Map<string, Event>();
  for (const l of lists) if (l.kind === KIND_OPERATOR_SERVERS && verifyEvent(l) && (latest.get(l.pubkey)?.created_at ?? -1) < l.created_at) latest.set(l.pubkey, l);
  return servers.map(s => ({ ...s, verified: s.verified || !!latest.get(s.operator)?.tags.some(t => t[0] === 'p' && t[1] === s.pk) }));
}

export type Query = (relays: string[], filter: Record<string, unknown>) => Promise<Event[]>;

/** Every server announced on these relays (and the seeds'), newest announcement each, operators checked. */
export async function findServers(o: { query: Query; relays?: string[]; seeds?: Seed[] }): Promise<Server[]> {
  const seeds = o.seeds ?? SEEDS;
  const relays = [...new Set([...(o.relays ?? []), ...DISCOVERY_RELAYS, ...seeds.flatMap(s => s.relays)])];
  const found = new Map<string, Server>();
  for (const e of await o.query(relays, { kinds: [KIND_SERVER], '#d': [D] })) {
    const s = parseAnnouncement(e);
    if (s && (found.get(s.pk)?.at ?? -1) < s.at) found.set(s.pk, s);
  }
  // A seed is vouched for by whoever shipped the list; its own announcement, if any, says how to reach it now.
  for (const seed of seeds) {
    const s = found.get(seed.pubkey);
    if (s && s.operator === seed.operator) s.verified = true;
    else if (!s) found.set(seed.pubkey, { pk: seed.pubkey, relays: seed.relays, https: null, enroll: 'open', version: '', operator: seed.operator, verified: true, at: 0 });
  }
  const operators = [...new Set([...found.values()].filter(s => !s.verified).map(s => s.operator))];
  const lists = operators.length ? await o.query(relays, { kinds: [KIND_OPERATOR_SERVERS], authors: operators }) : [];
  return verify([...found.values()], lists);
}

/**
 * Up to `n` servers for a new key: verified, taking new people, answering. The fastest of
 * each operator first; then, if that's fewer than `n`, the fastest of the rest. `ping`
 * gives a round trip in ms, or null for no answer. `exclude`: operators to leave out
 * entirely (`distinct: true` also stops at one per operator).
 */
export async function pickServers(servers: Server[], o: { ping: (s: Server) => Promise<number | null>; n?: number; exclude?: string[]; distinct?: boolean }): Promise<(Server & { ms: number })[]> {
  const n = o.n ?? 3;
  const candidates = servers.filter(s => s.verified && s.enroll === 'open' && !o.exclude?.includes(s.operator));
  const timed = (await Promise.all(candidates.map(async s => ({ ...s, ms: await o.ping(s).catch(() => null) }))))
    .filter((s): s is Server & { ms: number } => s.ms !== null)
    .sort((a, b) => a.ms - b.ms);
  const picked: (Server & { ms: number })[] = [];
  for (const s of timed) if (picked.length < n && !picked.some(p => p.operator === s.operator)) picked.push(s);
  if (!o.distinct) for (const s of timed) if (picked.length < n && !picked.includes(s)) picked.push(s);
  return picked;
}

/** Operators that run more than one of these servers: tell the user (COSIGN.md §9.5). */
export const sharedOperators = (picked: Server[]) => [...new Set(picked.map(s => s.operator).filter((op, i, all) => all.indexOf(op) !== i))];

// --- Ready-made I/O over nostr-tools ---------------------------------------------------

/** `query` for findServers: every relay at once, up to `maxWait` ms. */
export const relayQuery = (maxWait = 4000): Query => async (relays, filter) => {
  const p = new SimplePool();
  try { return await p.querySync(relays, filter as any, { maxWait }); } finally { p.close(relays); }
};

/** One round trip to a server's host key, once connected: a sealed `ping`, answered `pong`. Null if none in `ms`. */
export async function pingHost(s: Server, ms = 5000): Promise<number | null> {
  const sk = generateSecretKey(), me = getPublicKey(sk);
  const ck = nip44.v2.utils.getConversationKey(sk, s.pk);
  const id = bytesToHex(generateSecretKey().slice(0, 8));
  const p = new SimplePool();
  let t0 = Date.now();
  try {
    return await new Promise<number | null>(resolve => {
      const timer = setTimeout(() => { sub.close(); resolve(null); }, ms);
      const sub = p.subscribeMany(s.relays, { kinds: [KIND_MEMBER], '#p': [me], authors: [s.pk], since: Math.floor(t0 / 1000) - 5 } as any, {
        onevent: e => {
          try { if (JSON.parse(nip44.v2.decrypt(e.content, ck)).id === id) { clearTimeout(timer); sub.close(); resolve(Date.now() - t0); } } catch { /* not ours */ }
        },
        oneose: () => {
          const msg = JSON.stringify({ type: 'ping', id });
          const ev = finalizeEvent({ kind: KIND_MEMBER, created_at: Math.floor(Date.now() / 1000), tags: [['p', s.pk]], content: nip44.v2.encrypt(msg, ck) }, sk);
          t0 = Date.now(); // the round trip, not the connecting
          void Promise.allSettled(p.publish(s.relays, ev));
        },
      });
    });
  } finally { p.close(s.relays); }
}
