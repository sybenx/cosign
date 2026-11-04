// Grants (Doors §1–§2): a site's or app's permission to use the account, kept on the devices and never on a
// Keykin server. Each entry is signed by the device that made it (its home); each device publishes its grants
// as one kind 30078 event, signed by the account, under a `d` relays can't link to a member key, encrypted
// under the current data key. Every device reads every maker's newest event, so grants can be listed and
// signed out anywhere; a grant ended once never comes back (the union of ended ids); a removed device's grants
// are gone everywhere. A grant applies only on its own connection: synced copies are for listing and signing out.
//
// Not yet: the counted-relay majorities and adopt-own-newest checks (§2) — this publishes to the account's
// relays and reads whatever they hold; decrypt-to-self evidence from signed metadata (§1) — decrypts are
// classified from their plaintext only.

import { Ledger } from './history.ts';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha, bytesToHex, hexToBytes, randomBytes, jcs, utf8ToBytes, concatBytes, u64be, hkdf32, utf8Strict, strictJson, KeykinError } from '../src/bytes.ts';
import { schnorrSign, schnorrVerify, verifyEvent, type NostrEvent, type KeyPair } from '../src/event.ts';
import { base64 } from '@scure/base';

export type Scope = 'sign-in' | 'post' | 'lists' | 'dms' | 'private-data' | 'wallet' | `host:${string}`;
export const SCOPES: Scope[] = ['sign-in', 'post', 'lists', 'dms', 'private-data', 'wallet'];
export interface GrantEntry {
  id: string; v: number; site: string; says: string; door: 'nip07' | 'nip55' | 'nip46'; connection: string;
  relays?: string[]; signer?: string; scopes: Scope[]; borrowed: boolean; helper: boolean;
  made: number; expiry: 'unused-90d' | number | null; by: string; by_sig?: string; was?: [string, string];
  /** The home's day of last use (unix seconds, at most one republish a day): other devices read it for expiry. */
  last_used?: number;
}
export interface Ended { id: string; until: number }
export interface UnionEnded { by: string; id: string; until: number }
export interface Tombstone { by: string; id: string; at: number }
export interface GrantSet { entries: GrantEntry[]; tombstones: Tombstone[]; ended: Ended[]; union: UnionEnded[] }

export const KIND_GRANTS = 30078;
const PART_PLAIN = 17_000;                          // a part's plaintext: its base64 ciphertext stays under 24 KB
const MAX_PARTS = 64;                               // ~1.5 MB of grants: more is refused, never read
const YEAR = 365 * 86400;

// --- entries -----------------------------------------------------------------------------------

const entryBody = (e: GrantEntry) => { const { by_sig: _s, ...rest } = e; return rest; };
export const entryDigest = (g: string, e: GrantEntry) => sha('keykin-grant/1', hexToBytes(g), jcs(entryBody(e)));
export function signEntry(g: string, kp: KeyPair, e: Omit<GrantEntry, 'by' | 'by_sig'>): GrantEntry {
  const full: GrantEntry = { ...e, by: kp.pub };
  return { ...full, by_sig: schnorrSign(entryDigest(g, full), kp.sk) };
}
export const entryOk = (g: string, e: GrantEntry) => { try { return schnorrVerify(e.by_sig!, entryDigest(g, e), e.by); } catch { return false; } };
/** "Unused 90 days": expired once `last_used` (or `made`) is that old; a fixed expiry, once passed. */
export const expired = (e: GrantEntry, now: number, lastUsed?: number) =>
  e.expiry === 'unused-90d' ? now - Math.max(lastUsed ?? 0, e.last_used ?? 0, e.made) > 90 * 86400 : typeof e.expiry === 'number' ? now > e.expiry : false;

// --- the event ---------------------------------------------------------------------------------

/** §2: `d = "keykin-grants:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF(base data key, "keykin-grants-d/1"), member key))`. */
export const grantsD = (baseDk: string, member: string) =>
  'keykin-grants:' + bytesToHex(hmac(sha256, hkdf32(hexToBytes(baseDk), 'keykin-grants-d/1'), hexToBytes(member)).slice(0, 16));
const contentKey = (dk: Uint8Array) => hkdf32(dk, 'keykin-grants/1');
const aad = (g: string, d: string, state: string) => concatBytes(hexToBytes(g), utf8ToBytes(d), hexToBytes(state));
export const setDigest = (g: string, d: string, createdAt: number, set: GrantSet) =>
  sha('keykin-grant-set/1', hexToBytes(g), utf8ToBytes(d), u64be(createdAt), sha(jcs({ entries: set.entries, tombstones: set.tombstones, ended: set.ended, union: set.union })));

/** The maker's event(s) for `set`, unsigned (the account signs them): one, or parts `d:1`, `d:2`, … with the
 *  same `created_at` and `["parts", n]`, each its own encrypted chunk of the JCS-encoded set. */
export function grantEvents(g: string, maker: KeyPair, baseDk: string, dk: { state: string; key: Uint8Array }, set: GrantSet, createdAt: number) {
  const d = grantsD(baseDk, maker.pub);
  const text = jcs({ ...set, maker_sig: schnorrSign(setDigest(g, d, createdAt, set), maker.sk) });
  const chunks: string[] = [];
  for (let k = 0; k < text.length; k += PART_PLAIN) chunks.push(text.slice(k, k + PART_PLAIN));
  const n = chunks.length;
  return chunks.map((c, k) => {
    const dd = n === 1 ? d : `${d}:${k + 1}`;
    const nonce = randomBytes(24);
    const ct = xchacha20poly1305(contentKey(dk.key), nonce, aad(g, dd, dk.state)).encrypt(utf8ToBytes(c));
    return { pubkey: g, created_at: createdAt, kind: KIND_GRANTS, tags: [['d', dd], ['state', dk.state], ...(n > 1 ? [['parts', String(n)]] : [])], content: base64.encode(concatBytes(nonce, ct)) };
  });
}

/** A maker's newest complete, verified set among `events`: account-signed, every part present and opened under
 *  the data key of the state it names, `maker_sig` by `maker`; null if none. */
export function readMaker(g: string, maker: string, baseDk: string, keyFor: (state: string) => Uint8Array | null, events: NostrEvent[]): { at: number; set: GrantSet } | null {
  const d = grantsD(baseDk, maker);
  const mine = events.filter((e) => e?.kind === KIND_GRANTS && e.pubkey === g && (dOf(e) === d || dOf(e)?.startsWith(d + ':')) && verifyEvent(e));
  for (const at of [...new Set(mine.map((e) => e.created_at))].sort((a, b) => b - a)) {
    const same = mine.filter((e) => e.created_at === at);
    try {
      const n = Number(same[0].tags.find((t) => t[0] === 'parts')?.[1] ?? '1');
      if (!Number.isInteger(n) || n < 1 || n > MAX_PARTS) continue;
      const parts = n === 1 ? [same.find((e) => dOf(e) === d)] : Array.from({ length: n }, (_, k) => same.find((e) => dOf(e) === `${d}:${k + 1}`));
      if (parts.some((p) => !p)) continue;
      const text = parts.map((p) => {
        const state = p!.tags.find((t) => t[0] === 'state')?.[1] ?? '';
        const key = keyFor(state); if (!key) throw new KeykinError('no_key');
        const b = base64.decode(p!.content);
        return utf8Strict(xchacha20poly1305(contentKey(key), b.slice(0, 24), aad(g, dOf(p!)!, state)).decrypt(b.slice(24)));
      }).join('');
      const x = strictJson(text);
      const set: GrantSet = { entries: x.entries ?? [], tombstones: x.tombstones ?? [], ended: x.ended ?? [], union: x.union ?? [] };
      if (!setShapeOk(set)) continue;
      if (!schnorrVerify(x.maker_sig, setDigest(g, d, at, set), maker)) continue;
      return { at, set };
    } catch { /* a part we can't open, or a forgery: the next older event */ }
  }
  return null;
}
const dOf = (e: NostrEvent) => e.tags.find((t) => t[0] === 'd')?.[1];
const hex = (x: unknown, n: number) => typeof x === 'string' && x.length === 2 * n && /^[0-9a-f]+$/.test(x);
const num = (x: unknown) => typeof x === 'number' && Number.isInteger(x) && x >= 0;
/** A signed set still has to be a set: each list an array of the right objects (review 16 L2). */
function setShapeOk(s: GrantSet): boolean {
  return Array.isArray(s.entries) && s.entries.every((e) => e && hex(e.id, 16) && num(e.v) && hex(e.by, 32) && Array.isArray(e.scopes) && e.scopes.every((x) => typeof x === 'string') && typeof e.site === 'string')
    && Array.isArray(s.tombstones) && s.tombstones.every((t) => t && hex(t.by, 32) && hex(t.id, 16) && num(t.at))
    && Array.isArray(s.ended) && s.ended.every((t) => t && hex(t.id, 16) && num(t.until))
    && Array.isArray(s.union) && s.union.every((t) => t && hex(t.by, 32) && hex(t.id, 16) && num(t.until));
}

// --- which scope a request needs (§1) ----------------------------------------------------------

export const WALLET_KINDS = new Set([17375, 37375, 7375, 7376, 7374, 10019]);
/** Device policy §2's list and set kinds, exactly; the profile and relay lists count as lists here. */
export const LIST_KINDS = new Set([0, 3, 10000, 10002, 10050, 10001, 10003, 10004, 10005, 10006, 10007, 10009, 10012, 10013, 10015, 10020, 10030, 10063, 10101, 10102,
  30000, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30015, 30030, 39089]);
const tagOf = (tags: string[][], n: string) => tags.find((t) => t[0] === n)?.[1];
const hostOf = (u: string | undefined) => { try { return u ? new URL(u).host.toLowerCase() : null; } catch { return null; } };
/** What signing an event needs (§1's table): its scopes (all of them), or `declined` (refused here; Device
 *  policy's Confirm card is the person's way to do it). NIP-98 (27235) and Blossom (24242) tokens are for the
 *  site's own host (`ownHost`, a NIP-07 origin's) under sign-in (PUT and PATCH under post); a token for another
 *  host also needs `host:<host>`, asked once per host; a Blossom upload, media or get bound to one blob by an `x`
 *  tag is silent; deletions by token are never silent (review 16 H1). */
export function scopesForEvent(kind: number, tags: string[][] = [], ownHost: string | null = null): Scope[] | 'declined' {
  if (kind === 22242) return ['sign-in'];
  if (kind === 27235) {
    const method = (tagOf(tags, 'method') ?? '').toUpperCase(), host = hostOf(tagOf(tags, 'u'));
    if (method === 'DELETE' || !host) return 'declined';
    const base: Scope[] = method === 'PUT' || method === 'PATCH' ? ['sign-in', 'post'] : ['sign-in'];
    return host === ownHost ? base : [...base, `host:${host}`];
  }
  if (kind === 24242) {
    const t = tagOf(tags, 't') ?? '';
    if (t === 'delete') return 'declined';
    if (['upload', 'media', 'get'].includes(t) && tags.filter((x) => x[0] === 'x').length === 1) return ['sign-in'];
    const host = hostOf(tagOf(tags, 'server')) ?? 'any';
    return host === ownHost ? ['sign-in'] : ['sign-in', `host:${host}`];
  }
  return [WALLET_KINDS.has(kind) ? 'wallet' : LIST_KINDS.has(kind) ? 'lists' : 'post'];
}
/** The single scope (for callers that need one): the first `scopesForEvent` names; `post` for a declined one. */
export function scopeForEvent(kind: number): Scope { return WALLET_KINDS.has(kind) ? 'wallet' : LIST_KINDS.has(kind) ? 'lists' : kind === 22242 ? 'sign-in' : 'post'; }

const LIST_TAGS = new Set(['p', 'e', 'a', 't', 'r', 'word', 'emoji', 'group', 'relay']);
const WALLET_FIELDS = new Set(['privkey', 'mint', 'proofs', 'direction', 'amount', 'unit', 'balance']);
/** A NIP-51 list plaintext of list tags only, with no wallet field (§1's check before any release under lists). */
export function listPlaintextOk(plain: string): boolean {
  try { const x = JSON.parse(plain); return Array.isArray(x) && x.every((t) => Array.isArray(t) && t.length >= 1 && t.every((v: unknown) => typeof v === 'string') && LIST_TAGS.has(t[0])); }
  catch { return false; }
}
/** Plaintext that looks like a wallet's: a NIP-60 token object (`mint`, `proofs`) or tags with wallet fields. */
export function looksWallet(plain: string): boolean {
  try {
    const x = JSON.parse(plain);
    if (x && typeof x === 'object' && !Array.isArray(x)) return 'proofs' in x || 'mint' in x || 'privkey' in x;
    return Array.isArray(x) && x.some((t) => Array.isArray(t) && WALLET_FIELDS.has(t[0]));
  } catch { return false; }
}
const RANK: Record<string, number> = { 'private-data': 3, wallet: 2, lists: 1, dms: 0 };
/** What this device knows of the account's own ciphertexts (Device policy §1's metadata): by the SHA-256 of
 *  each ciphertext's decoded bytes, the account events carrying it, as `kind:signer` (the grant `${by}:${id}`
 *  that got it signed, or `member`), and who encrypted it (a grant, or `member`). An event is evidence only if
 *  the same grant, or the member app, both encrypted and signed it (Doors §1; review 17 M1). */
export class Evidence {
  kinds = new Map<string, Set<string>>();
  owners = new Map<string, Set<string>>();
  /** Device policy §1's records (grant per event, deletions, removal logs, references), synced with these. */
  ledger = new Ledger();
  /** Records per owner: a site can't crowd out the member app's (review 17 H2). */
  static readonly PER_OWNER = 2000;
  #count = new Map<string, number>();
  static hashOf(payload: string): string | null {
    try { const b = base64.decode(payload); return base64.encode(b) === payload ? bytesToHex(sha256(b)) : null; } catch { return null; }
  }
  encrypted(payload: string, owner: 'member' | string) {
    const h = Evidence.hashOf(payload); if (!h) return;
    const s = this.owners.get(h) ?? new Set(); if (s.has(owner)) return;
    if (owner !== 'member' && (this.#count.get(owner) ?? 0) >= Evidence.PER_OWNER) return;
    s.add(owner); this.owners.set(h, s); this.#count.set(owner, (this.#count.get(owner) ?? 0) + 1); this.#cap();
  }
  /** An account event this device signed (for `signer`) or fetched (verified by the caller). */
  event(kind: number, content: string, signer = 'member') {
    const h = Evidence.hashOf(content); if (!h) return;
    const s = this.kinds.get(h) ?? new Set(); s.add(`${kind}:${signer}`); this.kinds.set(h, s); this.#cap();
  }
  /** The kinds of the events carrying `h` that are evidence: signed by an owner of its encryption. */
  vouched(h: string): number[] {
    const os = this.owners.get(h); if (!os) return [];
    return [...(this.kinds.get(h) ?? [])].map((x) => { const i = x.indexOf(':'); return [Number(x.slice(0, i)), x.slice(i + 1)] as [number, string]; }).filter(([, sg]) => os.has(sg)).map(([k]) => k);
  }
  allKinds(h: string): number[] { return [...(this.kinds.get(h) ?? [])].map((x) => Number(x.slice(0, x.indexOf(':')))); }
  /** The oldest records go first, when a month must fit its parts. */
  trim(n: number, now?: number) { for (const m of [this.kinds, this.owners] as Map<string, unknown>[]) for (const k of [...m.keys()].slice(0, n)) m.delete(k); this.ledger.trim(n, now); this.#recount(); }
  size() { return this.kinds.size + this.owners.size + this.ledger.size(); }
  #recount() { this.#count.clear(); for (const os of this.owners.values()) for (const o of os) this.#count.set(o, (this.#count.get(o) ?? 0) + 1); }
  #cap() { for (const m of [this.kinds, this.owners] as Map<string, unknown>[]) while (m.size > 20_000) m.delete(m.keys().next().value!); }
  dump() { return { kinds: [...this.kinds].map(([h, k]) => [h, [...k]]), owners: [...this.owners].map(([h, o]) => [h, [...o]]), ledger: this.ledger.data() }; }
  load(x: any) {
    this.kinds = new Map((x?.kinds ?? []).map(([h, k]: [string, unknown[]]) => [h, new Set(k.map((y) => (typeof y === 'number' ? `${y}:member` : String(y))))]));
    this.owners = new Map((x?.owners ?? []).map(([h, o]: [string, string[]]) => [h, new Set(o)])); this.#recount();
    this.ledger = new Ledger(); this.ledger.take(x?.ledger, () => true);
  }
  clear() { this.kinds.clear(); this.owners.clear(); this.#count.clear(); this.ledger.clear(); }
}
/** The scope a decrypt needs (§1, "Which scope a decrypt needs"). With someone else's key, `dms`. To the account
 *  itself: the payload must be canonical base64, and is matched against the account's own events; an event counts
 *  as evidence only if its ciphertext was encrypted for the same grant (`owner`) or the member app. Matched kinds
 *  decide, the most private winning (private-data, then wallet, then lists; a kind 4 or 14 to self is dms). With
 *  no encrypt record, a list kind's ciphertext matching no wallet or private-data event needs lists. Whatever the
 *  evidence, lists is released only for a list plaintext; a wallet-looking one needs wallet. Unmatched bytes: a
 *  NIP-17 rumor of the account's own (14, 15, 7, 5) is dms, a wallet-looking plaintext wallet, else private-data. */
export function scopeForDecrypt(g: string, peer: string, plaintext?: string, o: { payload?: string; evidence?: Evidence; owner?: string } = {}): Scope | 'malformed' {
  if (peer.toLowerCase() !== g) return 'dms';
  if (plaintext === undefined) return 'private-data';
  const h = o.payload !== undefined ? Evidence.hashOf(o.payload) : null;
  if (o.payload !== undefined && !h) return 'malformed';
  const ofKind = (k: number): Scope => (WALLET_KINDS.has(k) ? 'wallet' : LIST_KINDS.has(k) ? 'lists' : k === 4 || k === 14 ? 'dms' : 'private-data');
  let need: Scope | null = null;
  if (h && o.evidence) {
    // Evidence: events whose ciphertext the same grant (or the member app) both encrypted and got signed.
    const vouched = o.evidence.vouched(h).map(ofKind);
    const all = o.evidence.allKinds(h).map(ofKind);
    if (vouched.length) need = [...vouched, ...all.filter((c) => RANK[c] > RANK.lists)].reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
    // With no encrypt record at all (no metadata to hand): a list kind's bytes matching no wallet or private event.
    else if (!o.evidence.owners.get(h)?.size && all.length && all.every((c) => c === 'lists')) need = 'lists';
  }
  if (need === 'lists' && !listPlaintextOk(plaintext)) need = looksWallet(plaintext) ? 'wallet' : 'private-data';
  if (need === 'dms' || need === 'wallet' || need === 'private-data' || need === 'lists') return need === 'private-data' && looksWallet(plaintext) ? 'wallet' : need;
  try { const x = JSON.parse(plaintext); if (x && typeof x === 'object' && !Array.isArray(x) && x.pubkey === g && [14, 15, 7, 5].includes(x.kind)) return 'dms'; } catch { /* not JSON */ }
  return looksWallet(plaintext) ? 'wallet' : 'private-data';
}

// --- one device's store ------------------------------------------------------------------------

/** What a device needs of itself for its grants. */
export interface GrantHost { g: string; kp: KeyPair; baseDk: string; now: number; currentDevices(): Set<string>;
  dataKey(): { state: string; key: Uint8Array }; keyFor(state: string): Uint8Array | null;
  sign(ev: { kind: number; created_at: number; tags: string[][]; content: string }): Promise<NostrEvent>;
  publish(e: NostrEvent): Promise<void>; query(): Promise<{ events: NostrEvent[]; answered: number; asked: number }> }

export class GrantStore {
  own = new Map<string, GrantEntry>();               // id → this device's entries
  tombstones: Tombstone[] = [];                      // ends this device made of others' grants
  ended: Ended[] = [];                               // this device's own ended ids
  union = new Map<string, UnionEnded>();             // `${by}:${id}` → every maker's ended ids
  others = new Map<string, { at: number; set: GrantSet }>();   // maker → its newest verified set
  lastUsed = new Map<string, number>();
  lastPublish = 0;
  readonly h: GrantHost;
  constructor(h: GrantHost) { this.h = h; }

  /** A new grant, from a human act on this device only (live finding #15). */
  make(o: { site: string; says: string; door: GrantEntry['door']; connection: string; scopes: Scope[]; relays?: string[]; signer?: string; expiry?: GrantEntry['expiry']; helper?: boolean; borrowed?: boolean }): GrantEntry {
    const e = signEntry(this.h.g, this.h.kp, { id: bytesToHex(randomBytes(16)), v: 1, site: o.site, says: o.says, door: o.door, connection: o.connection,
      ...(o.relays ? { relays: o.relays } : {}), ...(o.signer ? { signer: o.signer } : {}), scopes: [...new Set(o.scopes)].sort() as Scope[],
      borrowed: !!o.borrowed, helper: !!o.helper, made: this.h.now, expiry: o.expiry ?? 'unused-90d' });
    this.own.set(e.id, e);
    return e;
  }
  /** More scopes for an own grant (asked the first time they are needed): `v` goes up. */
  widen(id: string, scopes: Scope[]): GrantEntry {
    const e = this.own.get(id); if (!e) throw new KeykinError('unknown_grant');
    const { by: _b, by_sig: _s, ...rest } = e;
    const w = signEntry(this.h.g, this.h.kp, { ...rest, v: e.v + 1, scopes: [...new Set([...e.scopes, ...scopes])].sort() as Scope[] });
    this.own.set(id, w); return w;
  }
  /** Sign out one grant, anywhere: an own one ends here; another device's gets a tombstone for its home. */
  end(by: string, id: string) {
    const until = (e?: GrantEntry) => (typeof e?.expiry === 'number' ? e.expiry + 30 * 86400 : this.h.now + YEAR);
    if (by === this.h.kp.pub) {
      const e = this.own.get(id); this.own.delete(id);
      if (!this.ended.some((x) => x.id === id)) this.ended.push({ id, until: until(e) });
      this.union.set(`${by}:${id}`, { by, id, until: until(e) });
    } else if (!this.tombstones.some((t) => t.by === by && t.id === id)) this.tombstones.push({ by, id, at: this.h.now });
  }
  /** Every live grant on the account, for listing: own and others', newest per (by, id), never one ended, never
   *  one whose maker isn't a current device. */
  all(): GrantEntry[] {
    const cur = this.h.currentDevices(), out = new Map<string, GrantEntry>();
    const consider = (e: GrantEntry, maker: string) => {
      if (e.by !== maker || !cur.has(e.by) || !entryOk(this.h.g, e)) return;
      const k = `${e.by}:${e.id}`;
      if (this.union.has(k) || this.tombstones.some((t) => t.by === e.by && t.id === e.id)) return;
      const prev = out.get(k);
      if (!prev || e.v > prev.v || (e.v === prev.v && narrower(e.scopes, prev.scopes))) out.set(k, e);
    };
    for (const e of this.own.values()) consider(e, this.h.kp.pub);
    for (const [m, { set }] of this.others) if (m !== this.h.kp.pub) for (const e of set.entries) consider(e, m);
    return [...out.values()].filter((e) => !expired(e, this.h.now, this.lastUsed.get(e.id)));
  }
  /** An own grant for this site on this connection (a grant applies only there). */
  forSite(site: string, door: GrantEntry['door'], connection?: string): GrantEntry | null {
    for (const e of this.own.values()) if (e.site === site && e.door === door && (connection === undefined || e.connection === connection) && !expired(e, this.h.now, this.lastUsed.get(e.id)) && !this.union.has(`${e.by}:${e.id}`)) return e;
    return null;
  }
  /** A use of an own grant: recorded, and once a day put in the entry (re-signed), for other devices' expiry. */
  used(id: string) {
    this.lastUsed.set(id, this.h.now);
    const e = this.own.get(id); if (!e) return;
    const day = Math.floor(this.h.now / 86400) * 86400;
    if ((e.last_used ?? 0) < day) { const { by: _b, by_sig: _s, ...rest } = e; this.own.set(id, signEntry(this.h.g, this.h.kp, { ...rest, last_used: day })); this.dirty = true; }
  }
  /** Own grants changed since the last publish. */
  dirty = false;
  /** When a fetch last heard from more than half of the relays asked (§2: a publish follows a good fetch). */
  goodFetchAt = 0;
  #chain: Promise<unknown> = Promise.resolve();

  /** This device's set as it publishes it: own live entries, its tombstones (30 days), its ended list and the
   *  union, each dropped after its `until`, the union kept only for current makers. */
  set(): GrantSet {
    const now = this.h.now, cur = this.h.currentDevices();
    this.ended = this.ended.filter((x) => x.until > now);
    for (const [k, u] of this.union) if (u.until <= now || !cur.has(u.by)) this.union.delete(k);
    this.tombstones = this.tombstones.filter((t) => now - t.at < 30 * 86400 || [...this.others.values()].some((o) => o.set.entries.some((e) => e.by === t.by && e.id === t.id)));
    return { entries: [...this.own.values()].filter((e) => !expired(e, now, this.lastUsed.get(e.id))).sort((a, b) => (a.id < b.id ? -1 : 1)),
      tombstones: [...this.tombstones], ended: [...this.ended], union: [...this.union.values()].sort((a, b) => (`${a.by}:${a.id}` < `${b.by}:${b.id}` ? -1 : 1)) };
  }
  /** Publish this device's grant event, signed by the account, under the current data key. */
  async publish(): Promise<NostrEvent[]> {
    // One at a time, so two publishes never sign two sets at one created_at (review 16 L6).
    const run = this.#chain.then(() => this.#publish(), () => this.#publish());
    this.#chain = run.catch(() => {});
    return run;
  }
  async #publish(): Promise<NostrEvent[]> {
    // Never publish over a copy this device hasn't read: a restored copy must take over its own newest event
    // first, or it would publish an older set over it (§2; review 16, the fetch-before-publish gate).
    if (!this.goodFetchAt) await this.fetch();
    if (!this.goodFetchAt) throw new KeykinError('try_later', 'relays did not answer the grant fetch');
    const at = Math.max(this.h.now, this.lastPublish + 1);
    const evs = grantEvents(this.h.g, this.h.kp, this.h.baseDk, this.h.dataKey(), this.set(), at);
    const signed: NostrEvent[] = [];
    for (const e of evs) signed.push(await this.h.sign(e));
    this.lastPublish = at;
    for (const e of signed) await this.h.publish(e);
    this.dirty = false;
    return signed;
  }
  /** Read every current device's newest grant event: others' sets for listing, their ended ids into the union,
   *  their tombstones for this device's own grants applied; and this device's own newest, if newer than its
   *  last publish (a restored copy), taken over: ended ids and tombstones always, entries made before it. */
  async fetch() {
    const { events: evs, answered, asked } = await this.h.query();
    if (asked > 0 && answered * 2 > asked) this.goodFetchAt = this.h.now;
    for (const m of this.h.currentDevices()) {
      const got = readMaker(this.h.g, m, this.h.baseDk, (s) => this.h.keyFor(s), evs);
      if (!got) continue;
      if (m === this.h.kp.pub) { this.#adoptOwn(got); continue; }
      const prev = this.others.get(m);
      if (!prev || got.at > prev.at) this.others.set(m, got);
      for (const x of got.set.ended) this.#unite({ by: m, id: x.id, until: x.until });
      for (const u of got.set.union) if (this.h.currentDevices().has(u.by)) this.#unite(u);
      for (const t of got.set.tombstones) if (t.by === this.h.kp.pub && this.own.has(t.id)) this.end(t.by, t.id);
    }
    for (const u of this.union.values()) if (u.by === this.h.kp.pub && this.own.has(u.id)) this.end(u.by, u.id);
  }
  /** A union entry: the later `until` wins, so no member can shorten another's (review 16 L1). */
  #unite(u: UnionEnded) { const k = `${u.by}:${u.id}`, p = this.union.get(k); if (!p || u.until > p.until) this.union.set(k, { by: u.by, id: u.id, until: u.until }); }
  #adoptOwn(got: { at: number; set: GrantSet }) {
    for (const x of got.set.ended) { if (!this.ended.some((y) => y.id === x.id)) this.ended.push(x); this.own.delete(x.id); this.union.set(`${this.h.kp.pub}:${x.id}`, { by: this.h.kp.pub, id: x.id, until: x.until }); }
    for (const t of got.set.tombstones) if (!this.tombstones.some((y) => y.by === t.by && y.id === t.id)) this.tombstones.push(t);
    if (got.at <= this.lastPublish) return;
    const there = new Set(got.set.entries.map((e) => e.id));
    for (const [id, e] of this.own) if (e.made < got.at && !there.has(id)) this.own.delete(id);
    for (const e of got.set.entries) { const mine = this.own.get(e.id); if (e.by === this.h.kp.pub && entryOk(this.h.g, e) && (!mine || e.v > mine.v) && !this.union.has(`${e.by}:${e.id}`)) this.own.set(e.id, e); }
    this.lastPublish = got.at;
  }

  dump() { return { own: [...this.own.values()], tombstones: this.tombstones, ended: this.ended, union: [...this.union.values()], others: [...this.others], lastUsed: [...this.lastUsed], lastPublish: this.lastPublish }; }
  load(x: any) {
    if (!x) return;
    this.own = new Map((x.own ?? []).map((e: GrantEntry) => [e.id, e])); this.tombstones = x.tombstones ?? []; this.ended = x.ended ?? [];
    this.union = new Map((x.union ?? []).map((u: UnionEnded) => [`${u.by}:${u.id}`, u])); this.others = new Map(x.others ?? []);
    this.lastUsed = new Map(x.lastUsed ?? []); this.lastPublish = x.lastPublish ?? 0;
  }
  clear() { this.own.clear(); this.tombstones = []; this.ended = []; this.union.clear(); this.others.clear(); this.lastUsed.clear(); }
}
const narrower = (a: Scope[], b: Scope[]) => a.length < b.length && a.every((s) => b.includes(s));
