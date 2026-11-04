// Device policy §1's metadata, synced: what a device knows of the account's own ciphertexts (Doors §1's
// evidence: which grant, or the member app, encrypted each one, and the kinds of the account's events that
// carry it), so every device judges a decrypt on every device's records. Each device publishes one cumulative
// snapshot per month, split into parts at 24 KB, each part with its own sequence number and signed by its member
// key, part 0 listing every part's number and hash; and one index event naming each live month and its parts.
// All are account-signed kind 30078 under `keykin-meta…` d's relays can't link to a member key, encrypted under
// the data key with g, d and the state as associated data. A reader takes the index first, never a lower number
// than it has seen, and only parts the index names; only a current device's snapshots count.
//
// Each month also carries Device policy §1's records (device/history.ts's Ledger): grant per event, deletions,
// removal logs, pre-site and last-approved versions. Not yet: entries' retention by whether their event is
// current (months are kept 13 months instead).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { sha, bytesToHex, hexToBytes, randomBytes, jcs, utf8ToBytes, concatBytes, hkdf32, utf8Strict, strictJson, KeykinError } from '../src/bytes.ts';
import { schnorrSign, schnorrVerify, verifyEvent, type NostrEvent, type KeyPair } from '../src/event.ts';
import { Evidence } from './grants.ts';

export const KIND_META = 30078;
const PART_PLAIN = 16_000;
const MAX_PARTS = 64, KEEP_MONTHS = 13;

export const monthOf = (unix: number) => new Date(unix * 1000).toISOString().slice(0, 7);
/** The last `n` calendar months up to `unix`'s, as YYYY-MM (review 17 M4: never by 30-day steps). */
export function lastMonths(unix: number, n: number): string[] {
  const d = new Date(unix * 1000); let y = d.getUTCFullYear(), m = d.getUTCMonth() + 1;
  const out: string[] = [];
  for (let k = 0; k < n; k++) { out.push(`${y}-${String(m).padStart(2, '0')}`); if (--m === 0) { m = 12; y--; } }
  return out;
}
const u16 = (n: number) => new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
const metaKey = (baseDk: string) => hkdf32(hexToBytes(baseDk), 'keykin-meta-d/1');
/** §1: `d = "keykin-meta:" ‖ hex(HMAC-SHA256(HKDF(base data key, "keykin-meta-d/1"), member key ‖ month ‖ part))`. */
export const metaD = (baseDk: string, member: string, month: string, part: number) =>
  'keykin-meta:' + bytesToHex(hmac(sha256, metaKey(baseDk), concatBytes(hexToBytes(member), utf8ToBytes(month), u16(part))));
/** The index: the same HMAC without month or part. */
export const indexD = (baseDk: string, member: string) => 'keykin-meta-index:' + bytesToHex(hmac(sha256, metaKey(baseDk), hexToBytes(member)));
const contentKey = (dk: Uint8Array) => hkdf32(dk, 'keykin-meta/1');
const aad = (g: string, d: string, state: string) => concatBytes(hexToBytes(g), utf8ToBytes(d), hexToBytes(state));
const partDigest = (g: string, d: string, body: unknown) => sha('keykin-meta/1', hexToBytes(g), utf8ToBytes(d), jcs(body));
const indexDigest = (g: string, d: string, body: unknown) => sha('keykin-meta-index/1', hexToBytes(g), utf8ToBytes(d), jcs(body));

/** What a month holds, as it is published: encrypt records `[hash, owner]` and events `[hash, kind, signer]`, and
 *  Device policy §1's records (device/history.ts's Ledger: `signed`, `dels`, `removed`, `added`, `presite`,
 *  `approved`). */
export interface MonthData { encrypt: [string, string][]; events: [string, number, string][]; [k: string]: unknown }
const toData = (e: Evidence): MonthData => ({
  ...e.ledger.data(),
  encrypt: [...e.owners].flatMap(([h, os]) => [...os].map((o) => [h, o] as [string, string])),
  events: [...e.kinds].flatMap(([h, ks]) => [...ks].map((x) => { const i = x.indexOf(':'); return [h, Number(x.slice(0, i)), x.slice(i + 1)] as [string, number, string]; })),
});
const HASH = /^[0-9a-f]{64}$/;
/** A maker's records: only its member app or its own grants (`${maker}:…`) can be an owner or a signer (review 17
 *  L5); a malformed entry costs only itself (L4). */
const fromData = (x: MonthData, into = new Evidence(), maker?: string) => {
  const mine = (o: unknown) => typeof o === 'string' && (o === 'member' || maker === undefined || o.startsWith(`${maker}:`));
  for (const r of Array.isArray(x?.encrypt) ? x.encrypt : []) if (Array.isArray(r) && HASH.test(String(r[0])) && mine(r[1])) { const s = into.owners.get(r[0]) ?? new Set(); s.add(r[1]); into.owners.set(r[0], s); }
  for (const r of Array.isArray(x?.events) ? x.events : []) if (Array.isArray(r) && HASH.test(String(r[0])) && Number.isInteger(r[1]) && r[1] >= 0 && r[1] <= 65535 && mine(r[2])) {
    const s = into.kinds.get(r[0]) ?? new Set(); s.add(`${r[1]}:${r[2]}`); into.kinds.set(r[0], s);
  }
  into.ledger.take(x, mine);
  return into;
};

export interface MetaHost { g: string; kp: KeyPair; baseDk: string; now: number; currentDevices(): Set<string>;
  dataKey(): { state: string; key: Uint8Array }; keyFor(state: string): Uint8Array | null;
  sign(ev: { kind: number; created_at: number; tags: string[][]; content: string }): Promise<NostrEvent>;
  publish(e: NostrEvent): Promise<void>; query(f: { '#d': string[] }): Promise<{ events: NostrEvent[]; answered: number; asked: number }> }

export class MetaStore {
  readonly h: MetaHost;
  /** This device's records, by month. */
  own = new Map<string, Evidence>();
  /** What this device last published: per month, each part's sequence number and hash; the index's number. */
  sent = new Map<string, { seq: number; hash: string }[]>();
  indexSeq = 0;
  lastAt = 0;
  dirty = new Set<string>();
  /** A month's change count: a publish clears only what it saw (records made during it stay dirty, M3). */
  #gen = new Map<string, number>();
  /** Other devices' records, by maker and month, and the highest numbers seen (never lower: no rollback). */
  others = new Map<string, Map<string, Evidence>>();
  seenIndex = new Map<string, number>();
  seenPart = new Map<string, number>();
  #merged: Evidence | null = null;
  #mergedFor = '';
  constructor(h: MetaHost) { this.h = h; }

  #bucket(): Evidence { const m = monthOf(this.h.now); let e = this.own.get(m); if (!e) { e = new Evidence(); this.own.set(m, e); } this.dirty.add(m); this.#gen.set(m, (this.#gen.get(m) ?? 0) + 1); this.#merged = null; return e; }
  /** An encryption to the account's own key this device made, for a grant `${by}:${id}` or the member app. */
  encrypted(payload: string, owner: string) { this.#bucket().encrypted(payload, owner); }
  /** An account event this device signed (for `signer`, a grant or the member app) or fetched. */
  event(kind: number, content: string, signer = 'member') { if (Evidence.hashOf(content)) this.#bucket().event(kind, content, signer); }
  /** Add to this month's policy records (Device policy §1); the merged view is rebuilt after. */
  record(f: (l: import('./history.ts').Ledger) => void) { const b = this.#bucket(); f(b.ledger); this.#merged = null; }
  /** Every current device's records together: what a decrypt is judged on. */
  evidence(): Evidence {
    const cur = this.h.currentDevices(), key = [...cur].sort().join();
    // Rebuilt when the devices change, so a removed device's records stop counting at once (review 17 L1).
    if (this.#merged && this.#mergedFor === key) return this.#merged;
    const all = new Evidence();
    for (const e of this.own.values()) fromData(toData(e), all);
    for (const [m, months] of this.others) if (cur.has(m)) for (const e of months.values()) fromData(toData(e), all, m);
    this.#mergedFor = key;
    return (this.#merged = all);
  }

  /** Publish what changed: the changed months' parts (part 0 with every change) and the index. */
  async publish(): Promise<NostrEvent[]> {
    const keep = new Set(lastMonths(this.h.now, KEEP_MONTHS));
    for (const m of [...this.own.keys()]) if (!keep.has(m)) { this.own.delete(m); this.sent.delete(m); }
    if (!this.dirty.size) return [];
    const { g, kp, baseDk } = this.h, dk = this.h.dataKey(), at = Math.max(this.h.now, this.lastAt + 1);
    const out: NostrEvent[] = [];
    const seal = async (d: string, body: object, digest: Uint8Array) => {
      const text = jcs({ ...body, sig: schnorrSign(digest, kp.sk) });
      const nonce = randomBytes(24);
      const ct = xchacha20poly1305(contentKey(dk.key), nonce, aad(g, d, dk.state)).encrypt(utf8ToBytes(text));
      out.push(await this.h.sign({ kind: KIND_META, created_at: at, tags: [['d', d], ['state', dk.state]], content: base64.encode(concatBytes(nonce, ct)) }));
    };
    const sent = new Map(this.sent), seen = new Map([...this.dirty].map((m) => [m, this.#gen.get(m) ?? 0]));
    for (const month of [...this.dirty].filter((m) => this.own.has(m))) {
      // A month that won't fit its parts sheds its oldest records, never the whole sync (review 17 H2).
      let text = jcs(toData(this.own.get(month)!));
      while (Math.ceil(text.length / PART_PLAIN) > MAX_PARTS) { this.own.get(month)!.trim(Math.ceil(this.own.get(month)!.size() / 10)); text = jcs(toData(this.own.get(month)!)); this.#merged = null; }
      const chunks: string[] = []; for (let k = 0; k < text.length; k += PART_PLAIN) chunks.push(text.slice(k, k + PART_PLAIN));
      if (!chunks.length) chunks.push('');
      const prev = sent.get(month) ?? [];
      const parts = chunks.map((c, k) => {
        const hash = bytesToHex(sha256(utf8ToBytes(c)));
        // An unchanged part keeps its number; part 0 is new with every change, as it lists the others.
        const same = prev[k]?.hash === hash && k > 0;
        return { seq: same ? prev[k].seq : (prev[k]?.seq ?? 0) + 1, hash, data: c, changed: !same };
      });
      for (const [k, p] of parts.entries()) if (p.changed) {
        const d = metaD(baseDk, kp.pub, month, k);
        const body = { seq: p.seq, month, part: k, data: p.data, ...(k === 0 ? { parts: parts.map((x) => [x.seq, x.hash]) } : {}) };
        await seal(d, body, partDigest(g, d, body));
      }
      sent.set(month, parts.map(({ seq, hash }) => ({ seq, hash })));
    }
    const indexSeq = this.indexSeq + 1;
    const d = indexD(baseDk, kp.pub);
    const body = { seq: indexSeq, months: Object.fromEntries([...sent].map(([m, ps]) => [m, ps.map((p) => p.seq)])) };
    await seal(d, body, indexDigest(g, d, body));
    for (const e of out) await this.h.publish(e);
    // Only now, with every event handed to the relays, is it what this device sent (review 17 M3).
    this.sent = sent; this.indexSeq = indexSeq; this.lastAt = at;
    for (const [m, gen] of seen) if ((this.#gen.get(m) ?? 0) === gen) this.dirty.delete(m);
    return out;
  }

  /** Read every other current device's snapshots: its index first, then the months and parts it names. */
  async fetch() {
    const { g, baseDk } = this.h;
    const cur = [...this.h.currentDevices()];
    // The indexes first, by d (a site's own 30078 events can't crowd them out, review 17 M6), then what they name.
    const ixEvents = (await this.h.query({ '#d': cur.map((m) => indexD(baseDk, m)) })).events;
    const named: string[] = [];
    for (const m of cur) for (const e of ixEvents) if (e.tags?.some((t: string[]) => t[0] === 'd' && t[1] === indexD(baseDk, m))) {
      const x = (() => { try { const st = e.tags.find((t: string[]) => t[0] === 'state')?.[1] ?? ''; const k = this.h.keyFor(st); if (!k) return null; const b = base64.decode(e.content); return strictJson(utf8Strict(xchacha20poly1305(contentKey(k), b.slice(0, 24), aad(g, indexD(baseDk, m), st)).decrypt(b.slice(24)))); } catch { return null; } })();
      for (const [month, seqs] of Object.entries(x?.months ?? {}) as [string, number[]][]) if (Array.isArray(seqs)) for (let k = 0; k < Math.min(seqs.length, MAX_PARTS); k++) named.push(metaD(baseDk, m, month, k));
    }
    const events = [...ixEvents, ...(named.length ? (await this.h.query({ '#d': named })).events : [])];
    const open = (e: NostrEvent): any => {
      const d = e.tags.find((t) => t[0] === 'd')?.[1] ?? '', state = e.tags.find((t) => t[0] === 'state')?.[1] ?? '';
      const key = this.h.keyFor(state); if (!key) return null;
      try { const b = base64.decode(e.content); return strictJson(utf8Strict(xchacha20poly1305(contentKey(key), b.slice(0, 24), aad(g, d, state)).decrypt(b.slice(24)))); } catch { return null; }
    };
    const byD = new Map<string, NostrEvent[]>();
    for (const e of events) if (e?.kind === KIND_META && e.pubkey === g && verifyEvent(e)) { const d = e.tags.find((t) => t[0] === 'd')?.[1]; if (d) byD.set(d, [...(byD.get(d) ?? []), e]); }
    const newest = (d: string, ok: (x: any) => boolean) => {
      for (const e of (byD.get(d) ?? []).sort((a, b) => b.created_at - a.created_at)) { const x = open(e); if (x && ok(x)) return x; }
      return null;
    };
    for (const m of this.h.currentDevices()) {
      const id = indexD(baseDk, m);
      const ix = newest(id, (x) => { const { sig, ...b } = x; return Number.isInteger(b.seq) && schnorrVerify(sig, indexDigest(g, id, b), m); });
      // A restored copy of this device continues its own numbers above what it published before (review 17 L2).
      if (m === this.h.kp.pub) {
        if (ix && ix.seq > this.indexSeq) {
          this.indexSeq = ix.seq;
          for (const [month, seqs] of Object.entries(ix.months ?? {}) as [string, number[]][]) if (Array.isArray(seqs) && !this.sent.has(month)) { this.sent.set(month, seqs.map((q) => ({ seq: Number(q) || 0, hash: '' }))); this.dirty.add(month); }
        }
        continue;
      }
      if (!ix || ix.seq < (this.seenIndex.get(m) ?? 0)) continue;
      this.seenIndex.set(m, ix.seq);
      const months = new Map<string, Evidence>();
      for (const [month, seqs] of Object.entries(ix.months ?? {}) as [string, number[]][]) {
        if (!/^\d{4}-\d{2}$/.test(month) || !Array.isArray(seqs) || !seqs.length || seqs.length > MAX_PARTS) continue;
        const parts: any[] = [];
        for (let k = 0; k < seqs.length; k++) {
          const d = metaD(baseDk, m, month, k), key = `${m}:${month}:${k}`;
          const x = newest(d, (p) => { const { sig, ...b } = p; return b.part === k && b.month === month && Number.isInteger(b.seq) && b.seq >= seqs[k] && b.seq >= (this.seenPart.get(key) ?? 0) && schnorrVerify(sig, partDigest(g, d, b), m); });
          if (!x) break;
          parts.push(x);
        }
        // Anything short of a whole, consistent month keeps what was read before (review 17 M2).
        const prev = this.others.get(m)?.get(month);
        const keepPrev = () => { if (prev) months.set(month, prev); };
        if (parts.length !== seqs.length) { keepPrev(); continue; }
        // Part 0 names every part's number and hash: a stale or swapped part is caught.
        const list: [number, string][] = Array.isArray(parts[0].parts) ? parts[0].parts : [];
        if (list.length !== parts.length || parts.some((p, k) => !Array.isArray(list[k]) || list[k][0] !== p.seq || list[k][1] !== bytesToHex(sha256(utf8ToBytes(p.data))))) { keepPrev(); continue; }
        try { months.set(month, fromData(strictJson(parts.map((p) => p.data).join('')), new Evidence(), m)); } catch { keepPrev(); continue; }
        parts.forEach((p, k) => this.seenPart.set(`${m}:${month}:${k}`, p.seq));
      }
      this.others.set(m, months);
    }
    this.#merged = null;
  }

  dump() {
    const ev = (e: Evidence) => e.dump();
    return { own: [...this.own].map(([m, e]) => [m, ev(e)]), sent: [...this.sent], indexSeq: this.indexSeq, lastAt: this.lastAt, dirty: [...this.dirty],
      others: [...this.others].map(([m, ms]) => [m, [...ms].map(([mo, e]) => [mo, ev(e)])]), seenIndex: [...this.seenIndex], seenPart: [...this.seenPart] };
  }
  load(x: any) {
    if (!x) return;
    const ev = (d: any) => { const e = new Evidence(); e.load(d); return e; };
    this.own = new Map((x.own ?? []).map(([m, d]: [string, any]) => [m, ev(d)])); this.sent = new Map(x.sent ?? []); this.indexSeq = x.indexSeq ?? 0; this.lastAt = x.lastAt ?? 0;
    this.dirty = new Set(x.dirty ?? []); this.others = new Map((x.others ?? []).map(([m, ms]: [string, any[]]) => [m, new Map(ms.map(([mo, d]: [string, any]) => [mo, ev(d)]))]));
    this.seenIndex = new Map(x.seenIndex ?? []); this.seenPart = new Map(x.seenPart ?? []); this.#merged = null;
  }
  clear() { this.own.clear(); this.sent.clear(); this.others.clear(); this.dirty.clear(); this.seenIndex.clear(); this.seenPart.clear(); this.#merged = null; }
}
export { randomBytes };
