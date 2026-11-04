// Device policy §1's metadata, synced: what a device knows of the account's own ciphertexts (Doors §1's
// evidence: which grant, or the member app, encrypted each one, and the kinds of the account's events that
// carry it), so every device judges a decrypt on every device's records. Each device publishes one cumulative
// snapshot per month, split into parts at 24 KB, each part with its own sequence number and signed by its member
// key, part 0 listing every part's number and hash; and one index event naming each live month and its parts.
// All are account-signed kind 30078 under `keykin-meta…` d's relays can't link to a member key, encrypted under
// the data key with g, d and the state as associated data. A reader takes the index first, never a lower number
// than it has seen, and only parts the index names; only a current device's snapshots count.
//
// Not yet: the rest of §1's metadata (grant per event, list versions, removal logs, deletion counts), which the
// judging of events (Device policy §2–§4) needs; the 3-second fetch before a judgement; entries' retention by
// whether their event is current (months are kept 13 months instead).

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

/** What a month holds, as it is published: encrypt records and event kinds by ciphertext hash, sorted. */
export interface MonthData { encrypt: [string, string][]; events: [string, number][] }
const toData = (e: Evidence): MonthData => ({
  encrypt: [...e.owners].flatMap(([h, os]) => [...os].map((o) => [h, o] as [string, string])).sort((a, b) => (a.join() < b.join() ? -1 : 1)),
  events: [...e.kinds].flatMap(([h, ks]) => [...ks].map((k) => [h, k] as [string, number])).sort((a, b) => (`${a[0]}${a[1]}` < `${b[0]}${b[1]}` ? -1 : 1)),
});
const fromData = (x: MonthData, into = new Evidence()) => {
  for (const [h, o] of x.encrypt ?? []) if (typeof h === 'string' && typeof o === 'string') { const s = into.owners.get(h) ?? new Set(); s.add(o); into.owners.set(h, s); }
  for (const [h, k] of x.events ?? []) if (typeof h === 'string' && Number.isInteger(k)) { const s = into.kinds.get(h) ?? new Set(); s.add(k); into.kinds.set(h, s); }
  return into;
};

export interface MetaHost { g: string; kp: KeyPair; baseDk: string; now: number; currentDevices(): Set<string>;
  dataKey(): { state: string; key: Uint8Array }; keyFor(state: string): Uint8Array | null;
  sign(ev: { kind: number; created_at: number; tags: string[][]; content: string }): Promise<NostrEvent>;
  publish(e: NostrEvent): Promise<void>; query(): Promise<{ events: NostrEvent[]; answered: number; asked: number }> }

export class MetaStore {
  readonly h: MetaHost;
  /** This device's records, by month. */
  own = new Map<string, Evidence>();
  /** What this device last published: per month, each part's sequence number and hash; the index's number. */
  sent = new Map<string, { seq: number; hash: string }[]>();
  indexSeq = 0;
  lastAt = 0;
  dirty = new Set<string>();
  /** Other devices' records, by maker and month, and the highest numbers seen (never lower: no rollback). */
  others = new Map<string, Map<string, Evidence>>();
  seenIndex = new Map<string, number>();
  seenPart = new Map<string, number>();
  #merged: Evidence | null = null;
  constructor(h: MetaHost) { this.h = h; }

  #bucket(): Evidence { const m = monthOf(this.h.now); let e = this.own.get(m); if (!e) { e = new Evidence(); this.own.set(m, e); } this.dirty.add(m); this.#merged = null; return e; }
  /** An encryption to the account's own key this device made, for a grant `${by}:${id}` or the member app. */
  encrypted(payload: string, owner: string) { this.#bucket().encrypted(payload, owner); }
  /** An account event this device signed or fetched. */
  event(kind: number, content: string) { if (Evidence.hashOf(content)) this.#bucket().event(kind, content); }
  /** Every current device's records together: what a decrypt is judged on. */
  evidence(): Evidence {
    if (this.#merged) return this.#merged;
    const all = new Evidence(), cur = this.h.currentDevices();
    const add = (e: Evidence) => fromData(toData(e), all);
    for (const e of this.own.values()) add(e);
    for (const [m, months] of this.others) if (cur.has(m)) for (const e of months.values()) add(e);
    return (this.#merged = all);
  }

  /** Publish what changed: the changed months' parts (part 0 with every change) and the index. */
  async publish(): Promise<NostrEvent[]> {
    const keep = new Set(Array.from({ length: KEEP_MONTHS }, (_, k) => monthOf(this.h.now - k * 30 * 86400)));
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
    for (const month of [...this.dirty].filter((m) => this.own.has(m))) {
      const text = jcs(toData(this.own.get(month)!));
      const chunks: string[] = []; for (let k = 0; k < text.length; k += PART_PLAIN) chunks.push(text.slice(k, k + PART_PLAIN));
      if (!chunks.length) chunks.push('');
      if (chunks.length > MAX_PARTS) throw new KeykinError('too_large', 'a month of metadata past 64 parts');
      const prev = this.sent.get(month) ?? [];
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
      this.sent.set(month, parts.map(({ seq, hash }) => ({ seq, hash })));
    }
    this.indexSeq++;
    const d = indexD(baseDk, kp.pub);
    const body = { seq: this.indexSeq, months: Object.fromEntries([...this.sent].map(([m, ps]) => [m, ps.map((p) => p.seq)])) };
    await seal(d, body, indexDigest(g, d, body));
    for (const e of out) await this.h.publish(e);
    this.lastAt = at; this.dirty.clear();
    return out;
  }

  /** Read every other current device's snapshots: its index first, then the months and parts it names. */
  async fetch() {
    const { events } = await this.h.query();
    const { g, baseDk } = this.h;
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
      if (m === this.h.kp.pub) continue;
      const id = indexD(baseDk, m);
      const ix = newest(id, (x) => { const { sig, ...b } = x; return Number.isInteger(b.seq) && schnorrVerify(sig, indexDigest(g, id, b), m); });
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
        if (parts.length !== seqs.length) { const prev = this.others.get(m)?.get(month); if (prev) months.set(month, prev); continue; }
        // Part 0 names every part's number and hash: a stale or swapped part is caught.
        const list: [number, string][] = parts[0].parts ?? [];
        if (list.length !== parts.length || parts.some((p, k) => list[k][0] !== p.seq || list[k][1] !== bytesToHex(sha256(utf8ToBytes(p.data))))) continue;
        try { months.set(month, fromData(strictJson(parts.map((p) => p.data).join('')))); } catch { continue; }
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
