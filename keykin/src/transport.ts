// The envelope (core §9.1): a kind 24301 rumor, sealed (kind 13) by the sender's member key and
// gift-wrapped (NIP-59) to the recipient. Live wraps are kind 21059; stored ones kind 1059, and
// never for anything carrying a share, a key, an epoch record or a change (§7.1).

import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, randomBytes, refuse, utf8ToBytes, strictJson, utf8Strict, fromB64, concatBytes } from './bytes.ts';
import { base64 } from '@scure/base';
import { nip44Open } from './nip44.ts';
import { eventId, verifyEvent, eventShape, type NostrEvent } from './event.ts';
import { KIND_RUMOR } from './types.ts';
import { LIFETIME_S, type Cls } from './lifetimes.ts';

export const KIND_SEAL = 13, KIND_WRAP_LIVE = 21059, KIND_WRAP_STORED = 1059;
export const PART_BYTES = 24_000;
export const MAX_MESSAGE = 512 * 1024;

/** Message types that carry a share, a key, an epoch record or a change. */
export const SECRET_TYPES = new Set(['welcome', 'repair_sigma', 'repair_delta', 'delta', 'paper_ck', 'dk_seed', 'release_seed', 'paper_item',
  'release', 'change', 'changes', 'upload', 'seeds', 'paper_reissue', 'take_out', 'released', 'handover', 'forward', 'seated']);

const now = () => Math.floor(Date.now() / 1000);

/** Seal and wrap one message. `live` is the default; `stored` refuses secret-bearing types. */
/** NIP-13: leading zero bits of an event id. */
export function powBits(idHex: string): number {
  let n = 0;
  for (const ch of idHex) { const v = parseInt(ch, 16); if (v === 0) { n += 4; continue; } return n + Math.clz32(v) - 28; }
  return n;
}

/** `pow`: NIP-13 work on the wrap (a server under a flood asks newcomers for it over relays, Server
 *  profile §3); the nonce is mined on the id before signing, so a try costs a hash, not a signature. */
export function wrap(senderSk: Uint8Array, to: string, body: any, o: { stored?: boolean; at?: number; expiration?: number; pow?: number } = {}): NostrEvent {
  if (o.stored && SECRET_TYPES.has(body?.type)) refuse('never_stored', `${body.type} never goes to relays as kind 1059`);
  const senderPub = getPublicKey(senderSk);
  const at = o.at ?? now();
  const rumor = { pubkey: senderPub, created_at: at, kind: KIND_RUMOR, tags: [], content: JSON.stringify(body) };
  const r = { ...rumor, id: eventId(rumor) };
  const seal = finalizeEvent({ kind: KIND_SEAL, created_at: at, tags: [], content: nip44.v2.encrypt(JSON.stringify(r), nip44.v2.utils.getConversationKey(senderSk, to)) }, senderSk);
  const eph = randomBytes(32);
  const tags = [['p', to]];
  if (o.stored && o.expiration) tags.push(['expiration', String(o.expiration)]);
  const kind = o.stored ? KIND_WRAP_STORED : KIND_WRAP_LIVE;
  const content = nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(eph, to));
  if (o.pow) {
    const ephPub = getPublicKey(eph);
    for (let n = 0; ; n++) {
      const t = [...tags, ['nonce', String(n), String(o.pow)]];
      if (powBits(eventId({ pubkey: ephPub, created_at: at, kind, tags: t, content })) >= o.pow) return finalizeEvent({ kind, created_at: at, tags: t, content }, eph) as NostrEvent;
    }
  }
  return finalizeEvent({ kind, created_at: at, tags, content }, eph) as NostrEvent;
}

/** Open a wrap addressed to us: the sender is the seal's key and must be the rumor's pubkey. */
export function unwrap(sk: Uint8Array, w: NostrEvent): { from: string; body: any; sentAt: number } {
  if (w.kind !== KIND_WRAP_LIVE && w.kind !== KIND_WRAP_STORED) refuse('not_a_wrap');
  if (!verifyEvent(w)) refuse('bad_wrap');
  let seal: NostrEvent, rumor: any;
  try {
    // §9.5: each text on its own through the profile; fatal UTF-8; exact event shapes.
    seal = strictJson(nip44Open(w.content, nip44.v2.utils.getConversationKey(sk, w.pubkey)));
    if (seal.kind !== KIND_SEAL || !verifyEvent(seal)) refuse('bad_seal');
    rumor = strictJson(nip44Open(seal.content, nip44.v2.utils.getConversationKey(sk, seal.pubkey)));
    eventShape(rumor, 'rumor');
  } catch (e) { return refuse((e as any).code ?? 'undecryptable'); }
  if (rumor.kind !== KIND_RUMOR || rumor.pubkey !== seal!.pubkey || eventId(rumor) !== rumor.id) refuse('bad_rumor');
  const body = strictJson(rumor.content);
  return { from: seal!.pubkey, body, sentAt: rumor.created_at };
}

/** Split a message whose plaintext exceeds 24,000 bytes into `part` rumors (§9.1). */
export function split(body: any): any[] {
  const text = JSON.stringify(body);
  const bytes = utf8ToBytes(text);
  if (bytes.length > MAX_MESSAGE) refuse('too_large');
  if (bytes.length <= PART_BYTES) return [body];
  const of = bytesToHex(randomBytes(16)), m = Math.ceil(bytes.length / PART_BYTES);
  return Array.from({ length: m }, (_, k) => ({ v: 1, type: 'part', of, k, m, cls: body.cls, data: base64.encode(bytes.slice(k * PART_BYTES, (k + 1) * PART_BYTES)) }));
}

/** Reassembles parts by `(sender, of)`; refuses over 512 KB; drops parts whose message expired. */
/** Open partial messages (review 10 H3): parts arrive within seconds, so an incomplete message is dropped
 *  after 10 minutes whatever class it claims; a sender keeps at most 4 open, and a node at most 256. */
export const PARTS_TTL_S = 600, PARTS_PER_SENDER = 4, PARTS_OPEN = 256;

export class Reassembler {
  #open = new Map<string, { first: number; cls: Cls; got: (Uint8Array | undefined)[]; size: number }>();
  take(from: string, body: any, at: number): any | null {
    this.prune(at);
    if (body?.type !== 'part') return body;
    const { of, k, m } = body;
    if (!Number.isSafeInteger(k) || !Number.isSafeInteger(m) || k < 0 || k >= m || m > Math.ceil(MAX_MESSAGE / PART_BYTES) + 1) refuse('bad_part');
    const key = `${from}:${of}`;
    const cls: Cls = Object.hasOwn(LIFETIME_S, body.cls) ? body.cls : 'sign';
    let p = this.#open.get(key);
    if (!p) {
      if (this.#open.size >= PARTS_OPEN) refuse('too_many_parts');
      if ([...this.#open.keys()].filter((x) => x.startsWith(`${from}:`)).length >= PARTS_PER_SENDER) refuse('too_many_parts');
      p = { first: at, cls, got: Array.from({ length: m }, () => undefined), size: 0 };
    }
    if (p.got.length !== m) refuse('bad_part');
    const data = fromB64(body.data);
    if (data.length > PART_BYTES) refuse('bad_part');
    if (p.got[k] === undefined) { p.got[k] = data; p.size += data.length; }
    if (p.size > MAX_MESSAGE) { this.#open.delete(key); refuse('too_large'); }
    this.#open.set(key, p);
    if (p.got.some((x) => x === undefined)) return null;
    this.#open.delete(key);
    const all = concatBytes(...(p.got as Uint8Array[]));
    return strictJson(utf8Strict(all));
  }
  prune(at: number) { for (const [k, p] of this.#open) if (at - p.first > Math.min(LIFETIME_S[p.cls] + 30, PARTS_TTL_S)) this.#open.delete(k); }
  get pending() { return this.#open.size; }
}
