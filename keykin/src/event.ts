// Nostr events as Core uses them: NIP-01 ids, BIP-340 signatures by the group or a member key.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha, bytesToHex, hexToBytes, randomBytes, checkTree, KeykinError, type Bytes } from './bytes.ts';

export interface NostrEvent { id: string; pubkey: string; created_at: number; kind: number; tags: string[][]; content: string; sig: string }
export type Unsigned = Omit<NostrEvent, 'id' | 'sig'>;

/** NIP-01: the event id, computed, never taken from a message (§5.4). The strings go through §9.5 first,
 *  so JSON.stringify writes them as every implementation does (a U+000B is refused, not escaped). */
export const eventId = (e: Unsigned) => {
  checkTree([e.pubkey, e.created_at, e.kind, e.tags, e.content]);
  return bytesToHex(sha(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])));
};

/** What a coordinator sends a co-signer (§9.5): exactly the six fields, `id` computed here. */
export const wireEvent = (e: Unsigned) => ({ pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, id: eventId(e) });

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/;
const malformed = (why: string): never => { throw new KeykinError('malformed', why); };
const FIELDS = { signed: ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'], rumor: ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content'] };

/** §9.5's event shape: exactly the NIP-01 fields (a rumor without `sig`), each of its type, hex in
 *  lowercase. `cosign` is what a co-signer accepts: a rumor's six fields, `id` included. */
export function eventShape(e: any, form: 'signed' | 'rumor' | 'cosign'): void {
  if (!e || typeof e !== 'object' || Array.isArray(e)) malformed('an event is an object');
  const want = FIELDS[form === 'signed' ? 'signed' : 'rumor'];
  const keys = Object.keys(e);
  for (const k of keys) if (!want.includes(k)) malformed(`the event has a field "${k}"`);
  for (const k of want) if (!keys.includes(k)) malformed(`the event has no "${k}"`);
  if (typeof e.id !== 'string' || !HEX64.test(e.id)) malformed('id: 64 lowercase hex');
  if (typeof e.pubkey !== 'string' || !HEX64.test(e.pubkey)) malformed('pubkey: 64 lowercase hex');
  if (form === 'signed' && (typeof e.sig !== 'string' || !HEX128.test(e.sig))) malformed('sig: 128 lowercase hex');
  if (!Number.isSafeInteger(e.kind) || e.kind < 0 || e.kind > 65535) malformed('kind: an integer from 0 to 65535');
  if (!Number.isSafeInteger(e.created_at) || e.created_at < 0) malformed('created_at: a non-negative integer');
  if (!Array.isArray(e.tags) || !e.tags.every((t: unknown) => Array.isArray(t) && t.every((x) => typeof x === 'string'))) malformed('tags: an array of arrays of strings');
  if (typeof e.content !== 'string') malformed('content: a string');
  checkTree(e);
}

/** §9.5 "A site's event": what a site asks to have signed, read as the device reads it. `id`, `pubkey`
 *  and `sig` may be left out (`""` or `null` count as absent), a missing `tags` is `[]` and a missing
 *  `content` `""`; a `pubkey` other than `g` is refused; the site's `id`, `sig` and any extra field are
 *  dropped. The result is what goes to co-signers: the six fields, with the id computed here. Refusals
 *  name their cause (§9.5 "Saying why"). */
export function siteEvent(e: any, g: string): Unsigned & { id: string } {
  if (!e || typeof e !== 'object' || Array.isArray(e)) malformed('the event is not an object');
  const absent = (v: unknown) => v === undefined || v === null || v === '';
  if (!absent(e.pubkey) && e.pubkey !== g) malformed('the event names another pubkey');
  const out = { pubkey: g, created_at: e.created_at, kind: e.kind, tags: e.tags ?? [], content: e.content ?? '' };
  eventShape({ ...out, id: '0'.repeat(64) }, 'rumor');
  return { ...out, id: eventId(out) };
}

export function verifyEvent(e: NostrEvent): boolean {
  try { eventShape(e, 'signed'); return eventId(e) === e.id && schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey)); } catch { return false; }
}

/** BIP-340 by a single key (member keys, host keys, backup keys). */
export const schnorrSign = (digest: Bytes, sk: Bytes) => bytesToHex(schnorr.sign(digest, sk, randomBytes(32)));
export function schnorrVerify(sigHex: unknown, digest: Bytes, pubHex: unknown): boolean {
  try { return typeof sigHex === 'string' && typeof pubHex === 'string' && schnorr.verify(hexToBytes(sigHex), digest, hexToBytes(pubHex)); } catch { return false; }
}
export const pubOf = (sk: Bytes) => bytesToHex(schnorr.getPublicKey(sk));
export const tag = (e: { tags: string[][] }, name: string) => e.tags.find((t) => t[0] === name)?.[1];

/** A member key pair: secp256k1, x-only public (§1). */
export interface KeyPair { sk: Bytes; pub: string }
export const newKey = (): KeyPair => { const sk = schnorr.utils.randomSecretKey(); return { sk, pub: pubOf(sk) }; };
