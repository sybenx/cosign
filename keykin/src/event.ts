// Nostr events as Core uses them: NIP-01 ids, BIP-340 signatures by the group or a member key.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha, bytesToHex, hexToBytes, randomBytes, type Bytes } from './bytes.ts';

export interface NostrEvent { id: string; pubkey: string; created_at: number; kind: number; tags: string[][]; content: string; sig: string }
export type Unsigned = Omit<NostrEvent, 'id' | 'sig'>;

/** NIP-01: the event id, computed, never taken from a message (§5.4). */
export const eventId = (e: Unsigned) => bytesToHex(sha(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])));

export function verifyEvent(e: NostrEvent): boolean {
  try { return eventId(e) === e.id && schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey)); } catch { return false; }
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
