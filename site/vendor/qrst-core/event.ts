// Nostr events: ids, BIP-340 signatures, and the bech32 form of a public key.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32 } from '@scure/base';
import { bytesToHex, hexToBytes, isHex32, utf8Encode } from './bytes.ts';

export interface EventTemplate {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

/** An unsigned event with its id: what NIP-59 calls a rumor. */
export interface Rumor extends EventTemplate {
  id: string;
}

export interface NostrEvent extends Rumor {
  sig: string;
}

/** Source of randomness, injected so that a whole flow can be replayed in a test. */
export type Random = (length: number) => Uint8Array;

/** Clock in whole seconds, injected for the same reason. */
export type Now = () => number;

export interface Env {
  random: Random;
  now: Now;
}

export function generateSecretKey(random: Random): Uint8Array {
  for (;;) {
    const candidate = random(32);
    try {
      schnorr.getPublicKey(candidate);
      return candidate;
    } catch {
      // Outside [1, n-1]: astronomically unlikely, but the retry is the correct answer.
    }
  }
}

export function publicKey(secretKey: Uint8Array): string {
  return bytesToHex(schnorr.getPublicKey(secretKey));
}

export function serialize(e: EventTemplate): string {
  return JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]);
}

export function eventId(e: EventTemplate): string {
  return bytesToHex(sha256(utf8Encode(serialize(e))));
}

export function rumor(template: EventTemplate): Rumor {
  return { ...template, id: eventId(template) };
}

export function sign(template: EventTemplate, secretKey: Uint8Array, random: Random): NostrEvent {
  const id = eventId(template);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey, random(32)));
  return { ...template, id, sig };
}

const HEX_128 = /^[0-9a-f]{128}$/;

/** Structural check on anything that arrived from outside. Says nothing about signatures. */
export function isEventShape(value: unknown): value is EventTemplate & { id?: unknown; sig?: unknown } {
  if (typeof value !== 'object' || value === null) return false;
  const e = value as Record<string, unknown>;
  if (!isHex32(e.pubkey)) return false;
  if (typeof e.created_at !== 'number' || !Number.isSafeInteger(e.created_at) || e.created_at < 0) return false;
  if (typeof e.kind !== 'number' || !Number.isInteger(e.kind) || e.kind < 0 || e.kind > 65535) return false;
  if (typeof e.content !== 'string') return false;
  if (!Array.isArray(e.tags)) return false;
  for (const tag of e.tags) {
    if (!Array.isArray(tag)) return false;
    for (const item of tag) if (typeof item !== 'string') return false;
  }
  return true;
}

/** True when the id is the hash of the event and the signature is valid for its pubkey. */
export function verify(value: unknown): value is NostrEvent {
  if (!isEventShape(value)) return false;
  const e = value as NostrEvent;
  if (!isHex32(e.id) || typeof e.sig !== 'string' || !HEX_128.test(e.sig)) return false;
  if (eventId(e) !== e.id) return false;
  try {
    return schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey));
  } catch {
    return false;
  }
}

export function firstTag(e: { tags: string[][] }, name: string): string | undefined {
  for (const tag of e.tags) if (tag[0] === name) return tag[1];
  return undefined;
}

export function npubEncode(publicKeyHex: string): string {
  if (!isHex32(publicKeyHex)) throw new Error('npub: bad public key');
  return bech32.encode('npub', bech32.toWords(hexToBytes(publicKeyHex)), 90);
}

/** Decodes an npub, verifying the bech32 checksum. Throws on anything else. */
export function npubDecode(npub: string): string {
  const decoded = bech32.decode(npub as `${string}1${string}`, 90);
  if (decoded.prefix !== 'npub') throw new Error('npub: wrong prefix');
  const bytes = bech32.fromWords(decoded.words);
  if (bytes.length !== 32) throw new Error('npub: wrong length');
  const hex = bytesToHex(bytes);
  // The key must be a real point, or every message to it would fail later and less clearly.
  if (!isValidPublicKey(hex)) throw new Error('npub: not a valid key');
  return hex;
}

/** True for an x coordinate that is a point on the curve. */
export function isValidPublicKey(publicKeyHex: string): boolean {
  if (!isHex32(publicKeyHex)) return false;
  try {
    schnorr.Point.fromBytes(hexToBytes('02' + publicKeyHex));
    return true;
  } catch {
    return false;
  }
}
