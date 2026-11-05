// Member-key signing for other protocols (first user: the encrypted-sync spec, ~/nostr-sync-nip
// vaults.md §12.2, which signs "nostr-vault/ksig/1" ‖ a device root key). A device signs with its own
// Keykin member key, never the account's, over a domain-separated message:
//
//   digest = SHA-256(domain ‖ 0x00 ‖ message),  sig = BIP-340(digest, member key)
//
// The zero byte ends the domain, which may not contain one, so no domain is a prefix of another plus
// message bytes. A domain must be registered and versioned (`…/<n>`), and may never begin with `keykin`
// or `cosign`: every member-key signature in Keykin Core is over a `keykin-…` digest or a NIP-01 event id
// (whose preimage begins with `[`), so no registered domain can produce the same preimage as one of them.

import { sha, utf8ToBytes, concatBytes, refuse, type Bytes } from '../src/bytes.ts';
import { schnorrSign, schnorrVerify } from '../src/event.ts';

// Core 14.19 §5.9: the version has no leading zeros; a message is at most 65,536 bytes.
const SHAPE = /^[a-z0-9][a-z0-9.-]*(\/[a-z0-9.-]+)*\/(0|[1-9][0-9]*)$/;
export const MESSAGE_MAX = 65_536;
const RESERVED = /^(keykin|cosign)/;

/** Domains callers may sign under (and derive data keys under, core 14.21 §4.5). A library registers its own once, at
 *  load. An entry may be a whole first segment (`nostr-vault`), covering every domain whose first `/`-separated segment
 *  is exactly that (§5.9). */
const registered = new Set<string>(['nostr-vault/ksig/1']);
/** Core 14.21 §5.9: domains the app list marks `open` (per domain, never a whole segment): apps and the member share
 *  them by design (Doors §3.7), so a hand grant may cover them. */
export const OPEN_DOMAINS = new Set(['nostr-vault/ksig/1', 'nostr-vault/owner/1', 'nostr-vault/keyring/1']);
const SEGMENT = /^[a-z0-9][a-z0-9.-]*$/;
/** Whether `domain` is registered, itself or by its first segment. */
export const isRegistered = (domain: string) => registered.has(domain) || registered.has(domain.split('/')[0]);

/** Why `domain` can't be used, or null. */
export function domainFault(domain: unknown): string | null {
  if (typeof domain !== 'string' || domain.length > 128) return 'a domain is a short string';
  if (RESERVED.test(domain)) return 'keykin and cosign domains are Keykin Core\'s own';
  if (!SHAPE.test(domain)) return 'a domain is lowercase segments ending in a version, like nostr-vault/ksig/1';
  return null;
}
export function registerDomain(domain: string) {
  // A bare first segment covers its whole tree; otherwise a full, versioned domain.
  const f = SEGMENT.test(domain) && !RESERVED.test(domain) ? null : domainFault(domain); if (f) refuse('bad_domain', f);
  registered.add(domain);
}
export const registeredDomains = () => [...registered].sort();

/** The digest a member key signs for `domain` and `message`. */
export function memberDigest(domain: string, message: Bytes): Bytes {
  const f = domainFault(domain); if (f) refuse('bad_domain', f);
  if (!isRegistered(domain)) refuse('bad_domain', `${domain} is not registered`);
  if (message.length > MESSAGE_MAX) refuse('too_large', 'a message is at most 65,536 bytes');
  return sha(concatBytes(utf8ToBytes(domain), new Uint8Array([0]), message));
}
/** Sign with a member key (the device's own). `aux` only for test vectors. */
export const memberSign = (sk: Bytes, domain: string, message: Bytes) => schnorrSign(memberDigest(domain, message), sk);
/** Check a member-key signature; false for a bad domain as for a bad signature. */
export function memberVerify(sig: string, domain: string, message: Bytes, memberKey: string): boolean {
  try { return schnorrVerify(sig, memberDigest(domain, message), memberKey); } catch { return false; }
}
