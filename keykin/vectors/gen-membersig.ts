// Vectors for member-key signing over a domain-separated message (device/membersig.ts), for every port
// and for the protocols that use it. Run: node vectors/gen-membersig.ts > vectors/membersig.json
import { schnorr } from '@noble/curves/secp256k1.js';
import { memberDigest, domainFault } from '../device/membersig.ts';
import { bytesToHex, hexToBytes } from '../src/bytes.ts';

const sk = hexToBytes('11'.repeat(31) + '01');
const key = bytesToHex(schnorr.getPublicKey(sk));
const aux = new Uint8Array(32);
const ok = (domain: string, message: string) => {
  const d = memberDigest(domain, hexToBytes(message));
  return { domain, message, digest: bytesToHex(d), sig: bytesToHex(schnorr.sign(d, sk, aux)) };
};
const root = 'ab'.repeat(32);
console.log(JSON.stringify({
  note: 'digest = SHA-256(utf8(domain) || 0x00 || message); sig = BIP-340(digest, member key), aux = 32 zero bytes. Domains: registered, versioned, lowercase, never starting keykin or cosign.',
  member_sk: bytesToHex(sk), member_key: key,
  valid: [ok('nostr-vault/ksig/1', root), ok('nostr-vault/ksig/1', ''), ok('nostr-vault/ksig/1', 'ff'.repeat(100))],
  refused_domains: ['keykin-pair/1', 'keykin/1', 'cosign-ticket/1', 'Nostr-vault/ksig/1', 'nostr-vault/ksig', 'nostr-vault/ksig/1\u0000x', '[0,"x"]/1', '', 'a'.repeat(129) + '/1']
    .map((domain) => ({ domain, why: domainFault(domain) })),
}, null, 1));
