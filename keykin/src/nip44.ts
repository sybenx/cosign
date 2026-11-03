// NIP-44 v2 decryption to bytes, so the plaintext is decoded as fatal UTF-8 (core §9.5): nostr-tools
// decodes it leniently, turning invalid UTF-8 into U+FFFD where two implementations would differ.
// Encryption stays with nostr-tools; its output is what NIP-44 specifies.

import { chacha20 } from '@noble/ciphers/chacha.js';
import { expand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, eqBytes, fromB64, utf8Strict, KeykinError, type Bytes } from './bytes.ts';

const calcPaddedLen = (len: number) => {
  if (len <= 32) return 32;
  const next = 2 ** (Math.floor(Math.log2(len - 1)) + 1), chunk = next <= 256 ? 32 : next / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
};

/** The plaintext bytes, or `undecryptable`. The payload is padded standard base64 with zero unused bits;
 *  the length prefix is NIP-44's two bytes (1 to 65535). */
export function nip44Bytes(payload: string, ck: Bytes): Bytes {
  const no = (why: string): never => { throw new KeykinError('undecryptable', why); };
  if (typeof payload !== 'string' || payload.length < 132 || payload.length > 87472) no('payload length');
  let data: Bytes;
  try { data = fromB64(payload); } catch { return no('payload base64'); }
  if (data.length < 99 || data[0] !== 2) no('version');
  const nonce = data.subarray(1, 33), ct = data.subarray(33, -32), mac = data.subarray(-32);
  const keys = expand(sha256, ck, nonce, 76);
  if (!eqBytes(hmac(sha256, keys.subarray(44, 76), concatBytes(nonce, ct)), mac)) no('mac');
  const padded = chacha20(keys.subarray(0, 32), keys.subarray(32, 44), ct);
  const len = (padded[0] << 8) | padded[1];
  if (len < 1 || padded.length !== 2 + calcPaddedLen(len)) no('padding');
  return padded.slice(2, 2 + len);
}

/** The plaintext as text: fatal UTF-8, so invalid bytes are `malformed`, never repaired. */
export const nip44Open = (payload: string, ck: Bytes): string => utf8Strict(nip44Bytes(payload, ck));
