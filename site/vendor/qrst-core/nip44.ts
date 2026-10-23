// NIP-44 version 2: the encryption both layers of a gift wrap use (spec §11.1, T3).
//
// Written against the NIP's own pseudocode and checked in test/ against the official
// vector file and against nostr-tools. Nothing here is specific to QRST.

import { chacha20 } from '@noble/ciphers/chacha.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { concatBytes, equalBytes, hexToBytes, isHex32, utf8Decode, utf8Encode, wipe } from './bytes.ts';

const SALT = utf8Encode('nip44-v2');
const MIN_PLAINTEXT = 1;
const MAX_PLAINTEXT = 65535;

/** The shared key for one ordered pair of keys. Symmetric: (a, B) and (b, A) agree. */
export function conversationKey(secretKey: Uint8Array, publicKeyHex: string): Uint8Array {
  if (!isHex32(publicKeyHex)) throw new Error('nip44: bad public key');
  // x-only public keys are lifted with an even y, as BIP-340 does.
  const shared = secp256k1.getSharedSecret(secretKey, hexToBytes('02' + publicKeyHex));
  const x = shared.subarray(1, 33);
  const key = extract(sha256, x, SALT);
  wipe(shared);
  return key;
}

function messageKeys(conversation: Uint8Array, nonce: Uint8Array) {
  if (conversation.length !== 32) throw new Error('nip44: bad conversation key');
  if (nonce.length !== 32) throw new Error('nip44: bad nonce');
  const keys = expand(sha256, conversation, nonce, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76),
    all: keys,
  };
}

/** The padded length NIP-44 gives a plaintext of `length` bytes. Exported for the size tests. */
export function paddedLength(length: number): number {
  if (!Number.isSafeInteger(length) || length < 1) throw new Error('nip44: bad length');
  if (length <= 32) return 32;
  const nextPower = 2 ** (Math.floor(Math.log2(length - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((length - 1) / chunk) + 1);
}

function pad(plaintext: string): Uint8Array {
  const bytes = utf8Encode(plaintext);
  const n = bytes.length;
  if (n < MIN_PLAINTEXT || n > MAX_PLAINTEXT) throw new Error('nip44: plaintext length out of range');
  const out = new Uint8Array(2 + paddedLength(n));
  out[0] = n >>> 8;
  out[1] = n & 0xff;
  out.set(bytes, 2);
  return out;
}

function unpad(padded: Uint8Array): string {
  const n = (padded[0]! << 8) | padded[1]!;
  const body = padded.subarray(2, 2 + n);
  if (n < MIN_PLAINTEXT || n > MAX_PLAINTEXT || body.length !== n || padded.length !== 2 + paddedLength(n)) {
    throw new Error('nip44: bad padding');
  }
  return utf8Decode(body);
}

/** Encrypts under a conversation key. `nonce` MUST be 32 fresh random bytes. */
export function encrypt(plaintext: string, conversation: Uint8Array, nonce: Uint8Array): string {
  const k = messageKeys(conversation, nonce);
  const padded = pad(plaintext);
  const ciphertext = chacha20(k.chachaKey, k.chachaNonce, padded);
  const mac = hmac(sha256, k.hmacKey, concatBytes(nonce, ciphertext));
  wipe(k.all, padded);
  return base64.encode(concatBytes(new Uint8Array([2]), nonce, ciphertext, mac));
}

/** Decrypts and authenticates. Throws on anything that is not a valid version 2 payload. */
export function decrypt(payload: string, conversation: Uint8Array): string {
  const length = payload.length;
  if (length === 0 || payload[0] === '#') throw new Error('nip44: unknown version');
  if (length < 132 || length > 87472) throw new Error('nip44: bad payload size');
  let data: Uint8Array;
  try {
    data = base64.decode(payload);
  } catch {
    throw new Error('nip44: bad base64');
  }
  if (data.length < 99 || data.length > 65603) throw new Error('nip44: bad data size');
  if (data[0] !== 2) throw new Error('nip44: unknown version');
  const nonce = data.subarray(1, 33);
  const ciphertext = data.subarray(33, data.length - 32);
  const mac = data.subarray(data.length - 32);
  const k = messageKeys(conversation, nonce);
  const expected = hmac(sha256, k.hmacKey, concatBytes(nonce, ciphertext));
  if (!equalBytes(expected, mac)) {
    wipe(k.all);
    throw new Error('nip44: bad mac');
  }
  const padded = chacha20(k.chachaKey, k.chachaNonce, ciphertext);
  wipe(k.all);
  try {
    return unpad(padded);
  } finally {
    wipe(padded);
  }
}
