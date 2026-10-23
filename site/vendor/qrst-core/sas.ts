// The commitment and the short authentication string of spec §6.
//
//   commit = SHA-256("qrst-commit" || v || C.pub || nonce_C)
//   code   = SHA-256("qrst-sas" || v || len(p) || p || SND.pub || RCV.pub || nonce_S || nonce_R)
//   digits = (code[0..5] as u40 BE) mod 100_000, zero-padded to 5
//
// SND and RCV are in ROLE order whichever party made contact. Getting that backwards
// agrees with itself and fails only against a real peer, which is why vectors/ carries
// a transposed negative case.

import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes, isHex32, utf8Encode } from './bytes.ts';
import { PROFILE_ID } from './constants.ts';

const COMMIT_LABEL = utf8Encode('qrst-commit');
const SAS_LABEL = utf8Encode('qrst-sas');

function key32(hex: string, what: string): Uint8Array {
  if (!isHex32(hex)) throw new Error(`sas: ${what} must be 32 bytes of lowercase hex`);
  return hexToBytes(hex);
}

function versionByte(v: number): Uint8Array {
  if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error('sas: bad version');
  return new Uint8Array([v]);
}

/** The contacting party's commitment to its nonce. */
export function commit(v: number, contactingPub: string, contactingNonce: string): Uint8Array {
  return sha256(
    concatBytes(COMMIT_LABEL, versionByte(v), key32(contactingPub, 'public key'), key32(contactingNonce, 'nonce')),
  );
}

export interface Transcript {
  v: number;
  profile: string;
  senderPub: string;
  receiverPub: string;
  senderNonce: string;
  receiverNonce: string;
}

/** The 32-byte transcript hash. */
export function sasCode(t: Transcript): Uint8Array {
  if (!PROFILE_ID.test(t.profile)) throw new Error('sas: bad profile identifier');
  const p = utf8Encode(t.profile);
  return sha256(
    concatBytes(
      SAS_LABEL,
      versionByte(t.v),
      new Uint8Array([p.length]),
      p,
      key32(t.senderPub, 'sender public key'),
      key32(t.receiverPub, 'receiver public key'),
      key32(t.senderNonce, 'sender nonce'),
      key32(t.receiverNonce, 'receiver nonce'),
    ),
  );
}

/** The five digits a person carries between the two screens. */
export function sasDigits(code: Uint8Array): string {
  if (code.length < 5) throw new Error('sas: code too short');
  // 40 bits fit a double exactly; multiplication avoids the 32-bit wrap of shifts.
  let n = 0;
  for (let i = 0; i < 5; i++) n = n * 256 + code[i]!;
  return String(n % 100_000).padStart(5, '0');
}

export function sas(t: Transcript): string {
  return sasDigits(sasCode(t));
}
