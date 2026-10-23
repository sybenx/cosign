// Byte helpers. No I/O, no globals beyond TextEncoder/TextDecoder.

import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';

export { bytesToHex, concatBytes, hexToBytes };

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Decodes UTF-8 and throws on any malformed sequence. */
export function utf8Decode(bytes: Uint8Array): string {
  return strictDecoder.decode(bytes);
}

const HEX_64 = /^[0-9a-f]{64}$/;

/** True for exactly 32 bytes of lowercase hex, the form every key and nonce takes on the wire. */
export function isHex32(value: unknown): value is string {
  return typeof value === 'string' && HEX_64.test(value);
}

/** Constant-time comparison of two byte strings of the same length. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Constant-time comparison of two short ASCII strings of the same length. */
export function equalAscii(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Overwrites a buffer. JavaScript gives no guarantee about copies the engine made
 * earlier, so this is best effort; it is still worth doing for the buffers we own.
 */
export function wipe(...buffers: (Uint8Array | undefined)[]): void {
  for (const b of buffers) if (b) b.fill(0);
}
