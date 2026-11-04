// Web Push as Core sends it (core §8.2–§8.3): RFC 8291 `aes128gcm` message encryption towards a device's
// address (`p256dh`, `auth`), and RFC 8292 VAPID, by which a server signs each push with its own `vapid`
// key and a gateway checks it against the key pinned to the address. One record, so the encrypted body
// is the header (86 bytes) plus the plaintext, its delimiter and the tag: inbox.ts pads every payload to
// one length, so every body is PUSH_BODY bytes. Pure.

import { p256 } from '@noble/curves/nist.js';
import { gcm } from '@noble/ciphers/aes.js';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes, randomBytes, b64u, fromB64u, strictJson, utf8Strict, KeykinError, type Bytes } from './bytes.ts';

const RS = 4096;
const info = (s: string, ...rest: Bytes[]) => concatBytes(utf8ToBytes(s), new Uint8Array([0]), ...rest);
const no = (why: string): never => { throw new KeykinError('bad_push', why); };

function keys(ecdh: Bytes, auth: Bytes, uaPub: Bytes, asPub: Bytes, salt: Bytes) {
  // RFC 8291 §3.3–3.4: IKM from the ECDH secret and the auth secret; then RFC 8188's CEK and nonce.
  const ikm = expand(sha256, extract(sha256, ecdh, auth), info('WebPush: info', uaPub, asPub), 32);
  const prk = extract(sha256, ikm, salt);
  return { cek: expand(sha256, prk, info('Content-Encoding: aes128gcm'), 16), nonce: expand(sha256, prk, info('Content-Encoding: nonce'), 12) };
}

/** Encrypt `plain` to an address: `p256dh` (65-byte uncompressed point) and `auth` (16 bytes), base64url
 *  as a browser gives them. `asSk` and `salt` are for test vectors only. */
export function encryptPush(plain: Bytes, to: { p256dh: string; auth: string }, o: { asSk?: Bytes; salt?: Bytes } = {}): Bytes {
  const uaPub = fromB64u(to.p256dh), auth = fromB64u(to.auth);
  if (uaPub.length !== 65 || uaPub[0] !== 4 || auth.length !== 16) no('address keys');
  if (plain.length + 17 >= RS) no('one record only');      // RFC 8291 §4: rs must exceed the record
  const asSk = o.asSk ?? p256.utils.randomSecretKey(), asPub = p256.getPublicKey(asSk, false), salt = o.salt ?? randomBytes(16);
  const ecdh = p256.getSharedSecret(asSk, uaPub, true).slice(1);
  const { cek, nonce } = keys(ecdh, auth, uaPub, asPub, salt);
  const ct = gcm(cek, nonce).encrypt(concatBytes(plain, new Uint8Array([2])));    // 0x02: the last record
  const head = new Uint8Array(21); head.set(salt); new DataView(head.buffer).setUint32(16, RS); head[20] = 65;
  return concatBytes(head, asPub, ct);
}

/** The device's side: decrypt with its address key pair and auth secret. Refuses anything but one
 *  well-formed last record. */
export function decryptPush(body: Bytes, uaSk: Bytes, auth: Bytes): Bytes {
  if (body.length < 21 + 65 + 17) no('short');
  const salt = body.slice(0, 16), rs = new DataView(body.buffer, body.byteOffset).getUint32(16), idlen = body[20];
  if (idlen !== 65 || rs < 18) no('header');
  const asPub = body.slice(21, 86), ct = body.slice(86);
  if (ct.length >= rs) no('one record only');
  const uaPub = p256.getPublicKey(uaSk, false);
  let ecdh: Bytes;
  try { ecdh = p256.getSharedSecret(uaSk, asPub, true).slice(1); } catch { return no('sender key'); }
  const { cek, nonce } = keys(ecdh, auth, uaPub, asPub, salt);
  let padded: Bytes;
  try { padded = gcm(cek, nonce).decrypt(ct); } catch { return no('tag'); }
  // RFC 8188 §2: the delimiter is the last non-zero byte; after it only zeros.
  let k = padded.length - 1;
  while (k >= 0 && padded[k] === 0) k--;
  if (k < 0 || padded[k] !== 2) no('padding');
  return padded.slice(0, k);
}

// --- VAPID (RFC 8292) ----------------------------------------------------------------------------
export const VAPID_MAX_S = 24 * 3600;

/** The `Authorization` header for a push to `url`: an ES256 JWT for the push service's origin, valid at
 *  most 24 hours, and the server's VAPID public key. */
export function vapidHeader(url: string, vapidSk: Bytes, now: number, sub = 'mailto:operator@keykin.invalid', ttl = 12 * 3600): string {
  if (ttl > VAPID_MAX_S) no('exp beyond 24 hours');
  const enc = (o: unknown) => b64u(utf8ToBytes(JSON.stringify(o)));
  const input = `${enc({ typ: 'JWT', alg: 'ES256' })}.${enc({ aud: new URL(url).origin, exp: now + ttl, sub })}`;
  const sig = p256.sign(utf8ToBytes(input), vapidSk, { format: 'compact' });
  return `vapid t=${input}.${b64u(sig)}, k=${b64u(p256.getPublicKey(vapidSk, false))}`;
}

/** A gateway's check (core §8.3): the header's key is the one pinned to this address, the JWT is ES256
 *  over it, for this origin, unexpired and no more than 24 hours ahead. Returns null or why not. */
export function checkVapid(header: string, url: string, pinnedVapidHex: string, now: number): string | null {
  const m = /^vapid t=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+), k=([A-Za-z0-9_-]+)$/.exec(header);
  if (!m) return 'vapid_header';
  try {
    const k = fromB64u(m[4]);
    if (Buffer.from(k).toString('hex') !== pinnedVapidHex) return 'vapid_key';
    const head = strictJson(utf8Strict(fromB64u(m[1]))), claims = strictJson(utf8Strict(fromB64u(m[2])));
    if (head?.alg !== 'ES256' || head?.typ !== 'JWT') return 'vapid_alg';
    if (claims?.aud !== new URL(url).origin) return 'vapid_aud';
    if (!Number.isSafeInteger(claims?.exp) || claims.exp <= now || claims.exp > now + VAPID_MAX_S) return 'vapid_exp';
    const sig = fromB64u(m[3]);
    if (sig.length !== 64 || !p256.verify(sig, utf8ToBytes(`${m[1]}.${m[2]}`), k, { format: 'compact', lowS: false })) return 'vapid_sig';
    return null;
  } catch { return 'vapid_malformed'; }
}
