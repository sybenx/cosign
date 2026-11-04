// Locks: biometric-only P-256 keys, checked as WebAuthn assertions (core §6.1). Pure.
// `softLock` is a test and simulation stand-in; servers can't tell it from hardware (§10).

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { b64u, fromB64u, hexN, concatBytes, utf8ToBytes, bytesToHex, eqBytes, randomBytes, strictJson, utf8Strict, type Bytes } from './bytes.ts';
import { lockChallenge } from './codes.ts';

export interface LockPub { pub: string; rp: string }
export interface Assertion { authData: string; clientData: string; sig: string }

const UP = 0x01, UV = 0x04;

/** Null when the assertion is a valid lock signature over `what`; otherwise why not. */
export function checkAssertion(g: string, lock: LockPub, w: Bytes, a: Assertion): string | null {
  try {
    const pub = hexN(lock.pub, 65, 'lock pub'), rp = hexN(lock.rp, 32, 'rp');
    const authData = fromB64u(a.authData), clientDataRaw = fromB64u(a.clientData), sig = fromB64u(a.sig);
    const cd = strictJson(utf8Strict(clientDataRaw));
    if (!cd || typeof cd !== 'object' || Array.isArray(cd)) return 'lock_malformed';
    if (cd.type !== 'webauthn.get') return 'lock_type';
    if (cd.challenge !== lockChallenge(g, w)) return 'lock_challenge';
    if (authData.length < 37 || !eqBytes(authData.slice(0, 32), rp)) return 'lock_rp';
    if ((authData[32] & (UP | UV)) !== (UP | UV)) return 'lock_flags';
    const ok = p256.verify(sig, concatBytes(authData, sha256(clientDataRaw)), pub, { format: 'der', lowS: false });
    return ok ? null : 'lock_sig';
  } catch { return 'lock_malformed'; }
}

/** A software lock for tests and the simulation. */
/** A software stand-in for a lock (tests and the simulation only). `sk` rebuilds one from storage; a
 *  real lock's key never leaves its secure hardware. */
export function softLock(rpId = 'keykin.test', sk: Uint8Array = p256.utils.randomSecretKey()) {
  const pub: LockPub = { pub: bytesToHex(p256.getPublicKey(sk, false)), rp: bytesToHex(sha256(utf8ToBytes(rpId))) };
  let count = 0;
  return {
    pub, rpId, sk,
    stored: () => ({ soft: { rp: rpId, sk: bytesToHex(sk) } }),
    assert(g: string, w: Bytes, flags = UP | UV): Assertion {
      const authData = new Uint8Array(37);
      authData.set(sha256(utf8ToBytes(rpId)), 0);
      authData[32] = flags;
      new DataView(authData.buffer).setUint32(33, ++count);
      const clientData = utf8ToBytes(JSON.stringify({ type: 'webauthn.get', challenge: lockChallenge(g, w), origin: 'keykin:app' }));
      const sig = p256.sign(concatBytes(authData, sha256(clientData)), sk, { format: 'der', lowS: false });
      return { authData: b64u(authData), clientData: b64u(clientData), sig: b64u(sig) };
    },
  };
}
export type SoftLock = ReturnType<typeof softLock>;
/** A device's lock (§6.1), however it is held: the simulation's `softLock`, an Android Keystore key
 *  with BIOMETRIC_STRONG, a Secure Enclave key. `stored` is what a snapshot may keep of it: a soft lock's
 *  key; a hardware lock gives only its public part, and the app reopens it on restore. */
export interface Lock { pub: LockPub; assert(g: string, w: Bytes, flags?: number): Assertion; stored?(): unknown }
export const FLAGS = { UP, UV };
export { randomBytes };
