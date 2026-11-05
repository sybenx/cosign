// Every hash-derived value of Core: codes people type, indices, ids, challenges and digests.
// Each function names its section. Pure.

import { sha, shaHex, u32be, u64be, b64u, hkdf32, jcs, jcsBytes, hexN, cmpBytes, bytesToHex, concatBytes, utf8ToBytes, type Bytes } from './bytes.ts';

const six = (d: Bytes) => (new DataView(d.buffer, d.byteOffset).getBigUint64(0) % 1_000_000n).toString().padStart(6, '0');
const k32 = (h: string, what: string) => hexN(h, 32, what);
const b16 = (h: string, what: string) => hexN(h, 16, what);

/** §4.1: the 6-digit join check. Keys as 32 raw bytes, `s` and `t` as 16. */
export const joinCheck = (g: string, m: string, n: string, s: string, t: string) =>
  six(sha('keykin-join/1', k32(g, 'g'), k32(m, 'm'), k32(n, 'n'), b16(s, 's'), b16(t, 't')));

/** §6.1, §6.7.2: the list hash, `SHA-256(JCS(list))`; a single change is a list of one. */
export const listHash = (list: unknown[]) => shaHex(jcsBytes(list));

/** §6.2: the typed two-device code. */
export const pairCode = (g: string, listHashHex: string, r: string) =>
  six(sha('keykin-pair/1', k32(g, 'g'), k32(listHashHex, 'list hash'), b16(r, 'r')));

const idx30 = (d: Bytes) => 2 ** 16 + (new DataView(d.buffer, d.byteOffset).getUint32(0) % 2 ** 30);

/** §3.2: an added device's three indices for a salt. */
export const deviceIndices = (g: string, epochId: string, key: string, salt: number) =>
  [0, 1, 2].map((j) => idx30(sha('keykin-index/1', k32(g, 'g'), b16(epochId, 'epoch id'), k32(key, 'key'), u32be(salt), u32be(j))));

/** §3.1: the helper's reserved seat. */
export const helperSeat = (g: string) => [0, 1, 2].map((j) => idx30(sha('keykin-seat/1', k32(g, 'g'), 'helper', u32be(j))));

/** §3.2: the lowest salt whose indices collide with nothing known. */
export function pickSalt(g: string, epochId: string, key: string, taken: Set<number>): { salt: number; indices: number[] } {
  for (let salt = 0; ; salt++) {
    const indices = deviceIndices(g, epochId, key, salt);
    if (new Set(indices).size === 3 && indices.every((i) => !taken.has(i))) return { salt, indices };
  }
}

/** §6.3: wait ids. */
export const holdWaitId = (eventId: string) => shaHex('hold', k32(eventId, 'event id'));
export const recoveryWaitId = (backupKey: string, epochId: string, r: string) =>
  shaHex('recovery', k32(backupKey, 'backup key'), b16(epochId, 'epoch id'), b16(r, 'r'));

/** §6.1: what a lock assertion signs, by purpose. */
export const what = {
  sign: (eventId: string) => concatBytes(utf8ToBytes('sign'), k32(eventId, 'event id')),
  change: (listHashHex: string, epochId: string, expiry: number) =>
    concatBytes(utf8ToBytes('change'), k32(listHashHex, 'list hash'), b16(epochId, 'epoch id'), u64be(expiry)),
  cancel: (waitId: string) => concatBytes(utf8ToBytes('cancel'), k32(waitId, 'wait id')),
  /** take_out, removing a notice channel: `type ‖ id ‖ SHA-256(JCS(body without the assertion))`. */
  request: (type: string, id: string, body: unknown) => concatBytes(utf8ToBytes(type), b16(id, 'id'), sha(jcsBytes(body))),
};
/** §6.1: the WebAuthn `clientData.challenge`. */
export const lockChallenge = (g: string, w: Bytes) => b64u(sha('keykin-lock/1', k32(g, 'g'), w));

/** §6.3: the digest a server signs in a waited statement. */
export const waitedDigest = (g: string, kind: 'recovery' | 'hold', wait: string, start: number, end: number) =>
  sha('keykin-waited/1', k32(g, 'g'), kind, k32(wait, 'wait'), u64be(start), u64be(end));

/** §6.7.1: the state hash, SHA-256 of the sorted 16-byte redeal ids. */
export function stateHash(ids: Iterable<string>): string {
  const bs = [...new Set(ids)].map((i) => b16(i, 'redeal id')).sort(cmpBytes);
  return shaHex(...bs);
}
export const sortIds = (ids: Iterable<string>) => [...new Set(ids)].sort();

/** §4.5: `dk(S)` from the base data key and the seeds of S, sorted bytewise. */
export function dataKey(base: string, seeds: string[]): string {
  const ss = seeds.map((s) => k32(s, 'seed')).sort(cmpBytes);
  return bytesToHex(hkdf32(concatBytes(k32(base, 'base data key'), ...ss), 'keykin-dk/1'));
}

/** §6.7.5: the signpost's `d`, `h` and device-copy key. */
export const signpostD = (backupKey: string) => shaHex('keykin-beacon/1', k32(backupKey, 'backup key'));
export const signpostH = (epochId: string, servers: unknown[]) => shaHex('keykin-beacon/1', b16(epochId, 'epoch id'), jcs(servers));
export const signpostDeviceKey = (base: string) => bytesToHex(hkdf32(k32(base, 'base data key'), 'keykin-beacon/1'));

/** §6.7.5: what a `seated` reply's host signature covers. */
/** Core 14.19: the challenge signatures, each tagged (a raw challenge could be chosen to equal an app's digest). */
export const seatedAskDigest = (hKey: string, challenge: string) => sha('keykin-seated-ask/1', k32(hKey, 'H(key)'), b16(challenge, 'challenge'));
export const forwardAskDigest = (hKey: string, challenge: string) => sha('keykin-forward-ask/1', k32(hKey, 'H(key)'), b16(challenge, 'challenge'));
export const retireDigest = (g: string, challenge: string) => sha('keykin-retire/1', k32(g, 'g'), b16(challenge, 'challenge'));
export const seatedDigest = (hKey: string, challenge: Bytes, ciphertext: Bytes) => sha('keykin-seated/1', k32(hKey, 'H(key)'), challenge, ciphertext);

/** §6.2: the digest a detached approval signature covers: `SHA-256("keykin-<type>/1" ‖ g ‖ JCS(body))`. */
export const detachedDigest = (type: string, g: string, body: unknown) => sha(`keykin-${type}/1`, k32(g, 'g'), jcs(body));
/** §6.4: a `self` remove's digest: `"keykin-self/1" ‖ g ‖ change hash`. */
export const selfDigest = (g: string, listHashHex: string) => sha('keykin-self/1', k32(g, 'g'), k32(listHashHex, 'list hash'));
