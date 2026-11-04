// Backup module (§2, §3, §4.1): writing the backup key down, holder keys, and the heir's envelope. Pure.

import { bech32 } from '@scure/base';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { validateMnemonic } from '@scure/bip39';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha, hexN, jcs, concatBytes, bytesToHex, hexToBytes, randomBytes, utf8ToBytes, hkdf32, refuse, utf8Strict, strictJson } from './bytes.ts';
import { N, G, mod, mul, liftX, compHex, pointFrom, scalarHex, scalarFrom, lagrange } from './curve.ts';

const PREFIX = 'kkbak';

/** The backup secret is a scalar in [1, n): readers reject anything else (§2). */
function checkSecret(sk: Uint8Array) {
  const v = BigInt('0x' + bytesToHex(sk));
  if (sk.length !== 32 || v === 0n || v >= N) refuse('bad_backup', 'not a valid secret');
}

export interface Card { g: string; epoch: string; servers: { host: string; https: string; relays: string[] }[]; holderInbox: string }

/** TLV: 1-byte type, 2-byte big-endian length (Backup §2, unlike NIP-19's 1 byte), value. Server
 *  entries (type 3) are 32-byte host ‖ UTF-8 JSON {https, relays}. */
function tlv(sk: Uint8Array | null, c: Card): Uint8Array {
  const parts: Uint8Array[] = [];
  const put = (t: number, v: Uint8Array) => { if (v.length > 0xffff) refuse('too_long'); parts.push(new Uint8Array([t, v.length >> 8, v.length & 0xff]), v); };
  if (sk) put(0, sk);
  put(1, hexN(c.g, 32, 'g')); put(2, hexN(c.epoch, 16, 'epoch id'));
  for (const s of c.servers) put(3, concatBytes(hexN(s.host, 32, 'host'), utf8ToBytes(JSON.stringify({ https: s.https, relays: s.relays }))));
  put(4, hexN(c.holderInbox, 32, 'holder inbox'));
  return concatBytes(...parts);
}
function untlv(b: Uint8Array): { sk: Uint8Array | null; card: Card } {
  let sk: Uint8Array | null = null; const card: Card = { g: '', epoch: '', servers: [], holderInbox: '' };
  for (let i = 0; i < b.length;) {
    const t = b[i], l = (b[i + 1] << 8) | b[i + 2], v = b.slice(i + 3, i + 3 + l); i += 3 + l;
    if (v.length !== l) refuse('bad_backup', 'truncated');
    if (t === 0) sk = v; else if (t === 1) card.g = bytesToHex(v); else if (t === 2) card.epoch = bytesToHex(v);
    else if (t === 3) card.servers.push({ host: bytesToHex(v.slice(0, 32)), ...strictJson(utf8Strict(v.slice(32))) });
    else if (t === 4) card.holderInbox = bytesToHex(v);
  }
  if (sk) checkSecret(sk);
  return { sk, card };
}

/** §2: the QR payload, `kkbak1…` in bech32 (not bech32m), no length limit, upper case for the QR. */
export const backupQR = (sk: Uint8Array, c: Card) => { checkSecret(sk); return bech32.encode(PREFIX, bech32.toWords(tlv(sk, c)), false).toUpperCase(); };
/** The account card: the same TLV without the secret, kept by friends and the heir. */
export const accountCard = (c: Card) => bech32.encode(`${PREFIX}card`, bech32.toWords(tlv(null, c)), false);
export function readBackupQR(s: string) {
  const d = bech32.decode(s.toLowerCase() as `${string}1${string}`, false);
  if (d.prefix !== PREFIX && d.prefix !== `${PREFIX}card`) refuse('bad_backup', 'not a Keykin backup');
  return untlv(bech32.fromWords(d.words));
}

/** §2: 24 words: the raw scalar as BIP-39 English, the last 8 bits the first 8 of SHA-256("keykin-backup/1" ‖ secret). */
export function backupWords(sk: Uint8Array): string[] {
  checkSecret(sk);
  const bits = [...sk, sha('keykin-backup/1', sk)[0]].map((b) => b.toString(2).padStart(8, '0')).join('');
  return Array.from({ length: 24 }, (_, k) => wordlist[parseInt(bits.slice(11 * k, 11 * k + 11), 2)]);
}
export function readBackupWords(words: string[]): Uint8Array {
  if (words.length !== 24) refuse('bad_backup', '24 words');
  const idx = words.map((w) => wordlist.indexOf(w.toLowerCase().trim()));
  if (idx.some((i) => i < 0)) refuse('bad_backup', 'not a backup word');
  const bits = idx.map((i) => i.toString(2).padStart(11, '0')).join('');
  const bytes = Uint8Array.from({ length: 33 }, (_, k) => parseInt(bits.slice(8 * k, 8 * k + 8), 2));
  const sk = bytes.slice(0, 32);
  if (sha('keykin-backup/1', sk)[0] !== bytes[32]) {
    if (validateMnemonic(words.join(' '), wordlist)) refuse('wallet_seed', 'This looks like a wallet seed, not a Keykin backup');
    refuse('bad_backup', 'checksum');
  }
  checkSecret(sk);
  return sk;
}

/** §3: the holder-inbox key, and what a holder's acknowledgement signs. */
export const holderInboxKey = (baseDk: string) => hkdf32(hexN(baseDk, 32, 'base data key'), 'keykin-holders/1');
export const pieceAckDigest = (g: string, setId: string, piece: Uint8Array) => sha('keykin-piece/1', hexN(g, 32, 'g'), hexN(setId, 32, 'set id'), piece);

// --- §4.1 the heir's envelope ---------------------------------------------------------------

export interface HeirRecord { set: string; H: string; E: string; nonce: string; envelope: string; C0: string; C1: string; wait_days: number }
const heirAD = (g: string, H: string, set: string) => concatBytes(utf8ToBytes('keykin-heir/1'), hexN(g, 32, 'g'), hexN(H, 32, 'H'), hexN(set, 32, 'set id'));
const heirKey = (z: Uint8Array, r: bigint) => hkdf(sha256, concatBytes(z, hexToBytes(scalarHex(r))), new Uint8Array(0), utf8ToBytes('keykin-heir/1'), 32);

/** Seal the backup secret and card for the heir: `r` split 2-of-3 over the server seats' indices. */
export function makeHeir(o: { g: string; setId: string; heirKey: string; secret: Uint8Array; card: string; seats: number[]; waitDays?: number }) {
  const r = mod(BigInt('0x' + bytesToHex(randomBytes(32)))), a1 = mod(BigInt('0x' + bytesToHex(randomBytes(32))));
  const e = mod(BigInt('0x' + bytesToHex(randomBytes(32))));
  const z = hexToBytes(compHex(mul(e, liftX(o.heirKey))).slice(2));
  const nonce = randomBytes(12);
  const env = chacha20poly1305(heirKey(z, r), nonce, heirAD(o.g, o.heirKey, o.setId)).encrypt(utf8ToBytes(JSON.stringify({ secret: bytesToHex(o.secret), card: o.card })));
  const record: HeirRecord = { set: o.setId, H: o.heirKey, E: compHex(mul(e)), nonce: bytesToHex(nonce), envelope: bytesToHex(env), C0: compHex(mul(r)), C1: compHex(mul(a1)), wait_days: o.waitDays ?? 180 };
  if (record.wait_days < 30) refuse('bad_heir', 'wait days under 30');
  const pieces = new Map(o.seats.map((x) => [x, mod(r + a1 * BigInt(x))]));
  return { record, recordHash: bytesToHex(sha(jcs(record))), pieces };
}
/** A server's, or the heir's, check of one piece: `r_x·G == C0 + x·C1`. */
export const checkHeirPiece = (rec: HeirRecord, x: number, piece: bigint) => mul(piece).equals(pointFrom(rec.C0).add(mul(BigInt(x), pointFrom(rec.C1))));
/** The heir opens the envelope with two pieces and its holder key. */
export function openHeir(rec: HeirRecord, g: string, heirSk: Uint8Array, pieces: [number, bigint][]): { secret: string; card: string } {
  if (pieces.length < 2) refuse('bad_heir', 'two pieces');
  for (const [x, p] of pieces) if (!checkHeirPiece(rec, x, p)) refuse('bad_piece', `x = ${x}`);
  const two = pieces.slice(0, 2);
  const r = two.reduce((acc, [x, p]) => mod(acc + p * lagrange(BigInt(x), two.map(([y]) => BigInt(y)))), 0n);
  const z = hexToBytes(compHex(mul(BigInt('0x' + bytesToHex(heirSk)), pointFrom(rec.E))).slice(2));
  const plain = chacha20poly1305(heirKey(z, r), hexToBytes(rec.nonce), heirAD(g, rec.H, rec.set)).decrypt(hexToBytes(rec.envelope));
  return strictJson(utf8Strict(plain));
}
export const heirWaitId = (H: string, setId: string, requestId: string) => bytesToHex(sha('heir', hexN(H, 32, 'H'), hexN(setId, 32, 'set id'), hexN(requestId, 16, 'request id')));
export { G, scalarFrom };
