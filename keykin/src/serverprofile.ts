// Server profile module (§3, §4): enrol replies and their per-seat keys, the signed public server
// list, and the deterministic replacement pick. Pure.

import { p256 } from '@noble/curves/nist.js';
import { sha, shaHex, hkdf32, hexN, jcs, concatBytes, bytesToHex, hexToBytes, u32be, u64be, refuse, utf8ToBytes } from './bytes.ts';
import { schnorrSign, schnorrVerify, pubOf, verifyEvent, tag, type KeyPair, type NostrEvent } from './event.ts';
import { N } from './curve.ts';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const REPLY_MAX_AGE_S = 30 * 86400;
export const LIST_D = 'keykin-server-list';

export interface EnrollReply {
  g: string; secret_id: string; nonce: string; member_key: string; vapid: string; https: string;
  relays: string[]; operator: string; issued: number; host: string; host_sig: string;
}

/** §4: a key under an order from the enrol secret: HKDF-SHA256(empty salt, secret, info ‖ g ‖ nonce ‖ c). */
function derive(secret: Uint8Array, label: string, g: string, nonce: string, order: bigint): Uint8Array {
  for (let c = 0; c < 256; c++) {
    const info = concatBytes(utf8ToBytes(label), hexN(g, 32, 'g'), hexN(nonce, 16, 'nonce'), new Uint8Array([c]));
    const k = hkdf(sha256, secret, new Uint8Array(0), info, 32);
    const v = BigInt('0x' + bytesToHex(k));
    if (v > 0n && v < order) return k;
  }
  return refuse('derive');
}
export const deriveMemberSk = (secret: Uint8Array, g: string, nonce: string) => derive(secret, 'keykin-member/1', g, nonce, N);
export const deriveVapidSk = (secret: Uint8Array, g: string, nonce: string) => derive(secret, 'keykin-vapid/1', g, nonce, p256.Point.Fn.ORDER);

const replyBody = (r: Omit<EnrollReply, 'host' | 'host_sig'>) => ({ g: r.g, secret_id: r.secret_id, nonce: r.nonce, member_key: r.member_key, vapid: r.vapid,
  https: r.https, relays: r.relays, operator: r.operator, issued: r.issued });
export const enrollDigest = (r: Omit<EnrollReply, 'host' | 'host_sig'>) => sha('keykin-enroll/1', jcs(replyBody(r)));

/** A server's answer to `enroll {g}`: fresh keys for this one seat, signed by its host key. */
export function enrollReply(host: KeyPair, enrolSecret: Uint8Array, secretId: string, g: string, nonce: string, o: { https: string; relays: string[]; operator: string; issued: number }):
  { reply: EnrollReply; memberSk: Uint8Array; vapidSk: Uint8Array } {
  const memberSk = deriveMemberSk(enrolSecret, g, nonce), vapidSk = deriveVapidSk(enrolSecret, g, nonce);
  const body = { g, secret_id: secretId, nonce, member_key: pubOf(memberSk), vapid: bytesToHex(p256.getPublicKey(vapidSk, false)), ...o };
  return { reply: { ...body, host: host.pub, host_sig: schnorrSign(enrollDigest(body), host.sk) }, memberSk, vapidSk };
}

/** Repair helpers and the server itself check only the host signature (§4); the co-signer also checks
 *  the reply's age on its own clock (`now`). The seat's `new` entry must be the reply's. */
export function checkEnroll(entry: { key: string; host?: string; vapid?: string; enroll?: unknown }, g: string, now?: number): string | null {
  const r = entry.enroll as EnrollReply | undefined;
  if (!r || typeof r !== 'object') return 'no_enroll';
  if (r.g !== g || r.member_key !== entry.key || r.host !== entry.host || (entry.vapid !== undefined && entry.vapid !== r.vapid)) return 'enroll_mismatch';
  if (!schnorrVerify(r.host_sig, enrollDigest(r), r.host)) return 'enroll_sig';
  if (now !== undefined && (now - r.issued > REPLY_MAX_AGE_S || r.issued - now > 600)) return 'enroll_expired';
  return null;
}

// --- the signed public list -------------------------------------------------------------------

export interface ListServer { host: string; operator: string; https: string; relays: string[]; versions: number[]; closing?: boolean }
export interface ServerList { version: number; issued: number; key_next?: string; servers: ListServer[] }

/** A list version as the app takes it: signed by the pinned key (or a `key_next` a pinned version named),
 *  never lower than the newest seen from that key. Returns the new pin and the list. */
export function acceptList(ev: NostrEvent, pin: { key: string; newest: number }): { key: string; newest: number; list: ServerList; nextPin: string | null } {
  if (ev.kind !== 30078 || tag(ev, 'd') !== LIST_D || !verifyEvent(ev)) refuse('bad_list_event');
  if (ev.pubkey !== pin.key) refuse('not_pinned');
  const list = JSON.parse(ev.content) as ServerList;
  if (!Number.isSafeInteger(list.version) || list.version <= pin.newest) refuse('rollback', 'a list never goes back');
  const sorted = [...list.servers].map((x) => x.host).sort();
  if (JSON.stringify(sorted) !== JSON.stringify(list.servers.map((x) => x.host))) refuse('bad_list', 'servers sorted by host key');
  return { key: pin.key, newest: list.version, list, nextPin: list.key_next ?? null };
}

/** §4 / core §6.7.7: the open servers, in list order, dealt round-robin to the three server seats
 *  sorted by index; the pick is `int(SHA-256(g ‖ dead key ‖ seat (4) ‖ version (8))) mod |slice|`, then
 *  the slice in list order, then the whole list, never a host already seated or the helper's, and never
 *  two seats on one operator while another eligible one exists. Returns candidates in order. */
export function pickOrder(list: ServerList, seats: number[], seat: number, g: string, deadKey: string, o: { seatedHosts: Set<string>; seatedOperators: Set<string>; helperOperator?: string } ): ListServer[] {
  const open = list.servers.filter((x) => !x.closing);
  const order = [...seats].sort((a, b) => a - b);
  const k = order.indexOf(seat);
  if (k < 0) refuse('no_such_seat');
  const slice = open.filter((_, j) => j % order.length === k);
  const ok = (x: ListServer) => !o.seatedHosts.has(x.host) && x.operator !== o.helperOperator;
  const out: ListServer[] = [];
  if (slice.length) {
    const h = BigInt('0x' + shaHex(hexN(g, 32, 'g'), hexN(deadKey, 32, 'dead key'), u32be(seat), u64be(list.version)));
    const start = Number(h % BigInt(slice.length));
    for (let j = 0; j < slice.length; j++) out.push(slice[(start + j) % slice.length]);
  }
  for (const x of open) if (!out.includes(x)) out.push(x);
  const eligible = out.filter(ok);
  // Prefer an operator that holds no seat yet; fall back only when none is left.
  return [...eligible.filter((x) => !o.seatedOperators.has(x.operator)), ...eligible.filter((x) => o.seatedOperators.has(x.operator))];
}
export { hkdf32, hexToBytes };

// --- announcements (§4) -----------------------------------------------------------------------

export interface Announcement { host: string; relays: string[]; https: string | null; enroll: 'open' | 'invite'; versions: number[]; pow?: number; operator: string | null }
/** A kind 30243 server announcement, `d = keykin-server` (readers also accept `cosign-server`), signed by the host key. */
export function readAnnouncement(e: NostrEvent): Announcement | null {
  if (e.kind !== 30243 || !['keykin-server', 'cosign-server'].includes(tag(e, 'd') ?? '') || !verifyEvent(e)) return null;
  let c: any; try { c = JSON.parse(e.content); } catch { return null; }
  if (!Array.isArray(c.relays) || !['open', 'invite'].includes(c.enroll) || !Array.isArray(c.versions)) return null;
  const op = e.tags.find((t) => t[0] === 'p' && t[3] === 'operator')?.[1] ?? null;
  return { host: e.pubkey, relays: c.relays, https: c.https ?? null, enroll: c.enroll, versions: c.versions, pow: c.pow, operator: op };
}
/** A server belongs to an operator only when both name each other: its announcement's operator `p`, and
 *  the operator's kind 10243 list naming its host key. */
export function operatorOf(a: Announcement, opList: NostrEvent | null): string | null {
  if (!a.operator || !opList || opList.kind !== 10243 || opList.pubkey !== a.operator || !verifyEvent(opList)) return null;
  return opList.tags.some((t) => t[0] === 'p' && t[1] === a.host) ? a.operator : null;
}
/** Enrol secrets rotate monthly and are destroyed 13 months after they were made (§4). */
export const enrolSecretAlive = (madeAt: number, now: number) => now - madeAt < 13 * 31 * 86400;
