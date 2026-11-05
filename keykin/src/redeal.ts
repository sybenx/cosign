// Redeals and a member's state (core §6.7.1–§6.7.3, §7.2): dealing, the per-member deltas,
// the paper item, and applying. Pure apart from randomness.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import * as nip44 from 'nostr-tools/nip44';
import { nip44Open } from './nip44.ts';
import { sha, shaHex, bytesToHex, hexToBytes, randomBytes, jcs, concatBytes, utf8ToBytes, refuse, utf8Strict, strictJson } from './bytes.ts';
import { stateHash, detachedDigest } from './codes.ts';
import { type Commitment, mul, mod, N, addRedeal, deriveDelta, derivePoint, interpolate, pointFrom, compHex, scalarHex, scalarFrom, liftX } from './curve.ts';
import { checkOwnShares } from './record.ts';
import { schnorrSign, schnorrVerify, newKey, pubOf, type KeyPair } from './event.ts';
import type { Redeal } from './types.ts';

const rand = () => mod(BigInt('0x' + bytesToHex(randomBytes(32))));

/** The body the dealer signs: the redeal without its `sig`. */
export const redealDigest = (g: string, r: Redeal) => { const { sig: _s, ...body } = r; return detachedDigest('redeal', g, body); };

/** XChaCha20-Poly1305 under a release seed (§7.2): nonce ‖ ciphertext, hex. */
export function wrapUnder(seed: string, plain: Uint8Array): string {
  const nonce = randomBytes(24);
  return bytesToHex(concatBytes(nonce, xchacha20poly1305(hexToBytes(seed), nonce).encrypt(plain)));
}
export function unwrapUnder(seed: string, hex: string): Uint8Array {
  const b = hexToBytes(hex);
  return xchacha20poly1305(hexToBytes(seed), b.slice(0, 24)).decrypt(b.slice(24));
}

/** One material item (§7.2): sealed to the backup key K, then wrapped under a release seed. */
/** `seeds`: a paper's seed item; `seed-only`: a device's seed-only re-issue (core 14.21 §4.5, §7.2). */
export interface Item { kind: 'base' | 'paper' | 'reissue' | 'seeds' | 'seed-only'; redeal: string | null; to: string; eph: string; box: string; clear?: string[]; by?: string; sig?: string }
export const itemHash = (it: Item) => shaHex(jcs({ ...it, sig: undefined }));

/** Returns the item and its ephemeral secret (`eph`), which devices get as `paper_eph` / `reissue_eph`
 *  (core 14.20) to derive the conversation key themselves, exactly as K will from its side. */
export function sealItem(kind: Item['kind'], redeal: string | null, K: string, releaseSeed: string, body: unknown): { item: Item; eph: string } {
  const eph = newKey();
  const ck = nip44.v2.utils.getConversationKey(eph.sk, K);
  const inner = nip44.v2.encrypt(JSON.stringify(body), ck);
  return { item: { kind, redeal, to: K, eph: eph.pub, box: wrapUnder(releaseSeed, utf8ToBytes(inner)) }, eph: bytesToHex(eph.sk) };
}
/** Open an item: by the backup key holder (`backupSk`), or by a device from the item's ephemeral secret
 *  (`ephSk`), deriving the same conversation key towards the item's `to` (core 14.20). */
export function openItem(it: Item, releaseSeed: string, key: { backupSk?: Uint8Array; ephSk?: string }): any {
  const inner = utf8Strict(unwrapUnder(releaseSeed, it.box));
  const ck = key.ephSk ? nip44.v2.utils.getConversationKey(hexToBytes(key.ephSk), it.to) : nip44.v2.utils.getConversationKey(key.backupSk!, it.eph);
  return strictJson(nip44Open(inner, ck));
}

/** Everything a dealer makes for one redeal (§6.7.3). `δ` lives only in this object, in process
 *  memory, until the co-sign; call `destroy()` then or on any failure. */
export interface Dealt {
  redeal: Redeal;
  deltas: Map<string, Map<number, bigint>>;   // member key → its indices → δ(i)
  paperValues: { b: number[]; values: bigint[] };
  releaseSeed: string; dkSeed: string; paperEph: string; paperItem: Item;
  destroy(): void;
}

/** Deal a redeal for the post-change view: `members` maps each recipient's key to its indices
 *  (devices, seat holders and incoming ones; never the backup, never a removed key). */
export function deal(g: string, dealer: KeyPair, base: string[], members: Map<string, number[]>, paperTo: string, backupSeat: number[], abandons: string[] = []): Dealt {
  let d: bigint[] = [0n, rand(), rand(), rand()];
  if (d.slice(1).every((x) => x === 0n)) refuse('zero_redeal');
  const f = (x: number) => d.reduce((acc, c, k) => mod(acc + c * BigInt(x) ** BigInt(k)), 0n);
  const D = d.slice(1).map((c) => mul(c));
  const deltas = new Map([...members].map(([k, idx]) => [k, new Map(idx.map((i) => [i, f(i)]))]));
  const paperValues = { b: backupSeat, values: backupSeat.map(f) };
  const releaseSeed = bytesToHex(randomBytes(32)), dkSeed = bytesToHex(randomBytes(32));
  const id = bytesToHex(randomBytes(16));
  const { item, eph } = sealItem('paper', id, paperTo, releaseSeed, { redeal: id, d: paperValues.values.map(scalarHex), b: backupSeat, dk_seed: dkSeed });
  const r: Redeal = { id, dealer: dealer.pub, D: D.map(compHex), paper_to: paperTo, paper_item: itemHash(item),
    dk: shaHex(hexToBytes(dkSeed)), rs: shaHex(hexToBytes(releaseSeed)), base: [...base].sort(), abandons: [...abandons].sort() };
  r.sig = schnorrSign(redealDigest(g, r), dealer.sk);
  const out: Dealt = { redeal: r, deltas, paperValues, releaseSeed, dkSeed, paperEph: eph, paperItem: item,
    destroy() { d = []; out.deltas.clear(); out.paperValues.values = []; out.paperEph = ''; } };
  return out;
}

/** A member's share state (§6.7.1): applied redeal ids, `C_S` and its shares. */
export interface State { ids: Set<string>; C: Commitment; shares: Map<number, bigint> }
export const stateOf = (s: State) => stateHash(s.ids);

/** Why a redeal can't be applied now, or null. `abandoned` is every id a valid `abandons` names. */
export function applicable(s: State, r: Redeal, abandoned: Set<string>): string | null {
  if (s.ids.has(r.id)) return 'applied';
  if (abandoned.has(r.id) || r.base.some((b) => abandoned.has(b))) return 'abandoned';
  if (r.base.some((b) => !s.ids.has(b))) return 'missing_base';
  if (r.abandons.some((a) => s.ids.has(a))) return 'rerepair';
  return null;
}

/** §6.7.1 steps 1–3. Returns the new state; the caller destroys the old shares and deltas. For a
 *  device, also the paper values `δ(b1), δ(b2)` it keeps until the paper item is verified. */
export function applyRedeal(g: string, s: State, r: Redeal, deltas: Map<number, bigint>, device: boolean, backupSeat: number[], abandoned = new Set<string>()):
  { state: State; paperValues?: bigint[] } {
  const why = applicable(s, r, abandoned);
  if (why) refuse('cannot_apply', why);
  const D = r.D.map((h) => pointFrom(h));
  if (D.some((p) => p.is0())) refuse('bad_redeal', 'D contains the identity');
  if ([...s.shares.keys()].some((i) => !deltas.has(i)) || deltas.size !== s.shares.size) refuse('bad_redeal', 'a delta for each index');
  for (const [i, di] of deltas) if (!mul(di).equals(deriveDelta(D, BigInt(i)))) refuse('bad_delta', `index ${i}`);
  const C = addRedeal(s.C, D);
  const shares = new Map([...s.shares].map(([i, v]) => [i, mod(v + deltas.get(i)!)]));
  checkOwnShares(g, shares, C, device);
  const ids = new Set([...s.ids, r.id]);
  if (!device) return { state: { ids, C, shares } };
  const pts: [bigint, bigint][] = [[0n, 0n], ...[...deltas].map(([i, v]) => [BigInt(i), v] as [bigint, bigint])];
  return { state: { ids, C, shares }, paperValues: backupSeat.map((b) => interpolate(pts, BigInt(b))) };
}

/** §6.7.6: the clear `δ(b)·G` of a re-issued item checked against the redeal's commitments. */
export const reissueClearOk = (r: Redeal, b: number[], clear: string[]) =>
  clear.length === b.length && b.every((x, k) => compHex(deriveDelta(r.D.map((h) => pointFrom(h)), BigInt(x))) === clear[k]);

/** The commitment at a set of applied redeals: `C + Σ D_r`. */
export function commitmentAt(C0: Commitment, redeals: Redeal[]): Commitment {
  return redeals.reduce((c, r) => addRedeal(c, r.D.map((h) => pointFrom(h))), C0);
}
export { stateHash, derivePoint, liftX, scalarFrom, sha, pubOf, N };

/** A redeal delivery as its receiver checks it (§6.7.2, §6.7.3): sealed by the redeal's dealer, and
 *  every seed it carries matching the hash the group-signed redeal pins. Throws to refuse. */
export function checkDelivery(r: Redeal, from: string, body: { release?: string; dk?: string }, toDevice = false) {
  if (from !== r.dealer) refuse('not_dealer', 'a delta comes only from its redeal\'s dealer');
  // A device's delivery carries the data-key seed: without it the device could never read new data (review 12 L3).
  if (toDevice && body.dk === undefined) refuse('missing_seed', 'a device\'s delivery carries the data-key seed');
  // And the release seed: without it the device could neither re-issue nor read the item (review 14 M2).
  if (toDevice && body.release === undefined) refuse('missing_seed', 'a device\'s delivery carries the release seed');
  if (body.release !== undefined && shaHex(hexToBytes(body.release)) !== r.rs) refuse('bad_seed', 'release seed');
  if (body.dk !== undefined && shaHex(hexToBytes(body.dk)) !== r.dk) refuse('bad_seed', 'data-key seed');
}

/** `paper_eph` / `reissue_eph` as a device gets it (core 14.20): bound to its redeal and item. */
export interface ItemEph { redeal: string; item: string; eph: string; K?: string }
/** A device's own paper values for a redeal (§6.7.1 step 3): `δ(b)` for the backup seat, and the seed. */
export interface PaperValues { b: number[]; d: bigint[]; dk: string }

/** Core 14.20 §6.7.1 step 0 (and §6.7.6 for a re-issued item): open `item` with a conversation key derived
 *  from its ephemeral secret, never one taken from the sender, and compare it with this device's own values.
 *  'missing': the eph isn't bound to this redeal and item (or isn't the item's key), so it proves nothing;
 *  'bad': a bound eph that doesn't open the item, or opens it to other contents (proof against the sealer);
 *  'ok': the item is what K needs. `own` null: only the clear checks (a device that kept no values). */
export function checkItem(r: Redeal, item: Item | undefined, releaseSeed: string, pe: ItemEph | undefined, own: PaperValues | null, backupSeat: number[], pinned?: string): 'ok' | 'missing' | 'bad' {
  if (!item || !pe || typeof pe !== 'object' || pe.redeal !== r.id || item.redeal !== r.id || pe.item !== itemHash(item) || typeof pe.eph !== 'string') return 'missing';
  // The dealer's item is the one the group-signed redeal pins (its hash, to `paper_to`).
  if (pinned !== undefined && (pinned !== pe.item || item.to !== r.paper_to)) return 'missing';
  try { if (pubOf(hexToBytes(pe.eph)) !== item.eph) return 'missing'; } catch { return 'missing'; }
  let v: any;
  try { v = openItem(item, releaseSeed, { ephSk: pe.eph }); } catch { return 'bad'; }
  try {
    const D = r.D.map((h) => pointFrom(h));
    if (v.redeal !== r.id || JSON.stringify(v.b) !== JSON.stringify(backupSeat) || !Array.isArray(v.d) || v.d.length !== backupSeat.length) return 'bad';
    const ds = v.d.map((x: string) => scalarFrom(x));
    if (!backupSeat.every((b, k) => mul(ds[k]).equals(deriveDelta(D, BigInt(b))))) return 'bad';
    if (typeof v.dk_seed !== 'string' || shaHex(hexToBytes(v.dk_seed)) !== r.dk) return 'bad';
    if (own && (JSON.stringify(own.b) !== JSON.stringify(backupSeat) || own.d.some((x, k) => x !== ds[k]) || own.dk !== v.dk_seed)) return 'bad';
    return 'ok';
  } catch { return 'bad'; }
}

/** §6.7.6 re-issue: a device seals the paper values it kept for a redeal to the current backup key K, as
 *  a supplementary item under that redeal's release seed, with the `δ(b)·G` values in the clear, signed
 *  by its member key. K learns only what devices already know. */
/** Core 14.19 §5.9: a member key signs the item as `detached("paper-reissue", item without its sig)`. */
const reissueDigest = (g: string, it: Item) => detachedDigest('paper-reissue', g, { ...it, sig: undefined });
export function reissueItem(g: string, r: Redeal, K: string, releaseSeed: string, values: { b: number[]; d: bigint[]; dk: string }, by: KeyPair): { item: Item; eph: string } {
  const { item, eph } = sealItem('reissue', r.id, K, releaseSeed, { redeal: r.id, d: values.d.map(scalarHex), b: values.b, dk_seed: values.dk });
  const full: Item = { ...item, clear: values.d.map((x) => compHex(mul(x))), by: by.pub };
  return { item: { ...full, sig: schnorrSign(reissueDigest(g, full), by.sk) }, eph };
}
/** What a server (and any device) checks before keeping a re-issued item: for the current K, from a
 *  current device that signed it, and clear values on the redeal's commitments. */
export function checkReissue(g: string, r: Redeal, item: Item, K: string, isDevice: (k: string) => boolean, backupSeat: number[]): string | null {
  if (item.kind !== 'reissue' || item.redeal !== r.id) return 'bad_item';
  if (item.to !== K) return 'not_current_backup';
  if (!item.by || !isDevice(item.by)) return 'not_device';
  if (!schnorrVerify(item.sig, reissueDigest(g, item), item.by)) return 'bad_signature';
  if (!item.clear || !reissueClearOk(r, backupSeat, item.clear)) return 'bad_clear';
  return null;
}
