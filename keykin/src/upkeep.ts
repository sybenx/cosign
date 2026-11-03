// Upkeep's server-side rules and proofs (core §6.7.3–§6.7.4, §6.5 step 4, §7.2). Pure.

import { sha, bytesToHex, randomBytes, hexToBytes, refuse, u32be } from './bytes.ts';
import { type Commitment, derivePoint, mul, mod, compBytes, compHex, pointFrom, scalarFrom, scalarHex, G } from './curve.ts';
import { checkApproval, approvalHash, type Authority } from './approval.ts';
import { itemHash, openItem, sealItem, commitmentAt, type Item } from './redeal.ts';
import { schnorrSign, schnorrVerify, type KeyPair } from './event.ts';
import { detachedDigest } from './codes.ts';
import type { Membership } from './membership.ts';
import type { Approval, Change, MemberEntry, Redeal } from './types.ts';

export const UPLOAD_TTL_S = 7 * 86400;

/** The post-change view of a list (§6.7.3): who gets deltas. Never an outgoing seat holder, never
 *  a member the list removes, never the backup (it gets the paper item). Incoming seat holders are in. */
export function postListView(m: Membership, list: Change[]): Map<string, MemberEntry> {
  const out = new Map([...m.members].filter(([, x]) => x.kind !== 'backup'));
  for (const c of list) {
    if ('remove' in c) out.delete(c.remove);
    if ('seat' in c) {
      const cur = m.seats.get(c.seat.seat)?.holder;
      if (cur) out.delete(cur.key);
      if (c.seat.new) out.set(c.seat.new.key, c.seat.new);
    }
  }
  return out;
}
/** The backup key current after the list (`paper_to`). */
export const postListBackup = (m: Membership, list: Change[]) => (list.find((c) => 'paper' in c) as any)?.paper.key ?? m.backupKey;

export interface Upload { list: Change[]; approval: Approval; redealId: string; items: { type: string; to: string; wrap: unknown; release?: boolean }[]; at: number; paperItem?: Item; held: Set<string> }

/** `upload {list, approval, items}` (§6.7.3): refused without the approval list and its valid
 *  approval, from anyone but the list's dealer (a current device), for a redeal already co-signed,
 *  or to replace an upload already held. */
export function acceptUpload(m: Membership, from: string, msg: any, now: number, held?: Upload): Upload {
  const { error } = checkApproval(m.authority, msg.list, msg.approval);
  if (error) refuse(error, 'upload without a valid approval');
  if (msg.approval.expiry !== undefined && msg.approval.expiry < now) refuse('approval_expired');
  const ph = (msg.list as Change[]).find((c) => 'redeal' in c) as { redeal: { dealer: string } } | undefined;
  if (!ph || ph.redeal.dealer !== from || !m.devices.has(from) || m.removed.has(from)) refuse('not_dealer', 'only the list\'s dealer uploads');
  if (m.redeals.has(msg.redeal)) refuse('already_cosigned');
  if (held && uploadLive(held, now)) refuse('upload_held', 'an upload for this redeal is already held');
  return { list: msg.list, approval: msg.approval, redealId: msg.redeal, items: msg.items ?? [], at: now, paperItem: msg.paper_item, held: new Set() };
}
export const uploadLive = (u: Upload, now: number) => now - u.at <= UPLOAD_TTL_S;

/** The co-signer of a redeal (§6.7.3): what's missing before it may co-sign. */
export function redealMissing(m: Membership, list: Change[], r: Redeal, u: Upload | undefined, liveSeatHolders: number): string[] {
  if (!u) return ['upload'];
  const view = postListView(m, list);
  const missing = [...view.keys()].filter((k) => !u.items.some((it) => it.type === 'delta' && it.to === k));
  if (!u.paperItem || itemHash(u.paperItem) !== r.paper_item) missing.push('paper_item');
  // The release seed travels inside each device's and seat server's sealed delivery (`release`).
  if (!u.items.some((it) => it.type === 'release_seed' || it.release)) missing.push('release_seed');
  if (r.paper_to !== postListBackup(m, list)) refuse('bad_paper_to');
  const need = Math.min(2, liveSeatHolders);
  if (u.held.size < need) missing.push('upload_held');
  return missing;
}

// --- rerepair proofs (§6.7.4) ---------------------------------------------------------------

/** A Schnorr proof of knowledge of the share at index `i` at an earlier state, bound to the owner's
 *  member key and a server challenge issued to it: `e = H("keykin-rerepair/1" ‖ g ‖ key ‖ i ‖ P ‖ R ‖ challenge)`. */
export function rerepairProof(g: string, key: string, i: number, s: bigint, challenge: string) {
  const k = mod(BigInt('0x' + bytesToHex(randomBytes(32))));
  const R = mul(k), P = mul(s);
  const e = mod(BigInt('0x' + bytesToHex(sha('keykin-rerepair/1', hexToBytes(g), hexToBytes(key), u32be(i), compBytes(P), compBytes(R), hexToBytes(challenge)))));
  return { i, R: compHex(R), z: scalarHex(mod(k + e * s)) };
}
/** Verify against `P_i` derived from the commitment of the claimed earlier state. */
export function verifyRerepair(g: string, key: string, C: Commitment, challenge: string, p: { i: number; R: string; z: string }): boolean {
  try {
    const P = derivePoint(C, BigInt(p.i)), R = pointFrom(p.R), z = scalarFrom(p.z);
    const e = mod(BigInt('0x' + bytesToHex(sha('keykin-rerepair/1', hexToBytes(g), hexToBytes(key), u32be(p.i), compBytes(P), compBytes(R), hexToBytes(challenge)))));
    return mul(z).equals(R.add(mul(e, P)));
  } catch { return false; }
}

/** `need_repair` (§6.7.4): only a seat's current holder (or a device by its add), never the backup seat. */
export function needRepairAllowed(m: Membership, from: string, index: number): boolean {
  if (m.record.seats.backup.includes(index)) return false;
  const me = m.members.get(from);
  return !!me && !m.removed.has(from) && me.kind !== 'backup' && me.shares.includes(index);
}

// --- backup material (§4.3, §7.2) and recovery (§6.5 step 4) -------------------------------

/** The base item at creation or for a new paper: the backup's shares and the base data key, sealed
 *  to K, signed by K, wrapped under its own release seed. */
export function baseItem(backup: KeyPair, releaseSeed: string, shares: Map<number, bigint>, baseDk: string, state: string[]): Item {
  const { item } = sealItem('base', null, backup.pub, releaseSeed, { shares: [...shares].map(([i, s]) => [i, scalarHex(s)]), dk: baseDk, state });
  return { ...item, sig: schnorrSign(sha(itemHash(item)), backup.sk) };
}

/** The holder sums the base and the paper items of exactly the redeals in the servers' state and
 *  checks the result against `P_b^S`. `seeds` maps a redeal id (or 'base') to its release seed. */
export function openMaterial(o: { g: string; backup: KeyPair; pin: string; base: Item; baseSeed: string; items: Item[]; seeds: Map<string, string>;
  C0: Commitment; redeals: Redeal[]; state: Set<string> }) {
  if (itemHash(o.base) !== o.pin) refuse('bad_material', 'the base does not match its pin');
  if (!schnorrVerify(o.base.sig, sha(itemHash(o.base)), o.backup.pub)) refuse('bad_material', 'not signed by the backup key');
  const base = openItem(o.base, o.baseSeed, { backupSk: o.backup.sk });
  const shares = new Map<number, bigint>(base.shares.map(([i, s]: [number, string]) => [i, scalarFrom(s)]));
  const baseState = new Set<string>(base.state);
  const later = o.redeals.filter((r) => o.state.has(r.id) && !baseState.has(r.id));
  for (const r of later) {
    const it = o.items.find((x) => x.redeal === r.id && x.to === o.backup.pub && itemHash(x) === r.paper_item) ?? o.items.find((x) => x.redeal === r.id && x.kind === 'reissue' && x.to === o.backup.pub);
    const seed = o.seeds.get(r.id);
    if (!it || !seed) refuse('missing_item', r.id);
    const v = openItem(it!, seed!, { backupSk: o.backup.sk });
    v.b.forEach((b: number, k: number) => shares.set(b, mod(shares.get(b)! + scalarFrom(v.d[k]))));
  }
  const C = commitmentAt(o.C0, o.redeals.filter((r) => o.state.has(r.id)));
  for (const [i, s] of shares) if (!mul(s).equals(derivePoint(C, BigInt(i)))) refuse('bad_material', `the sum misses P_${i}`);
  return { shares, C, dk: base.dk as string };
}
export { G, detachedDigest };
