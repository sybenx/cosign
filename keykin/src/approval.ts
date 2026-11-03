// Approvals (core §6.1, §6.2): building and checking them. A checker here is what every member
// runs (signatures, the approver's membership, the structure). Freshness (the lock expiry, the
// paper challenge, waited statements' age) is the co-signer's alone (§3.2), in cosign.ts.

import { bytesToHex, refuse } from './bytes.ts';
import { what, listHash, detachedDigest, selfDigest, waitedDigest, recoveryWaitId } from './codes.ts';
import { checkAssertion, type LockPub, type SoftLock } from './lock.ts';
import { schnorrSign, schnorrVerify, type KeyPair } from './event.ts';
import { changeType, type Approval, type Change, type Waited } from './types.ts';

export const W_DEFAULT = 3 * 86400;
export const MAX_EXPIRY_S = 86400;

/** What every member knows about who may approve (§3.2): devices of the membership (never a
 *  helper), every lock each has had, the backup keys and the host keys of the account's seats. */
export interface Authority {
  g: string; epochId: string;
  devices: Set<string>;
  locks: (member: string) => LockPub[];
  backupKeys: Set<string>;
  hostKeys: Set<string>;
  W: number;
}

export type ApprovalType = 'lock' | 'pair' | 'paper' | 'recovery' | 'self';
export const approvalType = (a: Approval): ApprovalType | null => {
  const ks = (['lock', 'pair', 'paper', 'recovery', 'self'] as const).filter((k) => a && (a as any)[k] !== undefined);
  return ks.length === 1 ? ks[0] : null;
};

/** §6.2's table: which approvals each list shape accepts. */
export function allowedApprovals(list: Change[]): ApprovalType[] {
  const types = list.map(changeType);
  if (types.length === 1 && types[0] === 'add') return ['lock', 'pair', 'paper', 'recovery'];
  if (types.length === 1 && types[0] === 'lock') return ['pair', 'paper', 'recovery'];
  const selfRemove = list.some((c) => 'remove' in c && (c as any).to !== undefined);
  if (selfRemove) return ['self'];
  return ['lock', 'pair', 'paper', 'recovery'];
}

/** §6.7.2: list shapes. add and lock travel alone; seat, remove and paper travel with exactly one
 *  redeal (the mandatory redeal, a `self` remove included); a bare `[redeal]` is allowed. */
export function checkListShape(list: Change[]): void {
  if (!Array.isArray(list) || list.length === 0) refuse('bad_list', 'empty');
  const types = list.map(changeType);
  if (types.some((t) => !['add', 'remove', 'lock', 'seat', 'paper', 'redeal'].includes(t))) refuse('bad_list', 'unknown change');
  if ((types.includes('add') || types.includes('lock')) && list.length !== 1) refuse('bad_list', 'add and lock travel alone');
  const redeals = types.filter((t) => t === 'redeal').length;
  const needs = types.some((t) => t === 'seat' || t === 'remove' || t === 'paper');
  if (needs && redeals !== 1) refuse('mandatory_redeal', 'a list with a seat, remove or paper change carries exactly one redeal');
  if (!needs && types.includes('redeal') && list.length !== 1) refuse('bad_list');
  if (types.filter((t) => t === 'paper').length > 1) refuse('bad_list', 'one paper per list');
  // A device the list removes never deals its redeal (§6.4): it would keep 3 points at the new state.
  const dealer = (list.find((c) => 'redeal' in c) as any)?.redeal.dealer;
  if (dealer && list.some((c) => 'remove' in c && c.remove === dealer)) refuse('bad_list', 'a removed device never deals the redeal');
  const self = list.filter((c) => 'remove' in c && (c as any).to !== undefined);
  if (self.length && (self.length !== 1 || list.length !== 2 || !types.includes('redeal'))) refuse('bad_list', 'a self remove is exactly [remove, redeal]');
}

/** The list as approved: redeals as `{dealer}` placeholders, papers without `inner` and `state`. */
export function placeholderList(list: Change[]): Change[] {
  return list.map((c) => {
    if ('redeal' in c) return { redeal: { dealer: c.redeal.dealer } };
    if ('paper' in c) return { paper: { key: c.paper.key, replaces: c.paper.replaces } };
    return c;
  });
}
export const approvalHash = (list: Change[]) => listHash(placeholderList(list));

/** The bytes a lock (or a `pair`) signs for a list (§6.1). */
export const changeWhat = (g: string, epochId: string, list: Change[], expiry: number) => what.change(approvalHash(list), epochId, expiry);

const pairBody = (w: Uint8Array, r: string) => ({ what: bytesToHex(w), r });

// --- builders (devices) ----------------------------------------------------------------

export const approveLock = (g: string, epochId: string, list: Change[], expiry: number, member: string, lock: SoftLock): Approval =>
  ({ expiry, lock: { member, assertion: lock.assert(g, changeWhat(g, epochId, list, expiry)) } });

export function approvePair(g: string, epochId: string, list: Change[], expiry: number, first: KeyPair, second: KeyPair, r: string): Approval {
  const d = detachedDigest('pair', g, pairBody(changeWhat(g, epochId, list, expiry), r));
  return { expiry, pair: [{ member: first.pub, sig: schnorrSign(d, first.sk), r }, { member: second.pub, code_sig: schnorrSign(d, second.sk) }] };
}

export function approvePaper(g: string, epochId: string, list: Change[], expiry: number, device: KeyPair, backup: KeyPair, challenge: string, server: string): Approval {
  const w = changeWhat(g, epochId, list, expiry);
  return { expiry, paper: { member: device.pub, sig: schnorrSign(detachedDigest('paper', g, { what: bytesToHex(w) }), device.sk),
    backup: backup.pub, challenge, server,
    backup_sig: schnorrSign(detachedDigest('paper', g, { list: approvalHash(list), challenge }), backup.sk) } };
}

export function approveRecovery(g: string, list: Change[], backup: KeyPair, releaseRequest: unknown, waited: Waited[]): Approval {
  return { recovery: { backup: backup.pub, release_request: releaseRequest, waited,
    backup_sig: schnorrSign(detachedDigest('recovery', g, { list: approvalHash(list) }), backup.sk) } };
}

export function approveSelf(g: string, list: Change[], leaving: KeyPair, app: KeyPair): Approval {
  const d = selfDigest(g, approvalHash(list));
  return { self: { member: leaving.pub, sig: schnorrSign(d, leaving.sk), app_sig: schnorrSign(d, app.sk) } };
}

export function signWaited(g: string, host: KeyPair, kind: 'recovery' | 'hold', wait: string, start: number, end: number): Waited {
  return { server: host.pub, kind, wait, start, end, sig: schnorrSign(waitedDigest(g, kind, wait, start, end), host.sk) };
}
export const checkWaited = (g: string, w: Waited, W: number) =>
  w && w.end - w.start >= W && schnorrVerify(w.sig, waitedDigest(g, w.kind, w.wait, w.start, w.end), w.server);

// --- the check every member runs -------------------------------------------------------

/** Null if the approval is valid for this list in every member's eyes; otherwise the code. The
 *  approvers it names are returned for the co-signer's freshness checks. */
export function checkApproval(auth: Authority, list: Change[], a: Approval): { error: string | null; approvers: string[] } {
  const fail = (error: string) => ({ error, approvers: [] as string[] });
  const t = approvalType(a);
  if (!t) return fail('bad_approval');
  if (!allowedApprovals(list).includes(t)) return fail('approval_not_allowed');
  const { g, epochId } = auth;
  const isDevice = (k: unknown) => typeof k === 'string' && auth.devices.has(k);
  const needsExpiry = t === 'lock' || t === 'pair' || t === 'paper';
  if (needsExpiry && !Number.isSafeInteger(a.expiry)) return fail('bad_approval');
  const w = needsExpiry ? changeWhat(g, epochId, list, a.expiry!) : new Uint8Array();
  switch (t) {
    case 'lock': {
      const { member, assertion } = a.lock!;
      if (!isDevice(member)) return fail('approver_not_device');
      const errs = auth.locks(member).map((l) => checkAssertion(g, l, w, assertion));
      if (!errs.length) return fail('no_lock');
      return errs.includes(null) ? { error: null, approvers: [member] } : fail(errs[0]!);
    }
    case 'pair': {
      const p = a.pair!;
      if (!Array.isArray(p) || p.length !== 2) return fail('bad_approval');
      const [x, y] = p;
      if (!isDevice(x.member) || !isDevice(y.member)) return fail('approver_not_device');
      if (x.member === y.member) return fail('pair_same_device');
      const d = detachedDigest('pair', g, pairBody(w, x.r));
      if (!schnorrVerify(x.sig, d, x.member) || !schnorrVerify(y.code_sig, d, y.member)) return fail('bad_signature');
      return { error: null, approvers: [x.member, y.member] };
    }
    case 'paper': {
      const p = a.paper!;
      if (!isDevice(p.member)) return fail('approver_not_device');
      if (!auth.backupKeys.has(p.backup)) return fail('not_backup_key');
      if (!schnorrVerify(p.sig, detachedDigest('paper', g, { what: bytesToHex(w) }), p.member)) return fail('bad_signature');
      if (!schnorrVerify(p.backup_sig, detachedDigest('paper', g, { list: approvalHash(list), challenge: p.challenge }), p.backup)) return fail('bad_signature');
      return { error: null, approvers: [p.member] };
    }
    case 'recovery': {
      const p = a.recovery!;
      if (!auth.backupKeys.has(p.backup)) return fail('not_backup_key');
      if (!schnorrVerify(p.backup_sig, detachedDigest('recovery', g, { list: approvalHash(list) }), p.backup)) return fail('bad_signature');
      const rr = p.release_request as { r?: string };
      if (!rr || typeof rr.r !== 'string') return fail('bad_approval');
      const wait = recoveryWaitId(p.backup, epochId, rr.r);
      const ok = (p.waited ?? []).filter((s) => s.kind === 'recovery' && s.wait === wait && auth.hostKeys.has(s.server) && checkWaited(g, s, auth.W));
      if (new Set(ok.map((s) => s.server)).size < 2) return fail('waited_missing');
      return { error: null, approvers: [] };
    }
    case 'self': {
      const p = a.self!;
      const rm = list.find((c) => 'remove' in c) as { remove: string; to: string };
      if (p.member !== rm.remove) return fail('bad_approval');
      if (!isDevice(p.member) || !isDevice(rm.to) || p.member === rm.to) return fail('approver_not_device');
      const d = selfDigest(g, approvalHash(list));
      if (!schnorrVerify(p.sig, d, p.member) || !schnorrVerify(p.app_sig, d, rm.to)) return fail('bad_signature');
      const rd = list.find((c) => 'redeal' in c) as { redeal: { dealer: string } };
      if (rd.redeal.dealer !== rm.to) return fail('self_redeal_dealer'); // the app taking over deals the redeal
      return { error: null, approvers: [p.member, rm.to] };
    }
  }
}
