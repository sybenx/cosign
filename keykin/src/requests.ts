// Requests that every server checks and no co-signer joins (core §6.1's generic request, §6.2):
// `account_delete` (Account admin §3) and `helper_resume` (Helper §3.2). The approval check is pure, so
// a server checks it at first hand, a server checks a peer's relayed `deleted` with it, and a device
// checks a `deleted` answer with it before believing it. Also Account admin §3's `deleted` proof.

import { bytesToHex, hexToBytes, sha, jcsBytes, refuse } from './bytes.ts';
import { what, detachedDigest } from './codes.ts';
import { checkAssertion } from './lock.ts';
import { schnorrVerify } from './event.ts';
import { servers, type Membership } from './membership.ts';

export interface RequestCheck {
  /** The member the request came from: a lock or paper approval must be its own. */
  from?: string;
  /** This server's host key: its own paper challenge entry, when present, must check. */
  me?: string;
  /** Use up this server's own challenge, issued to `backup`. Given only at first hand: then the entry
   *  for `me` is required and its challenge must be fresh. */
  take?: (challenge: string, backup: string) => boolean;
}

/** The approvers of a request's approval in `m`'s view, or a refusal. `msg` is the whole request, the
 *  approval inside it; `what` is over the rest (§6.1). */
export function requestApprovers(m: Membership, g: string, type: string, msg: any, o: RequestCheck = {}): string[] {
  const { approval, ...body } = msg ?? {};
  const w = what.request(type, msg?.id, body);
  if (approval?.lock) {
    const member = approval.lock.member, cur = m.locks.get(member);
    if (!m.devices.has(member) || !cur || (o.from !== undefined && member !== o.from)) refuse('needs_approval');
    const e = checkAssertion(g, cur!, w, approval.lock.assertion); if (e) refuse(e);
    return [member];
  }
  if (approval?.pair) {
    const [x, y] = approval.pair;
    if (!x || !y || x.member === y.member || !m.devices.has(x.member) || !m.devices.has(y.member)) refuse('approver_not_device');
    const d = detachedDigest('pair', g, { what: bytesToHex(w), r: x.r });
    if (!schnorrVerify(x.sig, d, x.member) || !schnorrVerify(y.code_sig, d, y.member)) refuse('bad_signature');
    return [x.member, y.member];
  }
  if (approval?.paper) {
    const p = approval.paper;
    if (!p || typeof p !== 'object' || !Array.isArray(p.challenges) || !p.challenges.length) refuse('malformed', 'a paper request approval carries challenges');
    if (p.backup !== m.backupKey || !m.devices.has(p.member)) refuse('not_current_backup');
    if (o.from !== undefined && p.member !== o.from) refuse('needs_approval', 'the paper approval is by the requesting device');
    const wh = bytesToHex(w);
    if (!schnorrVerify(p.sig, detachedDigest('paper', g, { what: wh }), p.member)) refuse('bad_signature');
    const signed = (c: any) => typeof c?.challenge === 'string' && schnorrVerify(c.backup_sig, detachedDigest('paper', g, { what: wh, challenge: c.challenge }), p.backup);
    // Entries naming this server: another member can't block us by adding one (review 8 M1), so we
    // take the first that is validly signed and a challenge we issued and can still use.
    const mine = o.me === undefined ? [] : p.challenges.filter((c: any) => c?.server === o.me);
    if (o.take) {
      const ok = mine.filter(signed);
      if (!ok.length) refuse(mine.length ? 'bad_signature' : 'stale_challenge', 'no challenge from this server');
      if (!ok.some((c: any) => o.take!(c.challenge, p.backup))) refuse('stale_challenge');
    } else {
      // Not at first hand: some current server's entry must check (ours, if any, was taken already).
      const hosts = new Set(servers(m).map((s) => s.host));
      if (!p.challenges.some((c: any) => hosts.has(c?.server) && signed(c))) refuse('bad_signature');
    }
    return [p.member];
  }
  return refuse('needs_approval');
}

/** Account admin §3: the digest a server's host key signs in `deleted`. */
export const deletedDigest = (g: string, request: unknown) => sha('keykin-deleted/1', hexToBytes(g), jcsBytes(request));

/** Does a `deleted` answer prove the account was deleted, in `m`'s view? Host-signed by a current
 *  server seat's host, over an `account_delete` for `g` whose approval checks here (§3: "Every device
 *  that verifies it destroys everything"). A `deleted` that doesn't verify proves nothing. */
export function verifyDeleted(m: Membership, g: string, ans: any): boolean {
  try {
    if (ans?.type !== 'deleted' || ans.request?.type !== 'account_delete' || ans.request?.g !== g || ans.request?.epoch !== m.epochId) return false;
    if (!servers(m).some((s) => s.host === ans.host)) return false;
    if (!schnorrVerify(ans.host_sig, deletedDigest(g, ans.request), ans.host)) return false;
    requestApprovers(m, g, 'account_delete', ans.request);
    return true;
  } catch { return false; }
}
