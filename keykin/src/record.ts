// The epoch record (core §3.1), its invariants (§3.3) and the adoption checks (§3.4). Pure.

import { refuse, hexN, KeykinError } from './bytes.ts';
import { helperSeat } from './codes.ts';
import { commitmentFrom, liftX, derivePoint, rebuildCommitment, sameCommitment, mul, type Commitment } from './curve.ts';
import { verifyEvent, tag, type NostrEvent } from './event.ts';
import { KIND_EPOCH, KNOWN_KINDS, T, type EpochContent, type MemberEntry, type Seats } from './types.ts';

export const D_TAGS = ['keykin', 'cosign', 'frost'];

/** §3.3 over a list of members and the fixed seats. Throws `invariant` with the rule. */
export function checkInvariants(g: string, members: MemberEntry[], seats: Seats, removed: Set<string> = new Set()): void {
  const bad = (rule: string, why: string) => refuse('invariant', `${rule}: ${why}`);
  if (!Array.isArray(seats.servers) || seats.servers.length !== 3 || new Set(seats.servers).size !== 3) bad('seats', 'exactly 3 server seats');
  if (!Array.isArray(seats.backup) || seats.backup.length !== 2) bad('seats', 'the backup seat is 2 indices');
  const hs = helperSeat(g);
  if (JSON.stringify(seats.helper) !== JSON.stringify(hs)) bad('seats', 'the helper seat is the hashed reservation');
  const seatIdx = [...seats.servers, ...seats.backup, ...seats.helper];
  if (new Set(seatIdx).size !== seatIdx.length) bad('seats', 'seats overlap');
  const keys = new Set<string>(), hosts = new Set<string>(), owner = new Map<number, string>();
  let weakWeight = 0, backups = 0, helpers = 0;
  for (const m of members) {
    if (typeof m.key !== 'string' || !Array.isArray(m.shares)) bad('member', 'malformed');
    if (keys.has(m.key)) bad('member', 'a key appears twice');
    keys.add(m.key);
    if (removed.has(m.key)) bad('removed', `${m.key.slice(0, 8)} is removed`);
    if (m.shares.length > 3) bad('I1', 'more than 3 shares');
    for (const i of m.shares) {
      if (!Number.isSafeInteger(i) || i < 1) bad('index', 'indices are integers ≥ 1');
      if (owner.has(i)) bad('index', `index ${i} held twice`);
      owner.set(i, m.key);
    }
    const kind = (KNOWN_KINDS as readonly string[]).includes(m.kind) ? m.kind : 'unknown';
    if (kind === 'device') {
      if (m.shares.length !== 3) bad('device', 'a device holds exactly 3 shares');
      if (m.shares.some((i) => seatIdx.includes(i))) bad('device', 'a device index collides with a seat');
    }
    if (kind === 'server' || kind === 'unknown') {
      if (m.shares.length !== 1 || !seats.servers.includes(m.shares[0])) bad('I2', 'a server holds exactly one server seat');
      if (kind === 'server') {
        if (typeof m.host !== 'string') bad('I2', 'a server names its host');
        if (hosts.has(m.host!)) bad('I2', 'one host in two seats');
        hosts.add(m.host!);
      }
    }
    if (kind === 'backup') {
      backups++;
      if (JSON.stringify([...m.shares].sort((a, b) => a - b)) !== JSON.stringify([...seats.backup].sort((a, b) => a - b))) bad('I3', 'the backup holds exactly the backup seat');
    }
    if (kind === 'helper') {
      helpers++;
      if (JSON.stringify(m.shares) !== JSON.stringify(hs)) bad('I6', 'the helper holds exactly the helper seat');
    }
    if (kind === 'helper' || kind === 'unknown') weakWeight += m.shares.length;
  }
  if (backups > 1) bad('I3', 'one backup');
  if (helpers > 1) bad('I5', 'at most one helper');
  if (weakWeight >= T) bad('I5', 'members with no device and no server are worth 4');
}

export interface AdoptOptions {
  /** The group key this member already knows (its own creation, or the code it scanned). */
  g: string;
  /** For §3.4 step 3: the member's own shares and the commitment of its current state. */
  own?: { shares: Map<number, bigint>; C: Commitment; device: boolean };
  /** Every `removed` this member has seen. */
  removedSeen?: Set<string>;
}

/** §3.4: everything a member checks before adopting an epoch record. Returns the content. */
export function checkEpochRecord(ev: NostrEvent, o: AdoptOptions): EpochContent {
  if (ev?.kind !== KIND_EPOCH) refuse('not_a_record', 'kind');
  const d = tag(ev, 'd');
  if (!d || !D_TAGS.includes(d)) refuse('not_a_record', 'd tag');
  let c: EpochContent;
  try { c = JSON.parse(ev.content); } catch { return refuse('not_a_record', 'content'); }
  if (!c || typeof c !== 'object' || c.v === undefined) refuse('not_a_record', 'content');
  if (c.v !== 1) refuse('unsupported_version', `v ${c.v}`);
  if (tag(ev, 'v') !== String(c.v) || tag(ev, 'epoch') !== String(c.epoch?.n)) refuse('bad_record', 'tags disagree with the content');
  if (ev.pubkey !== o.g || c.g !== o.g) refuse('wrong_group');
  if (!verifyEvent(ev)) refuse('bad_signature');
  if (c.prev !== null || c.epoch.n !== 1) refuse('bad_record', 'Core 1.x has one epoch record');
  hexN(c.epoch.id, 16, 'epoch id');
  if (c.t !== T) refuse('bad_record', 't');
  if (!['master', 'child'].includes(c.role) || !['dkg', 'import'].includes(c.origin)) refuse('bad_record', 'role/origin');
  const C = commitmentFrom(c.commitment);
  if (!C[0].equals(liftX(c.g))) refuse('bad_record', 'C0 is not the group point');
  for (const k of c.removed ?? []) hexN(k, 32, 'removed key');
  const removed = new Set([...(c.removed ?? []), ...(o.removedSeen ?? [])]);
  checkInvariants(c.g, c.members, c.seats, removed);
  for (const m of c.members) if (m.kind === 'server' && !(m.shares[0] !== undefined)) refuse('invariant');
  const held = new Set(c.members.filter((m) => m.kind === 'server').map((m) => m.shares[0]));
  if (c.seats.servers.some((i) => !held.has(i))) refuse('invariant', 'every server seat is held at creation');
  if (!c.members.some((m) => m.kind === 'backup')) refuse('invariant', 'the paper is made at creation (§4.3)');
  if (!c.members.some((m) => m.kind === 'device')) refuse('invariant', 'a device creates the account');
  if (o.own) checkOwnShares(o.g, o.own.shares, o.own.C, o.own.device);
  return c;
}

/** §3.4 steps 3 and 4 at a state: every share it holds is on its point, and a device rebuilds
 *  `C_S` from its own 3 points and the group point. */
export function checkOwnShares(g: string, shares: Map<number, bigint>, C: Commitment, device: boolean): void {
  if (!C[0].equals(liftX(g))) refuse('bad_commitment', 'C0 is not the group point');
  for (const [i, s] of shares) if (!mul(s).equals(derivePoint(C, BigInt(i)))) refuse('bad_share', `index ${i}`);
  if (device) {
    if (shares.size !== 3) refuse('bad_share', 'a device holds 3 shares');
    const pts: [bigint, any][] = [[0n, liftX(g)], ...[...shares].map(([i, s]) => [BigInt(i), mul(s)] as [bigint, any])];
    if (!sameCommitment(rebuildCommitment(pts), C)) refuse('bad_commitment', 'the commitment does not rebuild from this device\'s points');
  }
}
export { KeykinError };
