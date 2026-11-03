// The membership: the epoch record plus every valid change, in any order (core §3.2, §6.7.2).
// `computeMembership` is a pure function of the record and the *set* of changes, so every member
// that holds the same set reaches the same answer whatever order the changes arrived in.

import { hexN, jcs, KeykinError, refuse } from './bytes.ts';
import { deviceIndices, helperSeat, listHash } from './codes.ts';
import { pointFrom } from './curve.ts';
import { verifyEvent, tag, schnorrVerify, type NostrEvent } from './event.ts';
import { checkApproval, checkListShape, placeholderList, approvalHash, W_DEFAULT, type Authority } from './approval.ts';
import { checkInvariants } from './record.ts';
import { redealDigest } from './redeal.ts';
import type { LockPub } from './lock.ts';
import { KIND_CHANGE, changeType, type Change, type ChangeContent, type EpochContent, type MemberEntry, type Redeal } from './types.ts';

export interface Parsed { ev: NostrEvent; c: ChangeContent; type: string; listHash: string }

const isLock = (l: any): l is LockPub => l && typeof l === 'object' && /^04[0-9a-f]{128}$/.test(l.pub) && /^[0-9a-f]{64}$/.test(l.rp);
const k32 = (h: unknown, what: string) => hexN(h, 32, what);

/** §3.4: the structural checks on one change event (kind, tags, group signature, shapes). */
export function parseChange(rec: EpochContent, ev: NostrEvent): Parsed {
  if (ev?.kind !== KIND_CHANGE) refuse('not_a_change', 'kind');
  let c: ChangeContent;
  try { c = JSON.parse(ev.content); } catch { return refuse('not_a_change', 'content'); }
  if (c.v !== 1) refuse('unsupported_version');
  if (tag(ev, 'v') !== String(c.v) || tag(ev, 'epoch') !== c.epoch) refuse('bad_change', 'tags disagree with the content');
  if (c.g !== rec.g || ev.pubkey !== rec.g) refuse('wrong_group');
  if (c.epoch !== rec.epoch.id) refuse('wrong_epoch');
  if (!verifyEvent(ev)) refuse('bad_signature');
  checkListShape(c.list);
  if (jcs(placeholderList(c.list)) !== jcs(c.list)) refuse('bad_list', 'the list is carried in its approved (placeholder) form');
  const ph = jcs(placeholderList([c.change])[0]);
  if (!c.list.some((x) => jcs(x) === ph)) refuse('bad_list', 'the change is not in its list');
  const type = changeType(c.change);
  const ch: any = c.change;
  switch (type) {
    case 'add': {
      const a = ch.add;
      k32(a.key, 'add key');
      if (a.kind !== 'device') refuse('bad_change', 'a new member is always a device');
      if (!Number.isSafeInteger(a.salt) || a.salt < 0) refuse('bad_change', 'salt');
      if (a.lock !== null && !isLock(a.lock)) refuse('bad_change', 'lock');
      break;
    }
    case 'remove': k32(ch.remove, 'remove key'); if (ch.to !== undefined) k32(ch.to, 'to'); break;
    case 'lock': {
      k32(ch.lock.member, 'lock member');
      if (!isLock(ch.lock.new)) refuse('bad_change', 'lock');
      const r = ch.lock.replaces;
      if (r !== null && typeof r !== 'string') refuse('bad_change', 'replaces');
      break;
    }
    case 'seat': {
      const s = ch.seat;
      const seats = rec.seats;
      const m = /^server:(\d+)$/.exec(s.seat);
      if (!(m && seats.servers.includes(Number(m[1]))) && s.seat !== 'helper') refuse('bad_change', 'no such seat');
      if (s.new !== null) {
        const e: MemberEntry = s.new;
        k32(e.key, 'seat key');
        if (m) { if (e.kind !== 'server' || JSON.stringify(e.shares) !== JSON.stringify([Number(m[1])]) || typeof e.host !== 'string') refuse('bad_change', 'a server seat takes a server at its index'); }
        else if (e.kind !== 'helper' || JSON.stringify(e.shares) !== JSON.stringify(helperSeat(rec.g))) refuse('bad_change', 'the helper seat takes a helper');
      }
      if (s.replaces !== null && typeof s.replaces !== 'string') refuse('bad_change', 'replaces');
      break;
    }
    case 'paper': {
      const p = ch.paper;
      k32(p.key, 'paper key'); k32(p.replaces, 'replaces');
      k32(p.inner, 'inner');
      if (!Array.isArray(p.state)) refuse('bad_change', 'a committed paper change names its state');
      p.state.forEach((i: unknown) => hexN(i, 16, 'state id'));
      break;
    }
    case 'redeal': {
      const r: Redeal = ch.redeal;
      hexN(r.id, 16, 'redeal id'); k32(r.dealer, 'dealer'); k32(r.paper_to, 'paper_to');
      k32(r.paper_item, 'paper_item'); k32(r.dk, 'dk'); k32(r.rs, 'rs');
      if (!Array.isArray(r.D) || r.D.length !== 3) refuse('bad_change', 'D is [D1, D2, D3]');
      r.D.forEach((d, k) => pointFrom(d, `D${k + 1}`));
      for (const x of [...r.base, ...r.abandons]) hexN(x, 16, 'redeal id');
      if (!schnorrVerify(r.sig, redealDigest(rec.g, r), r.dealer)) refuse('bad_signature', 'dealer');
      break;
    }
  }
  return { ev, c, type, listHash: approvalHash(c.list) };
}

export interface SeatState { holder: MemberEntry | null; voided: string[] }
export interface Membership {
  g: string; epochId: string; record: EpochContent;
  members: Map<string, MemberEntry>;
  devices: Set<string>;
  removed: Set<string>;
  seats: Map<string, SeatState>;
  backupKey: string | null; backupKeys: string[];
  locks: Map<string, LockPub | null>;
  accepted: Parsed[];
  refused: { id: string; code: string }[];
  redeals: Map<string, { r: Redeal; listHash: string; withRemove: boolean }>;
  abandoned: Set<string>;
  voidAdds: Set<string>;
  invariantError: string | null;
  /** Lists with seat changes that no current seat holder's host co-signed (F3): a notice. */
  uncosigned: string[];
  authority: Authority;
}

/** Follow a chain (a lock, a seat, the paper) from its first holder along changes that name the
 *  current holder in `replaces` (§3.2, §6.7.2). `same` groups candidates that count as one, the
 *  lowest change hash winning. When candidates disagree: `void` empties the chain until a
 *  `void:<id>` change, `lowest` takes the lowest hash (paper changes). */
function follow<N>(first: { id: string | null; value: N | null }, cands: { hash: string; replaces: string | null; newId: string | null; value: N | null; forceVoid?: boolean }[],
  same: (a: any, b: any) => boolean, onConflict: 'void' | 'lowest', retired: (id: string) => void) {
  let cur = first, voided: string[] = [];
  const used = new Set<string>();
  for (let guard = 0; guard < 10_000; guard++) {
    const step = cands.filter((c) => !used.has(c.hash) && (cur.id !== null ? c.replaces === cur.id : voided.length ? voided.some((v) => c.replaces === `void:${v}`) : c.replaces === null));
    if (!step.length) break;
    step.forEach((c) => used.add(c.hash));
    step.sort((a, b) => (a.hash < b.hash ? -1 : 1));
    const winner = step[0];
    const allSame = step.every((c) => same(c, winner)) && !step.some((c) => c.forceVoid);
    if (cur.id !== null) retired(cur.id);
    if (allSame || onConflict === 'lowest') {
      for (const c of step.slice(1)) if (c.newId && c.newId !== winner.newId) retired(c.newId);
      cur = { id: winner.newId, value: winner.value };
      voided = [];
    } else {
      for (const c of step) if (c.newId) retired(c.newId);
      cur = { id: null, value: null };
      voided = step.map((c) => c.hash);
    }
  }
  return { cur, voided };
}

export function computeMembership(rec: EpochContent, events: NostrEvent[], W = W_DEFAULT): Membership {
  const g = rec.g, epochId = rec.epoch.id;
  const refused: { id: string; code: string }[] = [];
  const parsed: Parsed[] = [];
  const seenIds = new Set<string>();
  for (const ev of events) {
    if (seenIds.has(ev?.id)) continue;
    seenIds.add(ev?.id);
    try { parsed.push(parseChange(rec, ev)); } catch (e) { refused.push({ id: ev?.id, code: e instanceof KeykinError ? e.code : 'malformed' }); }
  }
  const recDevices = rec.members.filter((m) => m.kind === 'device');
  const recBackup = rec.members.find((m) => m.kind === 'backup')?.key ?? null;

  // Approvals, to a fixed point: an approval may name a device added by another accepted change.
  const accepted: Parsed[] = [];
  let pending = parsed;
  const authority = (): Authority => {
    const adds = accepted.filter((p) => p.type === 'add');
    const devices = new Set([...recDevices.map((m) => m.key), ...adds.map((p) => (p.c.change as any).add.key)]);
    const lockHist = new Map<string, LockPub[]>();
    const push = (k: string, l: LockPub | null | undefined) => { if (l) lockHist.set(k, [...(lockHist.get(k) ?? []), l]); };
    recDevices.forEach((m) => push(m.key, m.lock));
    adds.forEach((p) => push((p.c.change as any).add.key, (p.c.change as any).add.lock));
    accepted.filter((p) => p.type === 'lock').forEach((p) => push((p.c.change as any).lock.member, (p.c.change as any).lock.new));
    const backupKeys = new Set([recBackup, ...accepted.filter((p) => p.type === 'paper').map((p) => (p.c.change as any).paper.key)].filter(Boolean) as string[]);
    const hostKeys = new Set([...rec.members.filter((m) => m.kind === 'server').map((m) => m.host!),
      ...accepted.filter((p) => p.type === 'seat').map((p) => (p.c.change as any).seat.new?.host).filter(Boolean)]);
    return { g, epochId, devices, locks: (k) => lockHist.get(k) ?? [], backupKeys, hostKeys, W };
  };
  for (let progress = true; progress && pending.length;) {
    progress = false;
    const auth = authority();
    const next: Parsed[] = [];
    for (const p of pending) {
      const { error } = checkApproval(auth, p.c.list, p.c.approval);
      if (error === null) { accepted.push(p); progress = true; } else next.push(p);
    }
    pending = next;
  }
  for (const p of pending) refused.push({ id: p.ev.id, code: checkApproval(authority(), p.c.list, p.c.approval).error! });
  const auth = authority();

  const removed = new Set(rec.removed);
  const of = (t: string) => accepted.filter((p) => p.type === t).map((p) => ({ p, ch: p.c.change as any }));
  const everDevice = auth.devices;

  // Removes (a remove always wins; it names a device, never a seat holder).
  for (const { p, ch } of of('remove')) {
    if (!everDevice.has(ch.remove)) { refused.push({ id: p.ev.id, code: 'remove_not_device' }); continue; }
    removed.add(ch.remove);
  }

  // Seats.
  const seats = new Map<string, SeatState>();
  const seatCh = of('seat');
  const hostOfNew = new Map<string, string[]>();
  for (const { p, ch } of seatCh) if (ch.seat.new?.host) hostOfNew.set(ch.seat.new.host, [...(hostOfNew.get(ch.seat.new.host) ?? []), `${ch.seat.seat}|${p.listHash}`]);
  const recordKeys = new Set(rec.members.map((m) => m.key));
  const seatIds = [...rec.seats.servers.map((i) => `server:${i}`), 'helper'];
  for (const sid of seatIds) {
    const first = sid === 'helper' ? rec.members.find((m) => m.kind === 'helper') : rec.members.find((m) => m.kind === 'server' && `server:${m.shares[0]}` === sid);
    const cands = seatCh.filter(({ ch }) => ch.seat.seat === sid)
      .filter(({ ch }) => !ch.seat.new || !(everDevice.has(ch.seat.new.key) || recordKeys.has(ch.seat.new.key) || rec.removed.includes(ch.seat.new.key)))
      .map(({ p, ch }) => ({ hash: p.listHash, replaces: ch.seat.replaces, newId: ch.seat.new?.key ?? null, value: ch.seat.new as MemberEntry | null,
        forceVoid: !!ch.seat.new?.host && new Set((hostOfNew.get(ch.seat.new.host) ?? []).map((x) => x.split('|')[0])).size > 1 }));
    const same = (a: any, b: any) => a.newId === b.newId || (a.value?.host && a.value?.host === b.value?.host);
    const r = follow({ id: first?.key ?? null, value: first ?? null }, cands, same, 'void', (k) => removed.add(k));
    seats.set(sid, { holder: r.cur.value, voided: r.voided });
  }

  // The paper: lowest hash wins a conflict, the loser's key is removed.
  const paperR = follow({ id: recBackup, value: recBackup }, of('paper').map(({ p, ch }) => ({ hash: p.listHash, replaces: ch.paper.replaces, newId: ch.paper.key, value: ch.paper.key })),
    (a, b) => a.newId === b.newId, 'lowest', (k) => removed.add(k));
  const backupKey = paperR.cur.id;

  // Adds: indices from the hash; any index claimed twice voids every add claiming it.
  const voidAdds = new Set<string>();
  const claims = new Map<number, Set<string>>();
  const claim = (i: number, who: string) => claims.set(i, (claims.get(i) ?? new Set()).add(who));
  for (const m of rec.members) m.shares.forEach((i) => claim(i, m.key));
  for (const i of [...rec.seats.servers, ...rec.seats.backup, ...rec.seats.helper]) claim(i, 'seat');
  const adds = new Map<string, { salt: number; lock: LockPub | null; indices: number[] }[]>();
  for (const { ch } of of('add')) {
    const a = ch.add, indices = deviceIndices(g, epochId, a.key, a.salt);
    const prev = adds.get(a.key) ?? [];
    if (!prev.some((x) => x.salt === a.salt)) prev.push({ salt: a.salt, lock: a.lock, indices });
    adds.set(a.key, prev);
    indices.forEach((i) => claim(i, a.key));
  }
  for (const [key, list] of adds) {
    if (list.length > 1 || recordKeys.has(key)) { voidAdds.add(key); continue; }
    if (list[0].indices.some((i) => (claims.get(i)?.size ?? 0) > 1) || new Set(list[0].indices).size !== 3) voidAdds.add(key);
  }

  // Locks: follow each device's lock along lock changes.
  const locks = new Map<string, LockPub | null>();
  const lockCh = of('lock');
  const lockFirst = new Map<string, LockPub | null>([...recDevices.map((m) => [m.key, m.lock ?? null] as const),
    ...[...adds].filter(([k]) => !voidAdds.has(k)).map(([k, l]) => [k, l[0].lock] as const)]);
  for (const [k, l0] of lockFirst) {
    const cands = lockCh.filter(({ ch }) => ch.lock.member === k).map(({ p, ch }) => ({ hash: p.listHash, replaces: ch.lock.replaces, newId: ch.lock.new.pub, value: ch.lock.new }));
    const r = follow({ id: l0?.pub ?? null, value: l0 }, cands, (a, b) => a.newId === b.newId, 'void', () => {});
    locks.set(k, r.cur.value);
  }

  // Redeals.
  const redeals = new Map<string, { r: Redeal; listHash: string; withRemove: boolean }>();
  for (const { p, ch } of of('redeal')) {
    const r: Redeal = ch.redeal;
    if (redeals.has(r.id)) continue;
    redeals.set(r.id, { r, listHash: p.listHash, withRemove: p.c.list.some((x) => 'remove' in x) });
  }
  const abandoned = new Set<string>();
  for (const [id, x] of [...redeals]) {
    if (x.r.abandons.some((a) => redeals.get(a)?.withRemove)) { redeals.delete(id); refused.push({ id, code: 'abandons_remove_redeal' }); continue; }
    x.r.abandons.forEach((a) => abandoned.add(a));
  }

  // The membership.
  const members = new Map<string, MemberEntry>();
  for (const m of recDevices) if (!removed.has(m.key)) members.set(m.key, { ...m, lock: locks.get(m.key) ?? null });
  for (const [k, l] of adds) if (!voidAdds.has(k) && !removed.has(k)) members.set(k, { key: k, kind: 'device', shares: l[0].indices, lock: locks.get(k) ?? null });
  for (const s of seats.values()) if (s.holder && !removed.has(s.holder.key)) members.set(s.holder.key, s.holder);
  if (backupKey && !removed.has(backupKey)) members.set(backupKey, { key: backupKey, kind: 'backup', shares: rec.seats.backup });
  for (const m of rec.members) if (!['device', 'server', 'helper', 'backup'].includes(m.kind) && !removed.has(m.key)) members.set(m.key, m);
  const devices = new Set([...members.values()].filter((m) => m.kind === 'device').map((m) => m.key));

  let invariantError: string | null = null;
  try { checkInvariants(g, [...members.values()], rec.seats, removed); } catch (e) { invariantError = (e as Error).message; }

  const recordHosts = new Set(rec.members.filter((m) => m.kind === 'server').map((m) => m.host));
  const uncosigned = [...new Set(seatCh.map(({ p }) => p).filter((p) => !p.c.cosig || !recordHosts.has(p.c.cosig.host) && !auth.hostKeys.has(p.c.cosig.host)).map((p) => p.listHash))];

  return { g, epochId, record: rec, members, devices, removed, seats, backupKey, backupKeys: [...auth.backupKeys], locks, accepted, refused,
    redeals, abandoned, voidAdds, invariantError, uncosigned, authority: auth };
}

/** Indices every member of this view knows are taken (§3.2's salt pick). */
export const takenIndices = (m: Membership) => new Set<number>([
  ...[...m.members.values()].flatMap((x) => x.shares), ...m.record.seats.servers, ...m.record.seats.backup, ...m.record.seats.helper,
  ...m.record.members.flatMap((x) => x.shares)]);

/** Current servers, by seat. */
export const servers = (m: Membership) => [...m.seats.entries()].filter(([k, s]) => k.startsWith('server:') && s.holder).map(([, s]) => s.holder!);
export const memberOf = (m: Membership, key: string) => m.members.get(key) ?? null;
export { listHash };
