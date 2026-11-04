// Behaviour cases 3 (records and changes), 5 (locks), 6 (approvals), 7 (report lost) and the
// order-free parts of 12 (seats, paper conflicts, mandatory redeal).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.ts';
import { checkEpochRecord, checkInvariants } from '../src/record.ts';
import { computeMembership, parseChange } from '../src/membership.ts';
import { approveLock, approvePair, approvePaper, approveSelf, changeWhat, checkApproval } from '../src/approval.ts';
import { checkAssertion, softLock, FLAGS } from '../src/lock.ts';
import { deviceIndices, pickSalt, what, helperSeat } from '../src/codes.ts';
import { deal as dealRedeal } from '../src/redeal.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { commitmentHex } from '../src/curve.ts';
import type { Change } from '../src/types.ts';

const EXP = () => Math.floor(Date.now() / 1000) + 3600;
const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

test('case 3: epoch record checks', () => {
  const F = fixture();
  assert.equal(checkEpochRecord(F.recEv, { g: F.g }).g, F.g);
  assert.equal(code(() => checkEpochRecord({ ...F.recEv, kind: 1 }, { g: F.g })), 'not_a_record');
  assert.equal(code(() => checkEpochRecord(F.sign(1, F.recEv.content, F.recEv.tags), { g: F.g })), 'not_a_record', 'a kind 1 that looks like a record');
  assert.equal(code(() => checkEpochRecord(F.sign(30242, F.recEv.content, [['d', 'other'], ['v', '1'], ['epoch', '1']]), { g: F.g })), 'not_a_record');
  assert.equal(code(() => checkEpochRecord(F.sign(30242, F.recEv.content, [['d', 'keykin'], ['v', '1'], ['epoch', '2']]), { g: F.g })), 'bad_record');
  assert.equal(code(() => checkEpochRecord(F.sign(30242, F.recEv.content, [['d', 'cosign'], ['v', '1'], ['epoch', '1']]), { g: F.g })), 'ok', 'old d tags stay readable');
  assert.equal(code(() => checkEpochRecord(F.recEv, { g: newKey().pub })), 'wrong_group', 'an epoch record for another group');
  const tampered = { ...F.recEv, content: F.recEv.content.replace('"t":4', '"t":3') };
  assert.equal(code(() => checkEpochRecord(tampered, { g: F.g })), 'bad_signature');
  // A device whose own points don't rebuild the commitment refuses the record (§3.4 step 4).
  const G = fixture({ mutate: (c) => { c.commitment = [...c.commitment]; } });
  const dev = G.devices[0];
  assert.equal(code(() => checkEpochRecord(G.recEv, { g: G.g, own: { shares: dev.shares, C: G.commitment, device: true } })), 'ok');
  const other = fixture();
  assert.equal(code(() => checkEpochRecord(G.recEv, { g: G.g, own: { shares: other.devices[0].shares, C: G.commitment, device: true } })), 'bad_share');
  const H = fixture({ mutate: (c) => { const x = [...c.commitment]; x[2] = other.rec.commitment[2]; c.commitment = x; } });
  assert.equal(code(() => checkEpochRecord(H.recEv, { g: H.g, own: { shares: H.devices[0].shares, C: H.commitment.map((p, k) => k === 2 ? other.commitment[2] : p), device: true } })), 'bad_share');
});

test('case 3: each invariant broken is refused', () => {
  const F = fixture();
  const ok = () => structuredClone(F.rec);
  const inv = (mut: (c: ReturnType<typeof ok>) => void) => { const c = ok(); mut(c); return code(() => checkInvariants(c.g, c.members, c.seats)); };
  assert.equal(inv(() => {}), 'ok');
  assert.match(String(inv((c) => { c.members[0].shares = [1, 2, 3, 9]; })), /invariant/);                       // I1
  assert.match(String(inv((c) => { c.members[1].shares = [5]; })), /invariant/);                                // I2: server off its seat
  assert.match(String(inv((c) => { c.members[2].host = c.members[1].host; })), /invariant/);                     // I2: one host two seats
  assert.match(String(inv((c) => { c.members[4].shares = [5]; })), /invariant/);                                // I3
  assert.match(String(inv((c) => { c.members.push({ key: newKey().pub, kind: 'helper', shares: [9, 10, 11] }); })), /invariant/); // I6
  // I5: a helper (3) plus an unknown kind holding a share = 4 points with no device and no server.
  assert.match(String(inv((c) => { c.members.push({ key: newKey().pub, kind: 'helper', shares: helperSeat(c.g) }, { key: newKey().pub, kind: 'wizard', shares: [4] }); c.members.splice(1, 1); })), /invariant/);
  assert.equal(inv((c) => { c.members.push({ key: newKey().pub, kind: 'helper', shares: helperSeat(c.g) }); }), 'ok', 'one helper is fine');
  assert.match(String(inv((c) => { c.seats.servers = [4, 7]; })), /invariant/);                                 // exactly 3 server seats
});

function addDevice(F: ReturnType<typeof fixture>, approve: 'lock' | 'pair' | 'paper', key = newKey().pub, salt = 0) {
  const ch: Change = { add: { key, kind: 'device', lock: null, salt } };
  const list = [ch], exp = EXP();
  const a = F.devices[0];
  const approval = approve === 'lock' ? approveLock(F.g, F.epochId, list, exp, a.kp.pub, a.lock!) :
    approve === 'paper' ? approvePaper(F.g, F.epochId, list, exp, a.kp, F.backup.kp, bytesToHex(randomBytes(16)), F.servers[0].host.pub) :
      approvePair(F.g, F.epochId, list, exp, a.kp, (F as any).second, bytesToHex(randomBytes(16)));
  return F.change(ch, list, approval);
}

test('case 3/5/6: an add by lock, then paper; membership grows and indices are hashed', () => {
  const F = fixture();
  const k1 = newKey().pub, k2 = newKey().pub;
  const m = computeMembership(F.rec, [addDevice(F, 'lock', k1), addDevice(F, 'paper', k2)]);
  assert.deepEqual(m.refused, []);
  assert.ok(m.devices.has(k1) && m.devices.has(k2));
  assert.deepEqual(m.members.get(k1)!.shares, deviceIndices(F.g, F.epochId, k1, 0));
  assert.equal(m.invariantError, null);
});

test('case 5: lock assertions', () => {
  const F = fixture();
  const L = F.devices[0].lock!;
  const ev = bytesToHex(randomBytes(32));
  assert.equal(checkAssertion(F.g, L.pub, what.sign(ev), L.assert(F.g, what.sign(ev))), null);
  assert.equal(checkAssertion(F.g, L.pub, what.cancel(ev), L.assert(F.g, what.cancel(ev))), null);
  const w = changeWhat(F.g, F.epochId, [{ remove: ev }], 1);
  assert.equal(checkAssertion(F.g, L.pub, w, L.assert(F.g, w)), null);
  assert.equal(checkAssertion(F.g, L.pub, what.sign(ev), L.assert(F.g, what.sign(ev), FLAGS.UP)), 'lock_flags', 'UV missing');
  assert.equal(checkAssertion(F.g, { ...L.pub, rp: '11'.repeat(32) }, what.sign(ev), L.assert(F.g, what.sign(ev))), 'lock_rp');
  assert.equal(checkAssertion(F.g, L.pub, what.sign(ev), L.assert(F.g, what.sign(bytesToHex(randomBytes(32))))), 'lock_challenge', 'over a different body');
  assert.equal(checkAssertion(F.g, softLock().pub, what.sign(ev), L.assert(F.g, what.sign(ev))), 'lock_sig');
});

test('case 6: approval table rows, met and not met', () => {
  const F = fixture();
  const b = newKey();
  const m0 = computeMembership(F.rec, [addDevice(F, 'lock', b.pub)]);
  const A = F.devices[0];
  const auth = m0.authority, exp = EXP();
  const add: Change[] = [{ add: { key: newKey().pub, kind: 'device', lock: null, salt: 0 } }];
  const lockCh: Change[] = [{ lock: { member: A.kp.pub, replaces: A.lock!.pub.pub, new: softLock().pub } }];
  const rm: Change[] = [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }];
  const ok = (list: Change[], a: any) => checkApproval(auth, list, a).error;
  assert.equal(ok(add, approveLock(F.g, F.epochId, add, exp, A.kp.pub, A.lock!)), null);
  assert.equal(ok(add, approvePair(F.g, F.epochId, add, exp, A.kp, b, 'aa'.repeat(16))), null);
  assert.equal(ok(lockCh, approveLock(F.g, F.epochId, lockCh, exp, A.kp.pub, A.lock!)), 'approval_not_allowed', 'a lock change is never approved by a lock');
  assert.equal(ok(lockCh, approvePair(F.g, F.epochId, lockCh, exp, A.kp, b, 'aa'.repeat(16))), null);
  assert.equal(ok(rm, approveLock(F.g, F.epochId, rm, exp, A.kp.pub, A.lock!)), null);
  assert.equal(ok(rm, approvePair(F.g, F.epochId, rm, exp, A.kp, A.kp, 'aa'.repeat(16))), 'pair_same_device');
  const stranger = newKey();
  assert.equal(ok(add, approvePair(F.g, F.epochId, add, exp, A.kp, stranger, 'aa'.repeat(16))), 'approver_not_device');
  assert.equal(ok(add, approvePaper(F.g, F.epochId, add, exp, A.kp, newKey(), 'bb'.repeat(16), F.servers[0].host.pub)), 'not_backup_key');
  // A helper never approves: it is not a device of the membership.
  const helper = newKey();
  assert.equal(ok(add, approvePair(F.g, F.epochId, add, exp, A.kp, helper, 'aa'.repeat(16))), 'approver_not_device');
  // An approval for one list does not carry over to another.
  assert.equal(ok(rm, approveLock(F.g, F.epochId, add, exp, A.kp.pub, A.lock!)), 'lock_challenge');
});

test('case 7: a lockless single device cannot report another; removal by lock, pair and paper', () => {
  const F = fixture({ lockless: true });
  const A = F.devices[0], b = newKey();
  const m0 = computeMembership(F.rec, [addDevice(F, 'paper', b.pub)]);
  const rm: Change[] = [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }];
  assert.equal(checkApproval(m0.authority, rm, { expiry: EXP(), lock: { member: A.kp.pub, assertion: softLock().assert(F.g, new Uint8Array()) } }).error, 'no_lock');
  for (const how of ['pair', 'paper'] as const) {
    const a = how === 'pair' ? approvePair(F.g, F.epochId, rm, EXP(), A.kp, b, 'cc'.repeat(16)) : approvePaper(F.g, F.epochId, rm, EXP(), A.kp, F.backup.kp, 'dd'.repeat(16), F.servers[0].host.pub);
    assert.equal(checkApproval(m0.authority, rm, a).error, null, how);
  }
});

function redealEv(F: ReturnType<typeof fixture>, list: Change[], approval: any, members: Map<string, number[]>) {
  const dealt = dealRedeal(F.g, F.devices[0].kp, [], members, F.backup.kp.pub, [5, 6]);
  const full = list.map((c) => ('redeal' in c ? { redeal: dealt.redeal } : c));
  return { dealt, events: full.map((c) => F.change(c, list, approval)) };
}

test('case 7/12: [remove, redeal]; mandatory redeal; remove wins over add; order does not matter', () => {
  const F = fixture();
  const A = F.devices[0], b = newKey();
  const addB = addDevice(F, 'lock', b.pub);
  const list: Change[] = [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }];
  const ap = approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!);
  const { events } = redealEv(F, list, ap, new Map([[A.kp.pub, [1, 2, 3]], ...F.servers.map((s) => [s.kp.pub, [s.idx]] as [string, number[]])]));
  const m1 = computeMembership(F.rec, [addB, ...events]);
  const m2 = computeMembership(F.rec, [...events].reverse().concat(addB));
  assert.ok(!m1.devices.has(b.pub) && m1.removed.has(b.pub));
  assert.deepEqual([...m1.devices], [...m2.devices]);
  assert.equal(m1.redeals.size, 1);
  // A [remove] without its redeal is refused structurally.
  const bare: Change[] = [{ remove: b.pub }];
  const ev = F.change(bare[0], bare, approveLock(F.g, F.epochId, bare, EXP(), A.kp.pub, A.lock!));
  assert.equal(code(() => parseChange(F.rec, ev)), 'mandatory_redeal');
  // A remove that names a seat holder is refused.
  const rs: Change[] = [{ remove: F.servers[0].kp.pub }, { redeal: { dealer: A.kp.pub } }];
  const r2 = redealEv(F, rs, approveLock(F.g, F.epochId, rs, EXP(), A.kp.pub, A.lock!), new Map());
  const m3 = computeMembership(F.rec, r2.events);
  assert.ok(m3.refused.some((x) => x.code === 'remove_not_device'));
  assert.ok(!m3.removed.has(F.servers[0].kp.pub));
});

test('case 3: two adds claiming one index are both void; two lock changes replacing one lock are both void', () => {
  const F = fixture();
  const A = F.devices[0];
  // Find two keys whose salt-0 indices collide is infeasible; instead give one key two adds with different salts.
  const k = newKey().pub;
  const m = computeMembership(F.rec, [addDevice(F, 'lock', k, 0), addDevice(F, 'lock', k, 1)]);
  assert.ok(m.voidAdds.has(k) && !m.devices.has(k) && m.removed.has(k), 'void adds\' keys are removed (14.1)');
  // The same add twice (a retry) counts once.
  const m1 = computeMembership(F.rec, [addDevice(F, 'lock', k, 0), addDevice(F, 'lock', k, 0)]);
  assert.ok(m1.devices.has(k));
  // An add whose index collides with a seat is void (forced by a crafted salt pick check).
  const taken = new Set(deviceIndices(F.g, F.epochId, k, 0));
  assert.notDeepEqual(pickSalt(F.g, F.epochId, k, taken).indices, [...taken]);
  // Two lock changes replacing the same lock: both void; the device is lockless until a void: change.
  const b = newKey();
  const addB = addDevice(F, 'lock', b.pub);
  const mk = (pub: any, replaces: string) => {
    const list: Change[] = [{ lock: { member: A.kp.pub, replaces, new: pub } }];
    return F.change(list[0], list, approvePair(F.g, F.epochId, list, EXP(), A.kp, b, 'ee'.repeat(16)));
  };
  const l1 = mk(softLock().pub, A.lock!.pub.pub), l2 = mk(softLock().pub, A.lock!.pub.pub);
  const mv = computeMembership(F.rec, [addB, l1, l2]);
  assert.equal(mv.locks.get(A.kp.pub), null);
  const fresh = softLock();
  const voidId = mv.accepted.find((p) => p.ev.id === l1.id)!.listHash;
  const l3 = mk(fresh.pub, `void:${voidId}`);
  assert.deepEqual(computeMembership(F.rec, [addB, l1, l2, l3]).locks.get(A.kp.pub), fresh.pub);
  // Two lock changes with the same new lock count as one.
  const same = softLock().pub;
  assert.deepEqual(computeMembership(F.rec, [addB, mk(same, A.lock!.pub.pub), mk(same, A.lock!.pub.pub)]).locks.get(A.kp.pub), same);
});

test('case 3: catch-up takes the union, so a server leaving out a removal changes nothing', () => {
  const F = fixture();
  const A = F.devices[0], b = newKey();
  const addB = addDevice(F, 'lock', b.pub);
  const list: Change[] = [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }];
  const { events } = redealEv(F, list, approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!), new Map());
  const s1 = [addB, ...events], s2 = [addB];          // s2 withheld the remove
  const union = [...new Map([...s1, ...s2].map((e) => [e.id, e])).values()];
  assert.ok(computeMembership(F.rec, union).removed.has(b.pub));
});

function seatList(F: ReturnType<typeof fixture>, idx: number, replaces: string | null, entry: any): Change[] {
  return [{ seat: { seat: `server:${idx}`, new: entry, replaces } }, { redeal: { dealer: F.devices[0].kp.pub } }];
}
const srvEntry = (idx: number, host = newKey().pub) => ({ key: newKey().pub, kind: 'server', shares: [idx], host });

test('case 12: seat changes: same new counts once, different new voids both, void: reseats', () => {
  const F = fixture();
  const A = F.devices[0], old = F.servers[2];
  const seatEvs = (entry: any, replaces: string | null = old.kp.pub) => {
    const l = seatList(F, 8, replaces, entry);
    return { list: l, ...redealEv(F, l, approveLock(F.g, F.epochId, l, EXP(), A.kp.pub, A.lock!), new Map()) };
  };
  const y = srvEntry(8);
  const one = seatEvs(y), twin = seatEvs(y);
  const m = computeMembership(F.rec, [...one.events, ...twin.events]);
  assert.equal(m.seats.get('server:8')!.holder!.key, y.key);
  assert.ok(m.removed.has(old.kp.pub), 'the replaced holder goes into removed');
  const z = srvEntry(8);
  const other = seatEvs(z);
  const mv = computeMembership(F.rec, [...one.events, ...other.events]);
  assert.equal(mv.seats.get('server:8')!.holder, null);
  assert.ok(mv.removed.has(y.key) && mv.removed.has(z.key), 'voided news are removed');
  const w = srvEntry(8);
  const re = seatEvs(w, `void:${mv.seats.get('server:8')!.voided[0]}`);
  assert.equal(computeMembership(F.rec, [...one.events, ...other.events, ...re.events]).seats.get('server:8')!.holder!.key, w.key);
  // Same host under two member keys counts once; the lower hash wins and the other key is removed.
  const h = newKey().pub;
  const p = seatEvs(srvEntry(8, h)), q = seatEvs(srvEntry(8, h));
  const mh = computeMembership(F.rec, [...p.events, ...q.events]);
  assert.equal(mh.seats.get('server:8')!.holder!.host, h);
  assert.equal([p, q].map((x) => (x.list[0] as any).seat.new.key).filter((k) => mh.removed.has(k)).length, 1);
  // One host in two seats: both void.
  const h2 = newKey().pub;
  const s4 = seatList(F, 4, F.servers[0].kp.pub, srvEntry(4, h2)), s8 = seatList(F, 8, old.kp.pub, srvEntry(8, h2));
  const e4 = redealEv(F, s4, approveLock(F.g, F.epochId, s4, EXP(), A.kp.pub, A.lock!), new Map());
  const e8 = redealEv(F, s8, approveLock(F.g, F.epochId, s8, EXP(), A.kp.pub, A.lock!), new Map());
  const m2 = computeMembership(F.rec, [...e4.events, ...e8.events]);
  assert.equal(m2.seats.get('server:4')!.holder, null);
  assert.equal(m2.seats.get('server:8')!.holder, null);
});

test('case 12: two paper changes, the lowest hash wins and the loser is removed', () => {
  const F = fixture();
  const A = F.devices[0];
  const mk = () => {
    const K = newKey();
    const list: Change[] = [{ paper: { key: K.pub, replaces: F.backup.kp.pub } }, { redeal: { dealer: A.kp.pub } }];
    const ap = approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!);
    const dealt = dealRedeal(F.g, A.kp, [], new Map(), K.pub, [5, 6]);
    const full: Change[] = [{ paper: { key: K.pub, replaces: F.backup.kp.pub, inner: bytesToHex(randomBytes(32)), state: [] } }, { redeal: dealt.redeal }];
    return { K, evs: full.map((c) => F.change(c, list, ap)), hash: computeMembership(F.rec, []).g && list };
  };
  const p1 = mk(), p2 = mk();
  const m = computeMembership(F.rec, [...p1.evs, ...p2.evs]);
  assert.ok([p1.K.pub, p2.K.pub].includes(m.backupKey!));
  const loser = m.backupKey === p1.K.pub ? p2.K.pub : p1.K.pub;
  assert.ok(m.removed.has(loser) && m.removed.has(F.backup.kp.pub));
  assert.equal(computeMembership(F.rec, [...p2.evs, ...p1.evs]).backupKey, m.backupKey);
});

test('§4.6: a self remove needs both keys, distinct, and the app deals its redeal', () => {
  const F = fixture();
  const ext = F.devices[0], app = newKey();
  const addApp = addDevice(F, 'lock', app.pub);
  const list: Change[] = [{ remove: ext.kp.pub, to: app.pub }, { redeal: { dealer: app.pub } }];
  const m0 = computeMembership(F.rec, [addApp]);
  assert.equal(checkApproval(m0.authority, list, approveSelf(F.g, list, ext.kp, app)).error, null);
  assert.equal(checkApproval(m0.authority, list, approveSelf(F.g, list, ext.kp, newKey())).error, 'bad_signature');
  const wrongDealer: Change[] = [{ remove: ext.kp.pub, to: app.pub }, { redeal: { dealer: ext.kp.pub } }];
  assert.equal(checkApproval(m0.authority, wrongDealer, approveSelf(F.g, wrongDealer, ext.kp, app)).error, 'self_redeal_dealer');
  const selfToSelf: Change[] = [{ remove: ext.kp.pub, to: ext.kp.pub }, { redeal: { dealer: ext.kp.pub } }];
  assert.equal(checkApproval(m0.authority, selfToSelf, approveSelf(F.g, selfToSelf, ext.kp, ext.kp)).error, 'approver_not_device');
  // A lock approval is not allowed for a self remove.
  assert.equal(checkApproval(m0.authority, list, approveLock(F.g, F.epochId, list, EXP(), ext.kp.pub, ext.lock!)).error, 'approval_not_allowed');
});
