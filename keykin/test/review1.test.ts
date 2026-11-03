// Regression tests for independent review 1 (shared notes: keykin-impl-review-1.md), one per finding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, type Fixture } from './helpers.ts';
import { create } from '../sim/account.ts';
import { CoSigner } from '../src/cosigner.ts';
import { OneCall, TwoCall, ListCall } from '../src/coordinator.ts';
import { computeMembership, parseChange } from '../src/membership.ts';
import { approveLock, approvePair, approvePaper, approveSelf, checkListShape } from '../src/approval.ts';
import { deal as dealRedeal } from '../src/redeal.ts';
import { softLock } from '../src/lock.ts';
import { newKey } from '../src/event.ts';
import { stateHash, signpostD, signpostH } from '../src/codes.ts';
const codesState = (ids: string[]) => stateHash(ids);
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { ReplayCache } from '../src/lifetimes.ts';
import type { Change } from '../src/types.ts';

const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };
let clock = Math.floor(Date.now() / 1000);
const now = () => clock;
const S0 = stateHash([]);
const server = (F: Fixture, k = 0, changes: any[] = [], extra: any = {}) => new CoSigner({ me: F.servers[k].kp, host: F.servers[k].host, kind: 'server', now, record: F.rec, changes,
  state: { ids: new Set(), C: F.commitment, shares: new Map([[F.servers[k].idx, F.servers[k].share]]) }, ...extra });
const ctx = (F: Fixture) => ({ g: F.g, epochId: F.epochId, state: S0, C: F.commitment });
const dev = (F: Fixture) => ({ indices: [1, 2, 3], shares: F.devices[0].shares });
const signChange = (S: CoSigner, F: Fixture, change: Change, list: Change[], approval: any, extra: any = {}) => {
  const ev = { pubkey: F.g, created_at: clock, kind: 24302, tags: [['v', '1'], ['epoch', F.epochId]], content: JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change, list, approval }) };
  const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, ev);
  return S.handle(F.devices[0].kp.pub, { ...r.request, ...extra }, clock);
};
const EXP = () => clock + 3600;
/** Co-sign a whole list in one request (§6.7.10). `changes` are the full changes, in list order. */
const signList = (S: CoSigner, F: Fixture, changes: Change[], list: Change[], approval: any, extra: any = {}) => {
  const evs = changes.map((change) => ({ pubkey: F.g, created_at: clock, kind: 24302, tags: [['v', '1'], ['epoch', F.epochId]], content: JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change, list, approval }) }));
  const r = new ListCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, evs, extra);
  return S.handle(F.devices[0].kp.pub, r.request, clock);
};

test('#1 critical: a repair is never sealed to anyone but the index\'s owner', async () => {
  const acc = await create({ lockless: true });
  const A = acc.A;
  // A lockless device asks S1 to help repair S2's index 7, sealed to itself.
  await assert.rejects(A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, A.kp.pub, 'add'), /not_assigned|bad_helpers/);
  await assert.rejects(A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, A.kp.pub, 'seat'), /not_assigned|bad_helpers/);
  // Even sealed to S2 itself, a join repair is only for an added device.
  await assert.rejects(A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, acc.servers[1].kp.pub, 'add'), /not_assigned/);
  // Review 2 N1: the helper list is checked, so A can't claim S1's index as its own.
  const st = [...A.state!.ids];
  const lie = (helpers: any) => acc.bus.send(A.kp, acc.servers[0].kp.pub, { type: 'repair_start', participant: 7, seal_to: acc.servers[1].kp.pub, why: 'seat', state: codesState(st), rid: '00'.repeat(16), helpers });
  assert.equal((await lie([{ key: A.kp.pub, indices: [1, 2, 3, 4] }, { key: acc.servers[0].kp.pub, indices: [4] }])).code, 'bad_helpers');
  assert.equal((await lie([{ key: A.kp.pub, indices: [1, 2, 3, 4] }])).code, 'bad_helpers', 'S1 must be in the list with its own index');
  await assert.rejects(A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [] }], 7, acc.servers[1].kp.pub, 'seat'), /bad_helpers/);
  // A seat repair is answered once per key and index, counted only once the owner confirms its share
  // (review 2 N5: a stranger's attempts can't use up the answer).
  await A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, acc.servers[1].kp.pub, 'seat');
  await A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, acc.servers[1].kp.pub, 'seat');
  await acc.bus.send(acc.servers[2].kp, acc.servers[0].kp.pub, { type: 'repair_ok', participant: 7 });   // not the owner: ignored
  await A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, acc.servers[1].kp.pub, 'seat');
  await acc.bus.send(acc.servers[1].kp, acc.servers[0].kp.pub, { type: 'repair_ok', participant: 7 });
  await assert.rejects(A.repairFor([{ key: A.kp.pub, indices: [1, 2, 3] }, { key: acc.servers[0].kp.pub, indices: [4] }], 7, acc.servers[1].kp.pub, 'seat'), /already_answered/);
});

test('#2 high: once a signpost is co-signed, its delete by e tag is refused', () => {
  const F = fixture(); const S = server(F);
  const servers = F.rec.members.filter((m) => m.kind === 'server').map((m) => ({ host: m.host, https: m.https, relays: m.relays ?? [] }));
  const post = { pubkey: F.g, created_at: clock, kind: 30078, tags: [['d', signpostD(F.backup.kp.pub)], ['n', '0'], ['h', signpostH(F.epochId, servers)]], content: 'sealed copies' };
  const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, post);
  const signed = r.finish(S.handle(F.devices[0].kp.pub, r.request, clock));
  const del = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, { pubkey: F.g, created_at: clock, kind: 5, tags: [['e', signed.id]], content: '' });
  assert.equal(S.handle(F.devices[0].kp.pub, del.request, clock).code, 'machinery');
  const S2 = server(F); S2.restore(S.snapshot());
  const del2 = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, { pubkey: F.g, created_at: clock, kind: 5, tags: [['e', signed.id]], content: '' });
  assert.equal(S2.handle(F.devices[0].kp.pub, del2.request, clock).code, 'machinery', 'survives a restart');
  // A server that didn't co-sign it learns the id by delivery (core 14.2), and refuses too.
  const S3 = server(F, 1);
  assert.equal(S3.takeSignpost({ ...signed, id: '00'.repeat(32) }), false, 'review 2 N6: only a real signpost is taken');
  assert.equal(S3.takeSignpost(signed), true);
  const del3 = new OneCall(ctx(F), dev(F), { key: F.servers[1].kp.pub, indices: [7] }, { pubkey: F.g, created_at: clock, kind: 5, tags: [['e', signed.id]], content: '' });
  assert.equal(S3.handle(F.devices[0].kp.pub, del3.request, clock).code, 'machinery');
});

function seatEvs(F: Fixture, idx: number, replaces: string | null, entry: any) {
  const A = F.devices[0];
  const list: Change[] = [{ seat: { seat: `server:${idx}`, new: entry, replaces } }, { redeal: { dealer: A.kp.pub } }];
  const ap = approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!);
  const d = dealRedeal(F.g, A.kp, [], new Map(), F.backup.kp.pub, [5, 6]);
  return [F.change(list[0], list, ap), F.change({ redeal: d.redeal }, list, ap)];
}

test('#3 high: a host that left one seat may hold another later; only simultaneous holding voids', () => {
  const F = fixture();
  const h1 = newKey().pub;
  const y1 = { key: newKey().pub, kind: 'server', shares: [4], host: h1 }, y2 = { key: newKey().pub, kind: 'server', shares: [4], host: newKey().pub };
  const z = { key: newKey().pub, kind: 'server', shares: [7], host: h1 };
  const evs = [...seatEvs(F, 4, F.servers[0].kp.pub, y1), ...seatEvs(F, 4, y1.key, y2), ...seatEvs(F, 7, F.servers[1].kp.pub, z)];
  const m = computeMembership(F.rec, evs);
  assert.equal(m.seats.get('server:4')!.holder!.key, y2.key);
  assert.equal(m.seats.get('server:7')!.holder!.key, z.key);
  assert.ok(!m.removed.has(z.key));
  // Both at once: void, then a void: reseat refills.
  const w = { key: newKey().pub, kind: 'server', shares: [7], host: h1 };
  const both = computeMembership(F.rec, [...seatEvs(F, 4, F.servers[0].kp.pub, y1), ...seatEvs(F, 7, F.servers[1].kp.pub, w)]);
  assert.equal(both.seats.get('server:4')!.holder, null);
  assert.equal(both.seats.get('server:7')!.holder, null);
  const v = both.seats.get('server:7')!.voided[0];
  const fresh = { key: newKey().pub, kind: 'server', shares: [7], host: newKey().pub };
  assert.equal(computeMembership(F.rec, [...seatEvs(F, 4, F.servers[0].kp.pub, y1), ...seatEvs(F, 7, F.servers[1].kp.pub, w), ...seatEvs(F, 7, `void:${v}`, fresh)]).seats.get('server:7')!.holder!.key, fresh.key);
});

test('#4/#5 medium: the co-signer tries the change; paper keys, stale lock changes and missing material are refused', () => {
  const F = fixture(); const A = F.devices[0];
  const S = server(F, 0, [], { uploads: { get: () => undefined, liveSeatHolders: () => 3 } });
  // A paper key that is a device key.
  const pl: Change[] = [{ paper: { key: A.kp.pub, replaces: F.backup.kp.pub } }, { redeal: { dealer: A.kp.pub } }];
  const pc: Change = { paper: { key: A.kp.pub, replaces: F.backup.kp.pub, inner: '00'.repeat(32), state: [] } };
  const d = dealRedeal(F.g, A.kp, [], new Map(), A.kp.pub, [5, 6]);
  const ap = approveLock(F.g, F.epochId, pl, EXP(), A.kp.pub, A.lock!);
  assert.match(String(signList(S, F, [pc, { redeal: d.redeal }], pl, ap).code), /invariant|bad_material/);
  // A fresh paper key, but no material with the request.
  const K = newKey();
  const pl2: Change[] = [{ paper: { key: K.pub, replaces: F.backup.kp.pub } }, { redeal: { dealer: A.kp.pub } }];
  const ap2 = approveLock(F.g, F.epochId, pl2, EXP(), A.kp.pub, A.lock!);
  const d2 = dealRedeal(F.g, A.kp, [], new Map(), K.pub, [5, 6]);
  assert.equal(signList(S, F, [{ paper: { key: K.pub, replaces: F.backup.kp.pub, inner: '11'.repeat(32), state: [] } }, { redeal: d2.redeal }], pl2, ap2).code, 'bad_material');
  // A lock change naming the wrong old lock.
  const b = newKey();
  const addB: Change[] = [{ add: { key: b.pub, kind: 'device', lock: null, salt: 0 } }];
  const S2 = server(F, 0, [F.change(addB[0], addB, approveLock(F.g, F.epochId, addB, EXP(), A.kp.pub, A.lock!))]);
  const lc: Change[] = [{ lock: { member: A.kp.pub, replaces: softLock().pub.pub, new: softLock().pub } }];
  assert.equal(signChange(S2, F, lc[0], lc, approvePair(F.g, F.epochId, lc, EXP(), A.kp, b, 'aa'.repeat(16))).code, 'lock_conflict');
  // A server without an upload store never co-signs a redeal.
  const S3 = server(F);
  const rl: Change[] = [{ redeal: { dealer: A.kp.pub } }];
  const d3 = dealRedeal(F.g, A.kp, [], new Map(), F.backup.kp.pub, [5, 6]);
  assert.equal(signChange(S3, F, { redeal: d3.redeal }, rl, approveLock(F.g, F.epochId, rl, EXP(), A.kp.pub, A.lock!)).code, 'no_upload_store');
  assert.equal(signChange(S, F, { redeal: d3.redeal }, rl, approveLock(F.g, F.epochId, rl, EXP(), A.kp.pub, A.lock!)).code, 'missing');
});

test('#4: a member refuses to adopt a view that breaks an invariant', () => {
  const F = fixture(); const A = F.devices[0];
  // Two helper seatings would be fine one at a time; the record's helper plus ... use I5: a helper plus
  // an unknown kind can't be made by changes, so break I2 instead: a server entry for a seat index taken by a device is refused by parseChange; use a paper key equal to a device key.
  const S = server(F);
  const pl: Change[] = [{ paper: { key: A.kp.pub, replaces: F.backup.kp.pub } }, { redeal: { dealer: A.kp.pub } }];
  const ap = approveLock(F.g, F.epochId, pl, EXP(), A.kp.pub, A.lock!);
  const ev = F.change({ paper: { key: A.kp.pub, replaces: F.backup.kp.pub, inner: '00'.repeat(32), state: [] } }, pl, ap);
  const rd = F.change({ redeal: dealRedeal(F.g, A.kp, [], new Map(), A.kp.pub, [5, 6]).redeal }, pl, ap);
  assert.equal(S.addChanges([ev]), true, 'without its redeal the paper change waits, inert');
  assert.equal(S.addChanges([rd]), false, 'with it, the view would break: refused');
  assert.ok(S.m.backupKey === F.backup.kp.pub && S.m.devices.has(A.kp.pub));
});

test('#7: the co-signer takes a lock approval only under the current lock', () => {
  const F = fixture(); const A = F.devices[0];
  const b = newKey();
  const addB: Change[] = [{ add: { key: b.pub, kind: 'device', lock: null, salt: 0 } }];
  const newLock = softLock();
  const lc: Change[] = [{ lock: { member: A.kp.pub, replaces: A.lock!.pub.pub, new: newLock.pub } }];
  const S = server(F, 0, [F.change(addB[0], addB, approveLock(F.g, F.epochId, addB, EXP(), A.kp.pub, A.lock!)),
    F.change(lc[0], lc, approvePair(F.g, F.epochId, lc, EXP(), A.kp, b, 'aa'.repeat(16)))]);
  const add2: Change[] = [{ add: { key: newKey().pub, kind: 'device', lock: null, salt: 0 } }];
  assert.equal(signChange(S, F, add2[0], add2, approveLock(F.g, F.epochId, add2, EXP(), A.kp.pub, A.lock!)).code, 'not_current_lock');
  assert.equal(signChange(S, F, add2[0], add2, approveLock(F.g, F.epochId, add2, EXP(), A.kp.pub, newLock)).type, 'partial');
});

test('#8: the same key and salt with different locks is void, whatever the order', () => {
  const F = fixture(); const A = F.devices[0];
  const k = newKey().pub;
  const mk = (lock: any) => { const l: Change[] = [{ add: { key: k, kind: 'device', lock, salt: 0 } }]; return F.change(l[0], l, approveLock(F.g, F.epochId, l, EXP(), A.kp.pub, A.lock!)); };
  const e1 = mk(softLock().pub), e2 = mk(softLock().pub);
  assert.ok(!computeMembership(F.rec, [e1, e2]).devices.has(k));
  assert.ok(!computeMembership(F.rec, [e2, e1]).devices.has(k));
});

test('#9: a self approval covers exactly [remove, redeal]', () => {
  const F = fixture();
  const app = newKey();
  assert.equal(code(() => checkListShape([{ remove: F.devices[0].kp.pub, to: app.pub }, { seat: { seat: 'server:4', new: null, replaces: null } }, { redeal: { dealer: app.pub } }])), 'bad_list');
  void approveSelf;
});

test('#10: a request dated 30 s ahead is remembered until it can no longer be fresh', () => {
  const R = new ReplayCache();
  R.claim('a', 'x', 'h', 'sign', 1000, 1030);
  assert.ok('reused' in R.check('a', 'x', 'h2', 1000 + 60 + 30 + 20));
});

test('#11: request types named after prototype keys are unsupported, not a crash', () => {
  const F = fixture(); const S = server(F);
  for (const type of ['constructor', '__proto__', 'toString', 'hasOwnProperty'])
    assert.equal(S.handle(F.devices[0].kp.pub, { v: 1, type, g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'ask' }, clock).code, 'unsupported');
});

test('#12: a paper approval\'s challenge is used once and only by whom it was issued to', () => {
  const F = fixture(); const A = F.devices[0];
  const S = server(F);
  const ch = S.handle(F.backup.kp.pub, { v: 1, type: 'challenge', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'ask' }, clock).challenge;
  const mk = () => { const k = newKey().pub; const l: Change[] = [{ add: { key: k, kind: 'device', lock: null, salt: 0 } }];
    return [l, approvePaper(F.g, F.epochId, l, EXP(), A.kp, F.backup.kp, ch, F.servers[0].host.pub)] as const; };
  const [l1, a1] = mk();
  assert.equal(signChange(S, F, l1[0], l1, a1).type, 'partial');
  const [l2, a2] = mk();
  assert.equal(signChange(S, F, l2[0], l2, a2).code, 'stale_challenge');
});

test('#14 / 14.3: a list is co-signed whole, in one request, and takes effect only whole', () => {
  const F = fixture(); const A = F.devices[0];
  const S = server(F, 0, [], { uploads: { get: () => undefined, liveSeatHolders: () => 3 } });
  const list: Change[] = [{ seat: { seat: 'server:8', new: { key: newKey().pub, kind: 'server', shares: [8], host: newKey().pub }, replaces: F.servers[2].kp.pub } }, { redeal: { dealer: A.kp.pub } }];
  const ap = approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!);
  assert.equal(signChange(S, F, list[0], list, ap).code, 'list_in_one_request');
  assert.equal(signList(S, F, [list[0]], list, ap).code, 'list_incomplete', 'the redeal is missing from the request');
  // A member holding only part of a list applies none of it.
  const d = dealRedeal(F.g, A.kp, [], new Map(), F.backup.kp.pub, [5, 6]);
  const seatEv = F.change(list[0], list, ap), rdEv = F.change({ redeal: d.redeal }, list, ap);
  const part = computeMembership(F.rec, [seatEv]);
  assert.equal(part.seats.get('server:8')!.holder!.key, F.servers[2].kp.pub);
  assert.equal(computeMembership(F.rec, [rdEv]).redeals.size, 0, 'nor the redeal alone');
  assert.notEqual(computeMembership(F.rec, [seatEv, rdEv]).seats.get('server:8')!.holder!.key, F.servers[2].kp.pub);
  void parseChange;
});

test('#15: a two-call co-signer that leaves out an index is named', () => {
  const F = fixture(); const S1 = server(F, 0), S2 = server(F, 1);
  const A = F.devices[0];
  const cos = [{ key: F.servers[0].kp.pub, indices: [4] }, { key: F.servers[1].kp.pub, indices: [7] }];
  const t = new TwoCall(ctx(F), { key: A.kp.pub, indices: [1, 2, 3], shares: A.shares }, cos, { pubkey: F.g, created_at: clock, kind: 1, tags: [], content: 'x' });
  t.took(cos[0].key, S1.handle(A.kp.pub, t.commitRequest(), clock)); t.took(cos[1].key, S2.handle(A.kp.pub, t.commitRequest(), clock));
  const req = t.signRequest();
  const p1 = S1.handle(A.kp.pub, req, clock), p2 = S2.handle(A.kp.pub, req, clock);
  assert.throws(() => t.finish(new Map([[cos[0].key, p1], [cos[1].key, { ...p2, z: [] }]])), new RegExp(`bad_partial: member ${cos[1].key}`));
});

// --- review 2 -------------------------------------------------------------------------------

test('review 2 N2: a paper-approved list commits (one challenge serves every change of the list)', async () => {
  const acc = await create({ lockless: true });
  const P = acc.paper;
  const ch = async () => (await acc.bus.send(acc.paper, acc.servers[0].kp.pub, { v: 1, type: 'challenge', g: acc.g, epoch: acc.epochId, id: bytesToHex(randomBytes(16)), cls: 'ask' })).challenge;
  const c1 = await ch();
  const { invite } = await import('../sim/account.ts');
  const B = await invite(acc, acc.A, (l) => approvePaper(acc.g, acc.epochId, l, acc.bus.now + 3600, acc.A.kp, P, c1, acc.servers[0].host.pub));
  const c2 = await ch();
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, approvePaper(acc.g, acc.epochId, list, acc.bus.now + 3600, acc.A.kp, P, c2, acc.servers[0].host.pub));
  assert.ok(acc.A.m!.removed.has(B.kp.pub));
  // The same challenge for another list is refused.
  const l2: Change[] = [{ add: { key: newKey().pub, kind: 'device', lock: null, salt: 0 } }];
  await assert.rejects(acc.A.submit(l2, approvePaper(acc.g, acc.epochId, l2, acc.bus.now + 3600, acc.A.kp, P, c2, acc.servers[0].host.pub)), /stale_challenge|wrong_challenge_server/);
});

test('review 2 N3: an F7 repair needs the current lock', () => {
  const F = fixture(); const A = F.devices[0];
  const b = newKey();
  const addB: Change[] = [{ add: { key: b.pub, kind: 'device', lock: null, salt: 0 } }];
  const nl = softLock();
  const lc: Change[] = [{ lock: { member: A.kp.pub, replaces: A.lock!.pub.pub, new: nl.pub } }];
  const S = server(F, 0, [F.change(addB[0], addB, approveLock(F.g, F.epochId, addB, EXP(), A.kp.pub, A.lock!)),
    F.change(lc[0], lc, approvePair(F.g, F.epochId, lc, EXP(), A.kp, b, 'aa'.repeat(16)))]);
  const K = newKey();
  const list: Change[] = [{ paper: { key: K.pub, replaces: F.backup.kp.pub } }, { redeal: { dealer: A.kp.pub } }];
  const body = (approval: any) => ({ participant: 5, seal_to: K.pub, why: 'paper', state: S0, list, approval,
    helpers: [{ key: A.kp.pub, indices: [1, 2, 3] }, { key: F.servers[0].kp.pub, indices: [4] }] });
  assert.equal(code(() => S.authorizeRepair(A.kp.pub, body(approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!)))), 'not_current_lock');
  assert.equal(code(() => S.authorizeRepair(A.kp.pub, body(approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, nl)))), 'ok');
});

test('review 2 N4: after a host conflict, a void: reseat refills the seat and it moves on as usual', () => {
  const F = fixture();
  const s1host = F.rec.members.find((m) => m.kind === 'server' && m.shares[0] === 4)!.host!;
  const clash = { key: newKey().pub, kind: 'server', shares: [7], host: s1host };
  const e1 = seatEvs(F, 7, F.servers[1].kp.pub, clash);
  const m1 = computeMembership(F.rec, e1);
  assert.equal(m1.seats.get('server:4')!.holder, null);
  assert.equal(m1.seats.get('server:7')!.holder, null);
  const v4 = m1.seats.get('server:4')!.voided[0];
  assert.ok(v4, 'the record holder\'s seat gets a void id to reseat with');
  const y = { key: newKey().pub, kind: 'server', shares: [4], host: newKey().pub };
  const z = { key: newKey().pub, kind: 'server', shares: [4], host: newKey().pub };
  const m2 = computeMembership(F.rec, [...e1, ...seatEvs(F, 4, `void:${v4}`, y), ...seatEvs(F, 4, y.key, z)]);
  assert.equal(m2.seats.get('server:4')!.holder!.key, z.key);
});

test('review 2 N9: one list can\'t seat one host twice', () => {
  const F = fixture(); const A = F.devices[0];
  const S = server(F, 0, [], { uploads: { get: () => undefined, liveSeatHolders: () => 3 } });
  const h = newKey().pub;
  const list: Change[] = [{ seat: { seat: 'server:7', new: { key: newKey().pub, kind: 'server', shares: [7], host: h }, replaces: F.servers[1].kp.pub } },
    { seat: { seat: 'server:8', new: { key: newKey().pub, kind: 'server', shares: [8], host: h }, replaces: F.servers[2].kp.pub } }, { redeal: { dealer: A.kp.pub } }];
  const ap = approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!);
  const rd = dealRedeal(F.g, A.kp, [], new Map(), F.backup.kp.pub, [5, 6]).redeal;
  assert.equal(signList(S, F, [list[0], list[1], { redeal: rd }], list, ap).code, 'invariant');
});

test('review 3 #1 critical: repair_finish seals only to the seal_to its start authorised', async () => {
  const acc = await create({ lockless: true });
  const A = acc.A, S1 = acc.servers[0], S2 = acc.servers[1];
  const { tag } = await import('../src/event.ts');
  const st = stateHash([...A.state!.ids]);
  const helpers = [{ key: A.kp.pub, indices: [1, 2, 3] }, { key: S1.kp.pub, indices: [4] }];
  const start = await acc.bus.send(A.kp, S1.kp.pub, { type: 'repair_start', participant: 7, seal_to: S2.kp.pub, why: 'seat', state: st, rid: 'ab'.repeat(16), helpers });
  assert.equal(start.type, 'repair_delta');
  const fin = await acc.bus.send(A.kp, S1.kp.pub, { type: 'repair_finish', participant: 7, rid: 'ab'.repeat(16), seal_to: A.kp.pub, deltas: [] });
  assert.equal(tag(fin.wrap, 'p'), S2.kp.pub, 'sealed to the authorised owner, whatever the finish says');
  // A finish for a start someone else made is unknown.
  const other = await acc.bus.send(acc.servers[2].kp, S1.kp.pub, { type: 'repair_finish', participant: 7, rid: 'ab'.repeat(16), deltas: [] });
  assert.equal(other.code, 'unknown_repair');
});

test('core 14.7 §5.2: in a list, each event gets its own nonce pair, at the coordinator and the co-signer', () => {
  const F = fixture(); const A = F.devices[0];
  const S = server(F, 0, [], { uploads: { get: () => ({ items: [], held: new Set(['a', 'b']), list: [], approval: {}, redealId: '', at: clock }) as any, liveSeatHolders: () => 3 } });
  const b = newKey();
  const list: Change[] = [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }];
  const addB: Change[] = [{ add: { key: b.pub, kind: 'device', lock: null, salt: 0 } }];
  const S2 = server(F, 0, [F.change(addB[0], addB, approveLock(F.g, F.epochId, addB, EXP(), A.kp.pub, A.lock!))]);
  const evs = [list[0], { redeal: dealRedeal(F.g, A.kp, [], new Map(), F.backup.kp.pub, [5, 6]).redeal }].map((change) => ({ pubkey: F.g, created_at: clock, kind: 24302, tags: [['v', '1'], ['epoch', F.epochId]],
    content: JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change, list, approval: approveLock(F.g, F.epochId, list, EXP(), A.kp.pub, A.lock!) }) }));
  const r = new ListCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, evs);
  const mineD = r.request.list_events.map((x: any) => x.commitments.map((c: any) => c.D).join());
  assert.notEqual(mineD[0], mineD[1], 'the coordinator commits afresh per event');
  void S; void S2;
  // The co-signer side: two-call `commit {count}` returns one distinct set per event.
  const t = new TwoCall(ctx(F), { key: A.kp.pub, indices: [1, 2, 3], shares: A.shares }, [{ key: F.servers[0].kp.pub, indices: [4] }, { key: F.servers[1].kp.pub, indices: [7] }], evs);
  const c = server(F, 0).handle(A.kp.pub, t.commitRequest(), clock);
  assert.equal(c.sets.length, 2);
  assert.notEqual(c.sets[0][0].D, c.sets[1][0].D);
});
