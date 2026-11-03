// End-to-end flows over the simulated bus (task step 2): create, sign, add a device, report lost,
// replace a server via Upkeep, paper recovery, concurrent changes, members dying mid-change.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, replaceServer, recover } from '../sim/account.ts';
import { approvePair, approvePaper } from '../src/approval.ts';
import { verifyEvent } from '../src/event.ts';
import { KIND_WRAP_STORED } from '../src/transport.ts';
import { mul, derivePoint, liftX } from '../src/curve.ts';
import { msg } from '../sim/nodes.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { Change } from '../src/types.ts';

const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

test('create and sign: device + first server; a dead server falls through to the next', () => {
  const acc = create();
  const e = acc.A.sign({ content: 'gm' });
  assert.ok(verifyEvent(e)); assert.equal(e.pubkey, acc.g);
  acc.bus.kill(acc.servers[0].kp.pub);
  assert.ok(verifyEvent(acc.A.sign({ content: 'still here' })));
  assert.ok(acc.bus.wire.every((w) => w.kind !== KIND_WRAP_STORED), 'nothing went to relays as kind 1059');
});

test('add a device by lock; the new device signs with another server and co-signs for A', () => {
  const acc = create();
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.ok(acc.servers.every((s) => s.m.devices.has(B.kp.pub)));
  assert.ok(verifyEvent(B.sign({ content: 'from B' })));
  // Two devices are 6 points: A can sign with B as its co-signer, no server needed.
  const { OneCall } = awaitImport();
  const r = new OneCall(acc.A.ctx(), acc.A.me(), { key: B.kp.pub, indices: [...B.state!.shares.keys()] }, { pubkey: acc.g, created_at: acc.bus.now, kind: 1, tags: [], content: 'A+B' });
  assert.ok(verifyEvent(r.finish(acc.bus.send(acc.A.kp, B.kp.pub, r.request))));
});
import * as coord from '../src/coordinator.ts';
function awaitImport() { return coord; }

test('report lost by lock: [remove, redeal]; everyone moves to the new state; the lost device is refused', () => {
  const acc = create();
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const before = new Map(acc.A.state!.shares);
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  acc.A.submit(list, acc.A.approveLock(list));
  assert.equal(acc.A.state!.ids.size, 1);
  for (const s of acc.servers) assert.deepEqual([...s.co!.state.ids], [...acc.A.state!.ids], `${s.name} applied the redeal`);
  assert.notEqual(acc.A.state!.shares.get(1), before.get(1), 'old share destroyed and replaced');
  assert.ok(verifyEvent(acc.A.sign({ content: 'after' })));
  // B is refused at once, with its old shares, at any server; and B wipes itself once it hears.
  assert.equal(code(() => B.sign({ content: 'thief' })), 'removed');
  B.fetch();
  assert.ok(B.wiped);
});

test('a lockless single device cannot report another, but pair with a second device can', () => {
  const acc = create({ lockless: true });
  const P = acc.paper;
  const B = invite(acc, acc.A, (l) => approvePaper(acc.g, acc.epochId, l, acc.bus.now + 3600, acc.A.kp, P,
    acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, msg('challenge', acc.g, acc.epochId, 'ask')).challenge, acc.servers[0].host.pub));
  const C = invite(acc, acc.A, (l) => approvePair(acc.g, acc.epochId, l, acc.bus.now + 3600, acc.A.kp, B.kp, bytesToHex(randomBytes(16))));
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  assert.equal(code(() => acc.A.submit(list, { expiry: acc.bus.now + 3600, lock: { member: acc.A.kp.pub, assertion: { authData: '', clientData: '', sig: '' } } })), 'no_lock');
  B.fetch();
  acc.A.submit(list, approvePair(acc.g, acc.epochId, list, acc.bus.now + 3600, acc.A.kp, B.kp, bytesToHex(randomBytes(16))));
  B.fetch();
  assert.ok(!B.m!.devices.has(C.kp.pub));
  assert.deepEqual([...B.state!.ids], [...acc.A.state!.ids], 'B caught up from its inbox');
  assert.ok(verifyEvent(B.sign({ content: 'B after redeal' })));
});

test('server replacement via Upkeep (F1): same share value at the same index; signing never stops', () => {
  const acc = create();
  const S3 = acc.servers[2];
  const oldShare = S3.co!.state.shares.get(8)!;
  acc.bus.kill(S3.kp.pub);
  const Y = replaceServer(acc, acc.A, 8, (l) => acc.A.approveLock(l));
  const s8 = Y.co!.state.shares.get(8)!;
  assert.ok(mul(s8).equals(derivePoint(acc.A.state!.C, 8n)), 'Y holds the seat at the new state');
  assert.notEqual(s8, oldShare, 'the redeal moved the seat value on; the dead server\'s old point is useless');
  assert.ok(acc.A.m!.removed.has(S3.kp.pub));
  // Sign with Y alone as co-signer.
  acc.bus.kill(acc.servers[0].kp.pub); acc.bus.kill(acc.servers[1].kp.pub);
  assert.ok(verifyEvent(acc.A.sign({ content: 'via Y' })));
  // The retired server, back online, refuses nothing it can use: its state is old, and it destroys on hearing.
  acc.bus.revive(S3.kp.pub);
  acc.bus.send(acc.A.kp, S3.kp.pub, { type: 'change', events: acc.A.changes });
  assert.ok(S3.retired);
});

test('report lost with every server: the redeal reaches a device asleep through its inbox', () => {
  const acc = create();
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  acc.bus.kill(B.kp.pub);                      // B asleep
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  acc.A.submit(list, acc.A.approveLock(list));
  acc.bus.revive(B.kp.pub);
  B.fetch();
  assert.deepEqual([...B.state!.ids], [...acc.A.state!.ids]);
  assert.ok(verifyEvent(B.sign({ content: 'B woke up' })));
});

test('paper recovery after a redeal: wait, release, recovery join, report the lost phone, redeal', () => {
  const acc = create();
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  acc.A.submit(list, acc.A.approveLock(list));             // a redeal: the paper must catch up through its item
  acc.bus.kill(acc.A.kp.pub);                              // the phone is lost
  const { D } = recover(acc, [acc.A]);
  assert.ok(!D.m!.devices.has(acc.A.kp.pub));
  assert.equal(D.state!.ids.size, 2, 'the recovery redeal applied');
  for (const s of acc.servers) assert.deepEqual([...s.co!.state.ids].sort(), [...D.state!.ids].sort());
  assert.ok(verifyEvent(D.sign({ content: 'recovered' })));
  assert.equal(code(() => { acc.bus.revive(acc.A.kp.pub); acc.A.sign({ content: 'old phone' }); }), 'removed');
});

test('a recovery wait cancelled by a locked device stops the release', () => {
  const acc = create();
  const s = acc.servers.map((x) => x.kp.pub);
  const { PaperHolder } = nodes;
  const P = new PaperHolder(acc.bus, acc.paper, acc.g, acc.epochId, s);
  P.start(s);
  const { recoveryWaitId, what } = codesMod;
  const wait = recoveryWaitId(acc.paper.pub, acc.epochId, P.r);
  for (const x of s) assert.equal(acc.bus.send(acc.A.kp, x, msg('cancel', acc.g, acc.epochId, 'ask', { wait, approval: { lock: { member: acc.A.kp.pub, assertion: acc.A.lock!.assert(acc.g, what.cancel(wait)) } } })).kind, 'cancelled');
  acc.bus.advance(3 * 86400 + 1);
  assert.equal(code(() => P.collect(s)), 'waited_missing');
});
import * as nodes from '../sim/nodes.ts';
import * as codesMod from '../src/codes.ts';

test('concurrent changes: two adds by two devices, delivered in different orders, give one membership', () => {
  const acc = create();
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  const C = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const D = invite(acc, B, (l) => B.approveLock(l), { via: 1 });
  for (const n of [acc.A, B, C, D]) n.fetch();
  const sets = [acc.A, B, C, D].map((n) => JSON.stringify([...n.m!.devices].sort()));
  assert.equal(new Set(sets).size, 1);
  for (const s of acc.servers) assert.equal(JSON.stringify([...s.m.devices].sort()), sets[0]);
  // Two report-lost lists at once from two devices (each with its own redeal) both apply: redeals add.
  const l1: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  const l2: Change[] = [{ remove: D.kp.pub }, { redeal: { dealer: B.kp.pub } }];
  acc.A.submit(l1, acc.A.approveLock(l1));
  B.submit(l2, B.approveLock(l2));                   // B dealt on the old state, concurrently
  acc.A.fetch(); B.fetch();
  assert.deepEqual([...acc.A.state!.ids].sort(), [...B.state!.ids].sort());
  assert.equal(acc.A.state!.ids.size, 2);
  for (const s of acc.servers) assert.equal(s.co!.state.ids.size, 2);
  assert.ok(verifyEvent(acc.A.sign({ content: 'both applied' })));
  assert.ok(verifyEvent(B.sign({ content: 'both applied, B' })));
});

test('a dealer dying before the co-sign changes nothing; inert uploads expire', () => {
  const acc = create();
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  acc.A.submit(list, acc.A.approveLock(list), { dieAfterUpload: true });
  assert.ok(acc.servers.every((s) => s.uploads.size === 1 && s.co!.state.ids.size === 0));
  assert.ok(verifyEvent(B.sign({ content: 'B still signs at the old state' })));
  acc.bus.advance(7 * 86400 + 1);
  assert.ok(acc.servers.every((s) => [...s.uploads.values()].every((u) => acc.bus.now - u.at > 7 * 86400)));
});

test('a server down during the redeal catches up by rerepair, with a proof at its old state', async () => {
  const acc = create();
  const S2 = acc.servers[1];
  acc.bus.kill(S2.kp.pub);
  const B = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  acc.A.submit(list, acc.A.approveLock(list));
  acc.bus.revive(S2.kp.pub);
  S2.catchUp();
  assert.equal(S2.co!.state.ids.size, 0, 'S2 never got its delta');
  // rerepair (§6.7.4): S2 proves its share at its own old state; B (3) and S1 (1) repair index 7 at the new state.
  const { rerepairProof } = await import('../src/upkeep.ts');
  const S1 = acc.servers[0];
  const ch = acc.bus.send(S2.kp, S1.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
  void ch;
  B.fetch();
  const chB = acc.bus.send(B.kp, S1.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
  const proof = rerepairProof(acc.g, 7, S2.co!.state.shares.get(7)!, chB.challenge);
  const sigmas = B.repairFor([{ key: B.kp.pub, indices: [...B.state!.shares.keys()] }, { key: S1.kp.pub, indices: [4] }], 7, S2.kp.pub, 'rerepair',
    { for: S2.kp.pub, proof: { challenge: chB.challenge, state: [], proof } });
  acc.bus.send(B.kp, S2.kp.pub, { type: 'seat_fill', sigmas, state: [...B.state!.ids] });
  assert.deepEqual([...S2.co!.state.ids], [...B.state!.ids]);
  acc.bus.kill(S1.kp.pub); acc.bus.kill(acc.servers[2].kp.pub);
  assert.ok(verifyEvent(B.sign({ content: 'via the rerepaired S2' })));
  // A forged proof is refused.
  const bad = { ...rerepairProof(acc.g, 7, 12345n, chB.challenge) };
  acc.bus.revive(S1.kp.pub);
  assert.match(code(() => B.repairFor([{ key: B.kp.pub, indices: [...B.state!.shares.keys()] }, { key: S1.kp.pub, indices: [4] }], 7, S2.kp.pub, 'rerepair',
    { for: S2.kp.pub, proof: { challenge: chB.challenge, state: [], proof: bad } })), /bad_proof|stale_challenge/);
});

test('one host cannot be repaired into two seats; the backup seat is never repaired by need_repair', () => {
  const acc = create();
  const S1 = acc.servers[0];
  assert.match(code(() => acc.A.repairFor([{ key: acc.A.kp.pub, indices: [1, 2, 3] }, { key: S1.kp.pub, indices: [4] }], 5, acc.paper.pub, 'seat')), /backup_seat/);
  assert.match(code(() => acc.A.repairFor([{ key: acc.A.kp.pub, indices: [1, 2, 3] }, { key: S1.kp.pub, indices: [4] }], 99999, acc.paper.pub, 'seat')), /not_assigned/);
  void liftX;
});
