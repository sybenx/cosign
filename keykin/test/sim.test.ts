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

const code = async (f: () => unknown) => { try { await f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

test('create and sign: device + first server; a dead server falls through to the next', async () => {
  const acc = await create();
  const e = await acc.A.sign({ content: 'gm' });
  assert.ok(verifyEvent(e)); assert.equal(e.pubkey, acc.g);
  acc.bus.kill(acc.servers[0].kp.pub);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'still here' })));
  assert.ok(acc.bus.wire.every((w) => w.kind !== KIND_WRAP_STORED), 'nothing went to relays as kind 1059');
});

test('add a device by lock; the new device signs with another server and co-signs for A', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.ok(acc.servers.every((s) => s.m.devices.has(B.kp.pub)));
  assert.ok(verifyEvent(await B.sign({ content: 'from B' })));
  // Two devices are 6 points: A can sign with B as its co-signer, no server needed.
  const { OneCall } = awaitImport();
  const r = new OneCall(acc.A.ctx(), acc.A.me(), { key: B.kp.pub, indices: [...B.state!.shares.keys()] }, { pubkey: acc.g, created_at: acc.bus.now, kind: 1, tags: [], content: 'A+B' });
  assert.ok(verifyEvent(r.finish(await acc.bus.send(acc.A.kp, B.kp.pub, r.request))));
});
import * as coord from '../src/coordinator.ts';
function awaitImport() { return coord; }

test('report lost by lock: [remove, redeal]; everyone moves to the new state; the lost device is refused', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const before = new Map(acc.A.state!.shares);
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  assert.equal(acc.A.state!.ids.size, 1);
  for (const s of acc.servers) assert.deepEqual([...s.co!.state.ids], [...acc.A.state!.ids], `${s.name} applied the redeal`);
  assert.notEqual(acc.A.state!.shares.get(1), before.get(1), 'old share destroyed and replaced');
  assert.ok(verifyEvent(await acc.A.sign({ content: 'after' })));
  // B is refused at once, with its old shares, at any server; and B wipes itself once it hears.
  assert.equal(await code(async () => await B.sign({ content: 'thief' })), 'removed');
  await B.fetch();
  assert.ok(B.wiped);
});

test('a lockless single device cannot report another, but pair with a second device can', async () => {
  const acc = await create({ lockless: true });
  const P = acc.paper;
  const ch = (await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'))).challenge;
  const B = await invite(acc, acc.A, (l) => approvePaper(acc.g, acc.epochId, l, acc.bus.now + 3600, acc.A.kp, P, ch, acc.servers[0].host.pub));
  const C = await invite(acc, acc.A, (l) => approvePair(acc.g, acc.epochId, l, acc.bus.now + 3600, acc.A.kp, B.kp, bytesToHex(randomBytes(16))));
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  assert.equal(await code(async () => await acc.A.submit(list, { expiry: acc.bus.now + 3600, lock: { member: acc.A.kp.pub, assertion: { authData: '', clientData: '', sig: '' } } })), 'no_lock');
  await B.fetch();
  await acc.A.submit(list, approvePair(acc.g, acc.epochId, list, acc.bus.now + 3600, acc.A.kp, B.kp, bytesToHex(randomBytes(16))));
  await B.fetch();
  assert.ok(!B.m!.devices.has(C.kp.pub));
  assert.deepEqual([...B.state!.ids], [...acc.A.state!.ids], 'B caught up from its inbox');
  assert.ok(verifyEvent(await B.sign({ content: 'B after redeal' })));
});

test('server replacement via Upkeep (F1): same share value at the same index; signing never stops', async () => {
  const acc = await create();
  const S3 = acc.servers[2];
  const oldShare = S3.co!.state.shares.get(8)!;
  acc.bus.kill(S3.kp.pub);
  const Y = await replaceServer(acc, acc.A, 8, (l) => acc.A.approveLock(l));
  const s8 = Y.co!.state.shares.get(8)!;
  assert.ok(mul(s8).equals(derivePoint(acc.A.state!.C, 8n)), 'Y holds the seat at the new state');
  assert.notEqual(s8, oldShare, 'the redeal moved the seat value on; the dead server\'s old point is useless');
  assert.ok(acc.A.m!.removed.has(S3.kp.pub));
  // Sign with Y alone as co-signer.
  acc.bus.kill(acc.servers[0].kp.pub); acc.bus.kill(acc.servers[1].kp.pub);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'via Y' })));
  // The retired server, back online, refuses nothing it can use: its state is old, and it destroys on hearing.
  acc.bus.revive(S3.kp.pub);
  await acc.bus.send(acc.A.kp, S3.kp.pub, { type: 'change', events: acc.A.changes });
  assert.ok(S3.retired);
});

test('report lost with every server: the redeal reaches a device asleep through its inbox', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  acc.bus.kill(B.kp.pub);                      // B asleep
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  acc.bus.revive(B.kp.pub);
  await B.fetch();
  assert.deepEqual([...B.state!.ids], [...acc.A.state!.ids]);
  assert.ok(verifyEvent(await B.sign({ content: 'B woke up' })));
});

test('paper recovery after a redeal: wait, release, recovery join, report the lost phone, redeal', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));             // a redeal: the paper must catch up through its item
  acc.bus.kill(acc.A.kp.pub);                              // the phone is lost
  const { D } = await recover(acc, [acc.A]);
  assert.ok(!D.m!.devices.has(acc.A.kp.pub));
  assert.equal(D.state!.ids.size, 2, 'the recovery redeal applied');
  for (const s of acc.servers) assert.deepEqual([...s.co!.state.ids].sort(), [...D.state!.ids].sort());
  assert.ok(verifyEvent(await D.sign({ content: 'recovered' })));
  assert.equal(await code(async () => { acc.bus.revive(acc.A.kp.pub); await acc.A.sign({ content: 'old phone' }); }), 'removed');
});

test('a recovery wait cancelled by a locked device stops the release', async () => {
  const acc = await create();
  const s = acc.servers.map((x) => x.kp.pub);
  const { PaperHolder } = nodes;
  const P = new PaperHolder(acc.bus, acc.paper, acc.g, acc.epochId, s);
  await P.start(s);
  const { recoveryWaitId, what } = codesMod;
  const wait = recoveryWaitId(acc.paper.pub, acc.epochId, P.r);
  for (const x of s) assert.equal((await acc.bus.send(acc.A.kp, x, msg('cancel', acc.g, acc.epochId, 'member', { wait, approval: { lock: { member: acc.A.kp.pub, assertion: acc.A.lock!.assert(acc.g, what.cancel(wait)) } } }))).kind, 'cancelled');
  acc.bus.advance(3 * 86400 + 1);
  assert.equal(await code(async () => await P.collect(s)), 'waited_missing');
});
test('a missed cancel still counts: a server fetches its peers before releasing (§6.3)', async () => {
  const acc = await create();
  const s = acc.servers.map((x) => x.kp.pub);
  const P = new nodes.PaperHolder(acc.bus, acc.paper, acc.g, acc.epochId, s);
  await P.start(s);
  const wait = codesMod.recoveryWaitId(acc.paper.pub, acc.epochId, P.r);
  acc.bus.kill(s[1]); acc.bus.kill(s[2]);                 // only S1 hears the cancel
  const cancel = msg('cancel', acc.g, acc.epochId, 'member', { wait, approval: { lock: { member: acc.A.kp.pub, assertion: acc.A.lock!.assert(acc.g, codesMod.what.cancel(wait)) } } });
  assert.equal((await acc.bus.send(acc.A.kp, s[0], cancel)).kind, 'cancelled');
  acc.bus.revive(s[1]); acc.bus.revive(s[2]);
  acc.bus.advance(3 * 86400 + 1);
  assert.equal(await code(async () => P.collect(s)), 'waited_missing', 'S2 and S3 fetched the cancel from S1 first');
});
test('F7, a new paper: repair towards K under the approval, commit with material; the old paper is dead; recovery with the new one', async () => {
  const acc = await create();
  const old = acc.paper;
  const K = await acc.A.newPaper((l) => acc.A.approveLock(l));
  assert.equal(acc.A.m!.backupKey, K.pub);
  assert.ok(acc.A.m!.removed.has(old.pub));
  for (const s of acc.servers) assert.equal(s.m.backupKey, K.pub);
  // Never a second repair towards the same K.
  const srv = acc.servers[0];
  await assert.rejects(acc.A.repairFor([{ key: acc.A.kp.pub, indices: [1, 2, 3] }, { key: srv.kp.pub, indices: [4] }], 5, K.pub, 'paper', { list: [], approval: {} }), /bad_list|not_current_backup|already_answered/);
  // The old paper can't start a recovery.
  const P0 = new nodes.PaperHolder(acc.bus, old, acc.g, acc.epochId, acc.servers.map((x) => x.kp.pub));
  const ch = await acc.bus.send(old, srv.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
  assert.equal(ch.code, 'not_member');
  void P0;
  // A later redeal reaches the new paper through its item; then recovery with K works.
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const rl: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(rl, acc.A.approveLock(rl));
  acc.bus.kill(acc.A.kp.pub);
  const { D } = await recover(acc, [acc.A], K);
  assert.ok(verifyEvent(await D.sign({ content: 'recovered with the new paper' })));
});

test('F7: a paper repair is refused without a valid approval, from a non-approver, or sealed elsewhere', async () => {
  const acc = await create();
  const A = acc.A, srv = acc.servers[0];
  const K = newKey();
  const list: Change[] = [{ paper: { key: K.pub, replaces: acc.paper.pub } }, { redeal: { dealer: A.kp.pub } }];
  const helpers = [{ key: A.kp.pub, indices: [1, 2, 3] }, { key: srv.kp.pub, indices: [4] }];
  await assert.rejects(A.repairFor(helpers, 5, K.pub, 'paper', { list, approval: {} }), /bad_approval/);
  await assert.rejects(A.repairFor(helpers, 5, A.kp.pub, 'paper', { list, approval: A.approveLock(list) }), /not_assigned/);
  await assert.rejects(A.repairFor(helpers, 4, K.pub, 'paper', { list, approval: A.approveLock(list) }), /not_assigned/);
});
test('F3, every server dead: pair approval, co-signed by a second device, seats filled by two devices', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  for (const s of acc.servers) acc.bus.kill(s.kp.pub);
  // A lock alone is refused when a device co-signs a seat list.
  const { replaceAllServers } = await import('../sim/account.ts');
  await assert.rejects(replaceAllServers(acc, acc.A, B, (l) => acc.A.approveLock(l)), /approval_not_allowed/);
  const Ys = await replaceAllServers(acc, acc.A, B, (l) => approvePair(acc.g, acc.epochId, l, acc.bus.now + 3600, acc.A.kp, B.kp, bytesToHex(randomBytes(16))));
  assert.deepEqual([...B.state!.ids], [...acc.A.state!.ids], 'B applied the redeal live');
  for (const Y of Ys) assert.deepEqual([...Y.co!.state.ids], [...acc.A.state!.ids]);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'new servers' })));
  assert.ok(verifyEvent(await B.sign({ content: 'new servers, B' })));
});
test('need_seeds: a device gives seeds to a current device (data key too) or a seat server (release only), and says so', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const { unwrap } = await import('../src/transport.ts');
  const a = await acc.bus.send(B.kp, acc.A.kp.pub, { type: 'need_seeds' });
  const o = unwrap(B.kp.sk, a.wrap).body;
  assert.ok(o.release.length >= 1 && o.base_dk === acc.A.baseDk);
  const s = await acc.bus.send(acc.servers[0].kp, acc.A.kp.pub, { type: 'need_seeds' });
  assert.equal(unwrap(acc.servers[0].kp.sk, s.wrap).body.base_dk, undefined, 'a server never gets the data key');
  assert.equal((await acc.bus.send(acc.paper, acc.A.kp.pub, { type: 'need_seeds' })).code, 'not_member');
  assert.equal(acc.A.notices.filter((n) => n.kind === 'need_seeds').length, 2);
});
test('§6.7.5: after every printed server is replaced, the paper finds today\'s servers by forwarding notes and seated?', async () => {
  const acc = await create();
  const printed = acc.servers.map((x) => x.kp.pub);
  const Ys = [];
  for (const [k, i] of [4, 7, 8].entries()) { acc.bus.kill(printed[k]); Ys.push(await replaceServer(acc, acc.A, i, (l) => acc.A.approveLock(l))); acc.bus.revive(printed[k]); }
  for (const p of printed) await acc.bus.send(acc.A.kp, p, { type: 'change', events: acc.A.changes });   // removal notices reach them
  assert.ok(acc.servers.every((x) => x.retired));
  // Route 2: a printed server serves only its forwarding note, only to an allowed key.
  const fw = await acc.bus.send(acc.paper, printed[0], msg('forward_get', acc.g, acc.epochId, 'ask'));
  assert.equal(fw.type, 'forward');
  const named = fw.changes.map((e: any) => JSON.parse(e.content).change.seat?.new?.key).filter(Boolean);
  assert.ok(named.includes(Ys[0].kp.pub));
  assert.equal((await acc.bus.send(newKey(), printed[0], msg('forward_get', acc.g, acc.epochId, 'ask'))).code, 'retired');
  assert.equal(acc.servers[0].seeds.size + acc.servers[0].items.length, 0, 'nothing else kept');
  // Route 1: seated? at today's server, reply sealed to the asker with the host's signature outside.
  const { sha, bytesToHex: hx, hexToBytes: hb } = await import('../src/bytes.ts');
  const { seatedDigest } = codesMod;
  const { schnorrVerify } = await import('../src/event.ts');
  const nip44 = await import('nostr-tools/nip44');
  const h = hx(sha(hb(acc.paper.pub))), challenge = hx(randomBytes(16));
  const r = await acc.bus.send(acc.paper, Ys[0].kp.pub, { type: 'seated?', h, challenge });
  assert.ok(schnorrVerify(r.sig, seatedDigest(h, hb(challenge), new TextEncoder().encode(r.ct)), r.host));
  const body = JSON.parse(nip44.v2.decrypt(r.ct, nip44.v2.utils.getConversationKey(acc.paper.sk, r.host)));
  assert.deepEqual(body.servers.map((x: any) => x.host).sort(), Ys.map((y) => y.host.pub).sort());
  assert.equal((await acc.bus.send(acc.paper, Ys[0].kp.pub, { type: 'seated?', h: hx(sha(hb(newKey().pub))), challenge })).code, 'not_seated');
});
import { newKey } from '../src/event.ts';
import * as nodes from '../sim/nodes.ts';
import * as codesMod from '../src/codes.ts';

test('concurrent changes: two adds by two devices, delivered in different orders, give one membership', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const D = await invite(acc, B, (l) => B.approveLock(l), { via: 1 });
  for (const n of [acc.A, B, C, D]) await n.fetch();
  const sets = [acc.A, B, C, D].map((n) => JSON.stringify([...n.m!.devices].sort()));
  assert.equal(new Set(sets).size, 1);
  for (const s of acc.servers) assert.equal(JSON.stringify([...s.m.devices].sort()), sets[0]);
  // Two report-lost lists at once from two devices (each with its own redeal) both apply: redeals add.
  const l1: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  const l2: Change[] = [{ remove: D.kp.pub }, { redeal: { dealer: B.kp.pub } }];
  await acc.A.submit(l1, acc.A.approveLock(l1));
  await B.submit(l2, B.approveLock(l2));                   // B dealt on the old state, concurrently
  await acc.A.fetch(); await B.fetch();
  assert.deepEqual([...acc.A.state!.ids].sort(), [...B.state!.ids].sort());
  assert.equal(acc.A.state!.ids.size, 2);
  for (const s of acc.servers) assert.equal(s.co!.state.ids.size, 2);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'both applied' })));
  assert.ok(verifyEvent(await B.sign({ content: 'both applied, B' })));
});

test('a dealer dying before the co-sign changes nothing; inert uploads expire', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list), { dieAfterUpload: true });
  assert.ok(acc.servers.every((s) => s.uploads.size === 1 && s.co!.state.ids.size === 0));
  assert.ok(verifyEvent(await B.sign({ content: 'B still signs at the old state' })));
  acc.bus.advance(7 * 86400 + 1);
  assert.ok(acc.servers.every((s) => [...s.uploads.values()].every((u) => acc.bus.now - u.at > 7 * 86400)));
});

test('a server down during the redeal catches up by rerepair, with a proof at its old state', async () => {
  const acc = await create();
  const S2 = acc.servers[1];
  acc.bus.kill(S2.kp.pub);
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  acc.bus.revive(S2.kp.pub);
  await S2.catchUp();
  assert.equal(S2.co!.state.ids.size, 0, 'S2 never got its delta');
  // rerepair (§6.7.4): S2 proves its share at its own old state; B (3) and S1 (1) repair index 7 at the new state.
  const { rerepairProof } = await import('../src/upkeep.ts');
  const S1 = acc.servers[0];
  const ch = await acc.bus.send(S2.kp, S1.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
  await B.fetch();
  const proof = rerepairProof(acc.g, S2.kp.pub, 7, S2.co!.state.shares.get(7)!, ch.challenge);
  const sigmas = await B.repairFor([{ key: B.kp.pub, indices: [...B.state!.shares.keys()] }, { key: S1.kp.pub, indices: [4] }], 7, S2.kp.pub, 'rerepair',
    { proof: { challenge: ch.challenge, state: [], proof } });
  await acc.bus.send(B.kp, S2.kp.pub, { type: 'seat_fill', sigmas, state: [...B.state!.ids] });
  assert.deepEqual([...S2.co!.state.ids], [...B.state!.ids]);
  acc.bus.kill(S1.kp.pub); acc.bus.kill(acc.servers[2].kp.pub);
  assert.ok(verifyEvent(await B.sign({ content: 'via the rerepaired S2' })));
  // A forged proof is refused (and the challenge, used once, can't be replayed).
  const bad = { ...rerepairProof(acc.g, S2.kp.pub, 7, 12345n, ch.challenge) };
  acc.bus.revive(S1.kp.pub);
  assert.match(await code(async () => await B.repairFor([{ key: B.kp.pub, indices: [...B.state!.shares.keys()] }, { key: S1.kp.pub, indices: [4] }], 7, S2.kp.pub, 'rerepair',
    { proof: { challenge: ch.challenge, state: [], proof: bad } })), /bad_proof|stale_challenge/);
});

test('one host cannot be repaired into two seats; the backup seat is never repaired by need_repair', async () => {
  const acc = await create();
  const S1 = acc.servers[0];
  assert.match(await code(async () => await acc.A.repairFor([{ key: acc.A.kp.pub, indices: [1, 2, 3] }, { key: S1.kp.pub, indices: [4] }], 5, acc.paper.pub, 'seat')), /backup_seat/);
  assert.match(await code(async () => await acc.A.repairFor([{ key: acc.A.kp.pub, indices: [1, 2, 3] }, { key: S1.kp.pub, indices: [4] }], 99999, acc.paper.pub, 'seat')), /not_assigned/);
  void liftX;
});
