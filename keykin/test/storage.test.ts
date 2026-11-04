// Core §2 and §5.2: a server restarted from durable storage keeps everything it must (share, record,
// changes, waits, answered ids, push addresses, tombstone) and nothing it must not (nonces).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { create, invite, restartServer } from '../sim/account.ts';
import { FileStore } from '../runtime/store.ts';
import { verifyEvent, wireEvent } from '../src/event.ts';
import { TwoCall, OneCall } from '../src/coordinator.ts';
import { msg, ServerNode } from '../sim/nodes.ts';

const store = () => { const dir = mkdtempSync(join(tmpdir(), 'keykin-store-')); return { s: new FileStore(dir), dir }; };

test('§2: every server restarted from storage; the account goes on: sign, add a device, sign again', async () => {
  const acc = await create();
  const { s, dir } = store();
  for (const i of [0, 1, 2]) restartServer(acc, i, s);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'after a restart' })));
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  for (const i of [0, 1, 2]) restartServer(acc, i, s);
  assert.ok(verifyEvent(await B.sign({ content: 'B, after another' })));
  assert.equal(acc.servers[0].co!.m.devices.size, 2);
  rmSync(dir, { recursive: true });
});

test('§2 item 4 and §5.6: a running hold and an answered request survive a restart', async () => {
  const acc = await create();
  const { s, dir } = store();
  const vanish = wireEvent({ pubkey: acc.g, created_at: acc.bus.now, kind: 62, tags: [], content: '' });
  const holdReq = { ...msg('hold', acc.g, acc.epochId, 'member'), event: vanish };
  const n = await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, holdReq);
  assert.equal(n.kind, 'hold');
  restartServer(acc, 0, s);
  assert.deepEqual(await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, holdReq), n, 'the same request gets the same answer');
  assert.ok(acc.servers[0].co!.holds.has(n.wait), 'the hold is still running');
  acc.bus.advance(acc.servers[0].co!.W + 1);
  restartServer(acc, 0, s);
  const r = new OneCall(acc.A.ctx(), acc.A.me(), { key: acc.servers[0].kp.pub, indices: acc.servers[0].co!.myIndices }, { ...vanish, created_at: vanish.created_at }, { hold: n.wait });
  const ans = await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, r.request);
  assert.equal(ans.type, 'partial', ans.code);
  assert.ok(verifyEvent(r.finish(ans)), 'the hold passed across two restarts');
  rmSync(dir, { recursive: true });
});

test('§5.2: no nonce reaches storage; a two-call round in flight is lost on restart', async () => {
  const acc = await create();
  const { s, dir } = store();
  const S = acc.servers[0];
  const ev = { pubkey: acc.g, created_at: acc.bus.now, kind: 1, tags: [], content: 'two-call' };
  const tc = new TwoCall(acc.A.ctx(), acc.A.me() as any, [{ key: S.kp.pub, indices: S.co!.myIndices }], ev);
  tc.took(S.kp.pub, await acc.bus.send(acc.A.kp, S.kp.pub, tc.commitRequest()));
  const snap = S.snapshot();
  for (const field of ['nonces', 'twoCall', 'hiding', 'binding']) assert.ok(!snap.includes(field), field);
  restartServer(acc, 0, s);
  assert.equal((await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, tc.signRequest())).code, 'unknown_after');
  rmSync(dir, { recursive: true });
});

test('§2 items 5 and 10: push addresses and a tombstone survive a restart', async () => {
  const acc = await create();
  const { s, dir } = store();
  await acc.A.registerPush();
  restartServer(acc, 1, s);
  assert.equal(acc.servers[1].pushReg.get(acc.A.kp.pub)!.length, 3);
  await acc.A.deleteAccount();
  restartServer(acc, 1, s);
  assert.ok(acc.servers[1].tombstone);
  assert.equal((await acc.bus.send(acc.A.kp, acc.servers[1].kp.pub, msg('state_get', acc.g, acc.epochId, 'ask'))).type, 'deleted');
  rmSync(dir, { recursive: true });
});

test('FileStore: atomic replace, and a damaged file is refused on restore, never half-read', async () => {
  const acc = await create();
  const { s, dir } = store();
  s.save('k', 'one'); s.save('k', 'two');
  assert.equal(s.load('k'), 'two');
  assert.equal(s.load('missing'), null);
  assert.throws(() => s.save('../escape', 'x'));
  const key = 'server-x';
  s.save(key, acc.servers[0].snapshot());
  const p = join(dir, `${key}.json`);
  writeFileSync(p, readFileSync(p, 'utf8').slice(0, 500));
  assert.throws(() => ServerNode.restore(acc.bus, s.load(key)!), /malformed/);
  // A share that doesn't match the commitments is refused, as in a welcome.
  const x = JSON.parse(acc.servers[0].snapshot()); x.co.shares[0][1] = '01'.padStart(64, '0');
  assert.throws(() => ServerNode.restore(acc.bus, JSON.stringify(x)));
  rmSync(dir, { recursive: true });
});

test('a device restarted from storage: same key, lock and shares; it signs, approves with its lock, adds a device', async () => {
  const { restartDevice } = await import('../sim/account.ts');
  const acc = await create();
  const { s, dir } = store();
  const A = restartDevice(acc, acc.A, s);
  assert.equal(acc.A, A);
  assert.ok(verifyEvent(await A.sign({ content: 'after a device restart' })));
  const B = await invite(acc, A, (l) => A.approveLock(l));
  const B2 = restartDevice(acc, B, s);
  assert.ok(verifyEvent(await B2.sign({ content: 'B restarted' })));
  assert.equal(B2.m!.devices.size, 2);
  rmSync(dir, { recursive: true });
});

test('a device restore is checked as a handover: shares against the commitments, the key a current member with exactly those indices', async () => {
  const { DeviceNode } = await import('../sim/nodes.ts');
  const acc = await create();
  const good = JSON.parse(acc.A.snapshot());
  const bad1 = structuredClone(good); bad1.state.shares[0][1] = '01'.padStart(64, '0');
  assert.throws(() => DeviceNode.restore(acc.bus, JSON.stringify(bad1)), 'a share that is not on the commitments');
  const bad2 = structuredClone(good); bad2.state.shares = bad2.state.shares.slice(1);
  assert.throws(() => DeviceNode.restore(acc.bus, JSON.stringify(bad2)), /not_member/, 'fewer indices than the member holds');
  const bad3 = structuredClone(good); bad3.kp = bytesToHexKey();
  assert.throws(() => DeviceNode.restore(acc.bus, JSON.stringify(bad3)), /not_member/, 'a key that is not a member');
  assert.throws(() => DeviceNode.restore(acc.bus, '{"v":2}'), /malformed/);
  // The watches and the push keys come back too.
  await acc.A.registerPush();
  const d = DeviceNode.restore(acc.bus, acc.A.snapshot());
  assert.equal(d.pushKeys.size, acc.A.pushKeys.size);
  assert.equal(d.lock!.pub.pub, acc.A.lock!.pub.pub);
});
const bytesToHexKey = () => [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
