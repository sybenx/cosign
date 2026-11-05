// Core §4.5, the data key, through the API another library calls (device/datakey.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, addHelper } from '../sim/account.ts';
import { DeviceNode } from '../device/index.ts';
import { bytesToHex } from '../src/bytes.ts';
import type { Change } from '../src/types.ts';

test('every device holds the same key for a state; a redeal moves it on, and older keys still read older data', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const k1 = acc.A.dataKeys.current();
  assert.equal(k1.key.length, 32);
  assert.deepEqual([bytesToHex(B.dataKeys.current().key), C.dataKeys.current().state], [bytesToHex(k1.key), k1.state], 'one key per state, on every device');
  const rotations: string[] = [];
  const stop = acc.A.dataKeys.onRotate((k) => rotations.push(k.state));
  // C is reported lost: [remove, redeal]. A new seed, to devices only, so a new key.
  const lost: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(lost, acc.A.approveLock(lost));
  await B.fetch();
  const k2 = acc.A.dataKeys.current();
  assert.notEqual(k2.state, k1.state);
  assert.notEqual(bytesToHex(k2.key), bytesToHex(k1.key));
  assert.deepEqual(rotations, [k2.state], 'the listener heard the rotation once');
  assert.equal(bytesToHex(B.dataKeys.current().key), bytesToHex(k2.key), 'B moved on too');
  assert.equal(bytesToHex(acc.A.dataKeys.forState(k1.state)!), bytesToHex(k1.key), 'the old key reads old data');
  assert.deepEqual(acc.A.dataKeys.states(), [k1.state, k2.state]);
  assert.equal(acc.A.dataKeys.forState('ab'.repeat(32)), null, 'a state this device never held');
  // The removed device has no key at all, now or later.
  await C.fetch();
  assert.throws(() => C.dataKeys.current(), /no_data_key/);
  assert.equal(C.dataKeys.forState(k2.state), null);
  // A restart keeps the history: old data stays readable.
  const A2 = DeviceNode.restore(acc.bus, acc.A.snapshot());
  assert.equal(bytesToHex(A2.dataKeys.forState(k1.state)!), bytesToHex(k1.key));
  assert.equal(bytesToHex(A2.dataKeys.current().key), bytesToHex(k2.key));
  stop();
});

test('helpers and servers never get the data key; nothing a server writes holds it or a seed', async () => {
  const acc = await create();
  const H = await addHelper(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.throws(() => H.dataKeys.current(), /no_data_key/);
  const lost: Change[] = [{ redeal: { dealer: acc.A.kp.pub } }];
  void lost;
  const secrets = [acc.A.baseDk, ...acc.A.dkSeeds, bytesToHex(acc.A.dataKeys.current().key)];
  for (const s of acc.servers) { const snap = s.snapshot(); for (const x of secrets) assert.ok(!snap.includes(x), `${s.name} holds ${x.slice(0, 8)}`); }
});
