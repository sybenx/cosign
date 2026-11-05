// DeviceNode.onRemoved: the extension signs out its tabs the moment the device learns it was removed or the account
// was deleted, once, and not on a server's word alone.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import type { Change } from '../src/types.ts';

const tick = () => new Promise((ok) => setTimeout(ok, 0));

test('onRemoved fires once, at the first refused sign, after the removal is verified', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const heard: string[] = [];
  B.onRemoved = (why) => heard.push(why);
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  assert.equal(B.wiped, false, 'nothing told B yet');
  await assert.rejects(B.sign({ content: 'after removal' }), (e: any) => e.code === 'removed');
  await tick();
  assert.ok(B.wiped);
  assert.deepEqual(heard, ['removed']);
  await B.fetch(); await tick();
  assert.deepEqual(heard, ['removed'], 'once only');
});

test('a server saying `removed` without the change does not wipe', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  let heard = 0; B.onRemoved = () => heard++;
  // Every server lies: it refuses B's sign as removed but has no such change to hand over.
  for (const s of acc.servers) { const h = s.handle.bind(s); s.handle = async (from: string, body: any, at: number) => body?.type === 'sign' || body?.type === 'sign_request' ? { type: 'error', code: 'removed' } : h(from, body, at); }
  await assert.rejects(B.sign({ content: 'x' }));
  await tick();
  assert.equal(B.wiped, false); assert.equal(heard, 0);
});

test('onRemoved says `deleted` when this device deletes the account', async () => {
  const acc = await create();
  const heard: string[] = [];
  acc.A.onRemoved = (why) => heard.push(why);
  assert.equal(await acc.A.deleteAccount(), 3);
  await tick();
  assert.deepEqual(heard, ['deleted']);
});
