// Review 13's findings, each as a regression test (TS; the Kotlin ones are in UpkeepTest).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeEvent } from 'nostr-tools/pure';
import { create, invite } from '../sim/account.ts';
import { newKey } from '../src/event.ts';
import { wrap, unwrap } from '../src/transport.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { Change } from '../src/types.ts';

const hex16 = () => bytesToHex(randomBytes(16));

test('H1: a stranger\'s junk change events never join the change set', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const before = B.changes.length;
  const junk = Array.from({ length: 200 }, (_, k) => finalizeEvent({ kind: 24302, created_at: acc.bus.now, tags: [['v', '1'], ['epoch', acc.epochId]],
    content: JSON.stringify({ v: 1, g: acc.g, epoch: acc.epochId, change: { remove: 'ab'.repeat(32) }, list: [{ remove: 'ab'.repeat(32) }], n: k }) }, newKey().sk));
  const t0 = Date.now();
  B.takeChanges(junk as any);
  assert.equal(B.changes.length, before);
  assert.equal(B.refusedChanges.length, 0, 'not kept for later either');
  assert.ok(Date.now() - t0 < 5000, 'and cheap');
});

test('M1: deliveries waiting for their redeal come only from current devices, bounded per sender; the rest stay at the server', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const stranger = newKey();
  for (let k = 0; k < 100; k++) assert.equal(B.takeDelivery(wrap(stranger.sk, B.kp.pub, { type: 'delta', redeal: hex16(), deltas: [] })), 'junk');
  assert.equal(B.takeDelivery(wrap(acc.A.kp.sk, B.kp.pub, { type: 'delta', redeal: 'x:' + hex16(), deltas: [] })), 'junk', 'a redeal id is 16 bytes of hex');
  for (let k = 0; k < 16; k++) assert.equal(B.takeDelivery(wrap(acc.A.kp.sk, B.kp.pub, { type: 'delta', redeal: hex16(), deltas: [] })), 'kept');
  assert.equal(B.takeDelivery(wrap(acc.A.kp.sk, B.kp.pub, { type: 'delta', redeal: hex16(), deltas: [] })), 'full');
  assert.equal(B.pendingDeltas.size, 16);
  // Past an upload's life, they go.
  acc.bus.advance(7 * 86400 + 1);
  B.applyAll();
  assert.equal(B.pendingDeltas.size, 0);
});

test('M3: a dealer\'s malformed deltas drop the delivery and never wedge later applies', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  acc.bus.kill(B.kp.pub);
  let mine: any;
  const send = acc.bus.send.bind(acc.bus);
  acc.bus.send = (async (from: any, to: string, body: any) => { if (body?.type === 'upload') mine ??= body.items.find((x: any) => x.to === B.kp.pub)?.wrap; return send(from, to, body); }) as any;
  const r: Change[] = [{ redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(r, acc.A.approveLock(r));
  acc.bus.send = send;
  const body = unwrap(B.kp.sk, mine).body;
  B.takeDelivery(wrap(acc.A.kp.sk, B.kp.pub, { ...body, deltas: body.deltas.map(([i]: [number]) => [i, 'zz']) }));
  B.takeChanges(acc.A.changes);
  assert.doesNotThrow(() => B.applyAll());
  assert.ok(B.notices.some((n) => n.kind === 'bad_delivery'));
  // The real delivery still applies afterwards.
  B.takeDelivery(mine); B.applyAll();
  assert.deepEqual([...B.state!.ids], [...acc.A.state!.ids]);
});

test('§8.2: a delivery left in an inbox is pushed to the sleeping device', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.equal(await B.registerPush(), 3);
  acc.bus.kill(B.kp.pub);
  const before = (acc.bus as any).pushes.length;
  const r: Change[] = [{ redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(r, acc.A.approveLock(r));
  acc.bus.revive(B.kp.pub);
  const got = B.readPushes().slice(0);
  assert.ok((acc.bus as any).pushes.length > before, 'the servers pushed');
  assert.ok(got.some((p: any) => p.cls === 'ask'), 'an ask push from a seated server');
});
