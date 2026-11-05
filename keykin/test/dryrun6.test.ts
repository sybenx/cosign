// Dry-run result 6: a device that missed another's join dealt a report-lost's redeal without it, and every server refused
// it as `missing: <new device>` (core §6.7.3). The dealer now fetches first, and deals again on `missing`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import type { Change } from '../src/types.ts';

test('a phone that missed the tablet\'s join reports the laptop lost: the redeal includes the tablet', async () => {
  const acc = await create();
  const A = acc.A;                                                            // the laptop
  const B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });   // the phone
  await B.fetch();
  const C = await invite(acc, A, (l) => A.approveLock(l), { lock: true });   // the tablet; the phone hears nothing
  assert.ok(!B.m!.members.has(C.kp.pub), 'the phone\'s view is stale, as on the user\'s phone');
  const list: Change[] = [{ remove: A.kp.pub }, { redeal: { dealer: B.kp.pub } }];
  // The bug, as it was: dealing from the stale view is refused.
  await assert.rejects(B.submitOnce(list, B.approveLock(list)), (e: any) => e.code === 'missing' && String(e.message).includes(C.kp.pub));
  // The fix: submit brings the membership up to date and deals to the tablet too.
  await B.submit(list, B.approveLock(list));
  assert.ok(B.m!.removed.has(A.kp.pub));
  await C.fetch();
  assert.ok(C.m!.removed.has(A.kp.pub) && !C.wiped, 'the tablet applied the redeal');
  const ev = await C.sign({ kind: 1, content: 'the tablet still posts', tags: [] });
  assert.equal(ev.pubkey, acc.g);
  const ev2 = await B.sign({ kind: 1, content: 'and the phone', tags: [] });
  assert.equal(ev2.pubkey, acc.g);
});
