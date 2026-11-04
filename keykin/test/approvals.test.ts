// Core §6.2 approvals between devices and with the paper: the pair flow (a code shown on one device, typed on
// the other) and a paper approval from the paper's own key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import { newKey, verifyEvent } from '../src/event.ts';
import type { Change } from '../src/types.ts';

async function three() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  for (const d of [B, C]) await d.fetch();
  return { acc, A: acc.A, B, C };
}

test('pair: A shows a code, the person types it on B, and the list goes through with both', async () => {
  const { acc, A, B, C } = await three();
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  const { code, approval } = A.pairStart(list, B.kp.pub);
  assert.match(code, /^\d{6}$/);
  await new Promise((r) => setTimeout(r, 10));
  const [ask] = [...B.pairAsks.values()];
  assert.ok(ask && ask.from === A.kp.pub, 'B was asked');
  assert.equal(await B.pairApprove(ask.id, code === '000000' ? '111111' : '000000'), false, 'a wrong code signs nothing');
  assert.equal(await B.pairApprove(ask.id, code), true);
  const a = await approval;
  assert.ok(a?.pair, 'the approval, with both devices');
  await A.submit(list, a!);
  assert.ok(A.m!.removed.has(C.kp.pub));
  assert.ok(verifyEvent(await A.sign({ content: 'after a paired removal' })));
  void acc;
});

test('pair: only the asked device answers; a stranger or a third device can\'t complete it', async () => {
  const { A, B, C } = await three();
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  const { code, approval } = A.pairStart(list, C.kp.pub);
  await new Promise((r) => setTimeout(r, 10));
  // B never got it, and a pair_sign from B is ignored.
  assert.equal(B.pairAsks.size, 0);
  const [ask] = [...C.pairAsks.values()];
  await A.handle(B.kp.pub, { type: 'pair_sign', id: ask.id, code_sig: '00'.repeat(64) }, A.now);
  await C.pairApprove(ask.id, code);
  assert.equal((await approval)!.pair![1].member, C.kp.pub);
});

test('paper: a device and the paper approve a list; another key is refused', async () => {
  const { acc, A, C } = await three();
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  await assert.rejects(A.approveWithPaper(list, newKey()), /not_current_backup/);
  const a = await A.approveWithPaper(list, acc.paper);
  await A.submit(list, a);
  assert.ok(A.m!.removed.has(C.kp.pub));
});
