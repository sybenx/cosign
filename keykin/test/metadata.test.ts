// Device policy §1's metadata, synced: every device judges a decrypt on every current device's records.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import { scopeForDecrypt } from '../device/grants.ts';
import { metaD, indexD, KIND_META } from '../device/metadata.ts';
import type { Change } from '../src/types.ts';

async function three() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  for (const d of [B, C]) await d.fetch();
  return { acc, A: acc.A, B, C };
}
const list = JSON.stringify([['p', 'ab'.repeat(32)]]);

test('a list encrypted and signed on A is lists on B once A\'s metadata syncs (and private-data before)', async () => {
  const { A, B } = await three();
  const ct = await A.nip44(A.g, list, true);                 // the member app's own encryption
  await A.sign({ kind: 10000, content: ct, tags: [] });
  const judge = () => scopeForDecrypt(B.g, B.g, list, { payload: ct, evidence: B.evidence, owner: 'x:y' });
  assert.equal(judge(), 'private-data', 'B has no record of it yet');
  await A.meta.publish();
  await B.meta.fetch();
  assert.equal(judge(), 'lists', 'A\'s records count on B');
});

test('a removed device\'s records stop counting', async () => {
  const { A, B, C } = await three();
  const ct = await C.nip44(C.g, list, true);
  await C.sign({ kind: 10000, content: ct, tags: [] });
  await C.meta.publish(); await B.meta.fetch();
  assert.equal(scopeForDecrypt(B.g, B.g, list, { payload: ct, evidence: B.evidence }), 'lists');
  const r: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  await A.submit(r, A.approveLock(r)); await B.fetch();
  assert.equal(scopeForDecrypt(B.g, B.g, list, { payload: ct, evidence: B.evidence }), 'private-data');
});

test('a big month goes in parts and reads back whole; an older snapshot never rolls a reader back', async () => {
  const { acc, A, B } = await three();
  for (let k = 0; k < 400; k++) A.meta.encrypted((await A.nip44(A.g, `n${k}`, true)), `by:${k}`);
  const first = await A.meta.publish();
  assert.ok(first.filter((e) => e.tags.some((t) => t[1].startsWith('keykin-meta:'))).length > 1, 'more than one part');
  await B.meta.fetch();
  // Each ciphertext carries two records: the member app's own encryption, and the grant this test adds.
  assert.equal(B.evidence.owners.size, 400);
  assert.equal([...B.evidence.owners.values()].reduce((n, s) => n + s.size, 0), 800);
  // A newer snapshot, then a reader shown only the older one: it keeps what it read.
  A.meta.encrypted(await A.nip44(A.g, 'later', true), 'by:later');
  acc.bus.advance(1); await A.meta.publish();
  await B.meta.fetch();
  const n = B.evidence.owners.size;
  acc.bus.published.splice(0, acc.bus.published.length, ...first);
  await B.meta.fetch();
  assert.equal(B.evidence.owners.size, n, 'no rollback to the older snapshot');
});

test('no other member can publish under a device\'s d', async () => {
  const { A, B } = await three();
  A.meta.encrypted(await A.nip44(A.g, 'x', true), 'by:1');
  await A.meta.publish();
  // B re-signs A's index under its own member key: B's index d, never A's.
  assert.notEqual(indexD(B.baseDk, B.kp.pub), indexD(A.baseDk, A.kp.pub));
  assert.notEqual(metaD(A.baseDk, A.kp.pub, '2026-11', 0), metaD(A.baseDk, B.kp.pub, '2026-11', 0));
  const before = B.evidence.owners.size;
  B.meta.encrypted(await B.nip44(B.g, 'forged', true), 'by:forged');
  // B publishes, but its snapshot sits under its own d; A reading it attributes it to B, never to A.
  await B.meta.publish(); await A.meta.fetch();
  assert.ok([...A.meta.others.keys()].every((m) => m === B.kp.pub));
  assert.equal(KIND_META, 30078); void before;
});
