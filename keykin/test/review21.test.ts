// Review 21's findings (core 14.21: seeds to the paper), as regression tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, recover } from '../sim/account.ts';
import { bytesToHex } from '../src/bytes.ts';
import { seedItems, seedOnlyItem, materialInner } from '../src/upkeep.ts';
import { itemHash } from '../src/redeal.ts';
import { msg } from '../src/msg.ts';
import { newKey } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const redeal = async (A: any) => { const r: Change[] = [{ redeal: { dealer: A.kp.pub } }]; await A.submit(r, A.approveLock(r)); };

test('H1: one server\'s junk seed item can\'t block a paper-only recovery', async () => {
  const acc = await create();
  const A = acc.A; await redeal(A);
  const s1 = A.dataKeys.current();
  const K = await A.newPaper((l) => A.approveLock(l));
  // A dishonest server adds a seed item addressed to K, signed by someone else, and another K can't have signed.
  const junk = seedItems(newKey(), 'ab'.repeat(32), [['cd'.repeat(16), 'ef'.repeat(32)]])[0];
  acc.servers[0].items.push({ ...junk, to: K.pub });
  const { D } = await recover(acc, [A], K);
  assert.equal(bytesToHex(D.dataKeys.forState(s1.state)!), bytesToHex(s1.key));
});

test('M1: a device\'s later seed-only batches are each kept, not only its first', async () => {
  const acc = await create();
  const A = acc.A, B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  await B.fetch(); await A.fetch(); await redeal(A); await B.fetch();
  const K = await A.newPaper((l) => A.approveLock(l)); await B.fetch();
  const pc = B.m!.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === K.pub)!;
  const pr = [...B.m!.redeals.values()].find((x) => x.listHash === pc.listHash)!.r.id;
  const rec = B.seedRecords()[0];
  const second = seedOnlyItem(acc.g, B.kp, K.pub, pr, B.seeds.get(pr)!, [[rec.id, rec.seed]]);
  const a = await acc.bus.send(B.kp, acc.servers[0].kp.pub, msg('paper_reissue', acc.g, acc.epochId, 'member', { item: second }));
  assert.equal(a.type, 'seed_held'); assert.equal(a.item, itemHash(second), 'kept as itself, not answered with the first');
});

test('L8: a device that didn\'t print the paper catches up its material, so the welcomes it sends carry it', async () => {
  const acc = await create();
  const A = acc.A, B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  await B.fetch(); await A.fetch(); await redeal(A); await B.fetch();
  acc.bus.kill(B.kp.pub);
  const K = await A.newPaper((l) => A.approveLock(l));
  acc.bus.revive(B.kp.pub); await B.fetch();
  const pc = B.m!.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === K.pub)!;
  assert.equal(materialInner(B.base!, B.items.filter((x) => x.kind === 'seeds')), (pc.c.change as any).paper.inner);
});
