// Review 17's findings (synced metadata), as regression tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { create, invite } from '../sim/account.ts';
import { Evidence, scopeForDecrypt } from '../device/grants.ts';
import { lastMonths, MetaStore } from '../device/metadata.ts';
import { newKey } from '../src/event.ts';

const g = 'ab'.repeat(32);
const list = JSON.stringify([['p', 'x']]);
const ct = () => nip44.v2.encrypt('x', nip44.v2.utils.getConversationKey(newKey().sk, newKey().pub));

test('M1: evidence needs the same grant to have encrypted and signed it; a site\'s copy into its own list proves nothing', () => {
  const ev = new Evidence(), c = ct();
  ev.encrypted(c, 'member'); ev.event(30078, c, 'member');           // the member's private note
  ev.event(10000, c, 'dev:siteX');                                     // a site with lists signs a copy into a 10000
  assert.equal(scopeForDecrypt(g, g, list, { payload: c, evidence: ev, owner: 'dev:siteX' }), 'private-data');
  const l = ct(); ev.encrypted(l, 'dev:siteX'); ev.event(10000, l, 'dev:siteX');
  assert.equal(scopeForDecrypt(g, g, list, { payload: l, evidence: ev, owner: 'dev:siteX' }), 'lists', 'its own list, encrypted and signed by it');
});

test('H2: a flood of records sheds the oldest, never halts the sync; one site can\'t crowd out the member', async () => {
  const ev = new Evidence();
  for (let k = 0; k < Evidence.PER_OWNER + 50; k++) ev.encrypted(ct(), 'dev:flooder');
  assert.equal([...ev.owners.values()].filter((s) => s.has('dev:flooder')).length, Evidence.PER_OWNER);
  ev.encrypted(ct(), 'member');
  assert.equal([...ev.owners.values()].filter((s) => s.has('member')).length, 1);
  const acc = await create();
  for (let k = 0; k < 7000; k++) acc.A.meta.encrypted(ct(), `${acc.A.kp.pub}:${k % 40}`);
  await acc.A.meta.publish();                                          // no throw: trimmed to fit
  assert.equal(acc.A.meta.dirty.size, 0);
});

test('M4: the kept months are calendar months, also on the 31st', () => {
  assert.deepEqual(lastMonths(Date.UTC(2026, 2, 31) / 1000, 3), ['2026-03', '2026-02', '2026-01']);
  assert.deepEqual(lastMonths(Date.UTC(2026, 0, 15) / 1000, 2), ['2026-01', '2025-12']);
});

test('M2: a month whose parts don\'t match part 0 keeps what was read before', async () => {
  const acc = await create();
  const A = acc.A, B = await invite(acc, A, (l) => A.approveLock(l)); await B.fetch(); await A.fetch();
  const c = await A.nip44(A.g, list, true); await A.sign({ kind: 10000, content: c, tags: [] });
  await A.meta.publish(); await B.meta.fetch();
  assert.equal(scopeForDecrypt(B.g, B.g, list, { payload: c, evidence: B.evidence }), 'lists');
  // A newer part 0 alone (the other parts held back): B keeps the month it had.
  for (let k = 0; k < 600; k++) A.meta.encrypted(await A.nip44(A.g, `n${k}`, true), 'member');
  acc.bus.advance(1);
  const evs = await A.meta.publish();
  acc.bus.published.splice(acc.bus.published.length - evs.length, evs.length, ...evs.filter((e, k) => k === 0 || e.tags.some((t) => t[1].startsWith('keykin-meta-index:'))));
  await B.meta.fetch();
  assert.equal(scopeForDecrypt(B.g, B.g, list, { payload: c, evidence: B.evidence }), 'lists', 'still there');
});

test('L2: a restored copy continues its own numbers', async () => {
  const acc = await create();
  const A = acc.A; await A.fetch();
  A.meta.encrypted(ct(), 'member'); await A.meta.publish(); acc.bus.advance(1);
  A.meta.encrypted(ct(), 'member'); await A.meta.publish();
  const fresh = new MetaStore((A.meta as any).h);
  await fresh.fetch();
  assert.ok(fresh.indexSeq >= 2, `it read its own index (${fresh.indexSeq})`);
});
