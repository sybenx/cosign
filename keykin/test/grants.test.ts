// Doors §1–§2: grants signed by their maker, one encrypted event per device, read and merged by every device.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import { grantEvents, readMaker, grantsD, scopeForEvent, scopeForDecrypt, signEntry, entryOk, type GrantSet } from '../device/grants.ts';
import { newKey } from '../src/event.ts';
import type { Change } from '../src/types.ts';

async function two() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  await B.fetch();
  return { acc, A: acc.A, B };
}
const site = (n: string) => ({ site: `https://${n}.example`, says: n, door: 'nip07' as const, connection: 'chrome', scopes: ['sign-in', 'post'] as any });

test('an entry is signed by its maker; a changed one fails', async () => {
  const kp = newKey(), g = newKey().pub;
  const e = signEntry(g, kp, { id: '00'.repeat(16), v: 1, ...site('a'), borrowed: false, helper: false, made: 1, expiry: 'unused-90d' });
  assert.ok(entryOk(g, e));
  assert.ok(!entryOk(g, { ...e, scopes: ['dms'] }));
});

test('a device publishes its grants; another device lists them and signs one out; it never comes back', async () => {
  const { A, B } = await two();
  const g1 = A.grants.make(site('coracle')); A.grants.make(site('primal'));
  await A.grants.publish();
  await B.grants.fetch();
  assert.deepEqual(B.grants.all().map((e) => e.says).sort(), ['coracle', 'primal'], 'B lists A\'s grants');
  // B signs out coracle: a tombstone for A, published in B's event.
  B.grants.end(A.kp.pub, g1.id);
  await B.grants.publish();
  await A.grants.fetch();
  assert.equal(A.grants.forSite(g1.site, 'nip07'), null, 'A ended it on B\'s word');
  await A.grants.publish();
  await B.grants.fetch();
  assert.deepEqual(B.grants.all().map((e) => e.says), ['primal']);
  // A restored copy of A that still has coracle: it adopts its own newer event, and the ended id stays ended.
  const stale = A.grants.dump(); stale.own.push(g1); stale.lastPublish = 0;
  A.grants.load({ ...stale, union: [], ended: [] });
  await A.grants.fetch();
  assert.equal(A.grants.forSite(g1.site, 'nip07'), null, 'never back from a restored copy');
});

test('a removed device\'s grants are gone everywhere', async () => {
  const { acc, A, B } = await two();
  B.grants.make(site('thief-planted'));
  await B.grants.publish();
  await A.grants.fetch();
  assert.equal(A.grants.all().length, 1);
  const r: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  await A.submit(r, A.approveLock(r));
  assert.equal(A.grants.all().length, 0, 'B is no longer a device: its grants are revoked');
  void acc;
});

test('the event is account-signed, unlinkable to the member key, encrypted under the data key; a forged maker_sig is refused', async () => {
  const { A, B } = await two();
  A.grants.make(site('x'));
  const [ev] = await A.grants.publish();
  assert.equal(ev.pubkey, A.g);
  const d = ev.tags.find((t) => t[0] === 'd')![1];
  assert.ok(d.startsWith('keykin-grants:') && !d.includes(A.kp.pub.slice(0, 16)));
  assert.ok(!ev.content.includes('coracle') && !ev.content.includes('example'), 'encrypted');
  // Another member can't publish a set under A's d: maker_sig is A's member key.
  const dk = B.dataKeys.current();
  const forged = grantEvents(A.g, B.kp, B.baseDk, dk, { entries: [], tombstones: [], ended: [], union: [] }, ev.created_at + 10);
  assert.notEqual(forged[0].tags[0][1], d, 'a set is under its own maker\'s d');
  const fake = { ...forged[0], tags: [['d', d], ...forged[0].tags.slice(1)] };
  const signed = await A.sign(fake);
  assert.equal(readMaker(A.g, A.kp.pub, A.baseDk, (s) => A.dataKeys.forState(s), [signed])?.set.entries.length ?? null, null, 'B\'s forgery under A\'s d fails');
  assert.equal(grantsD(A.baseDk, A.kp.pub), d);
});

test('a big set goes in parts, read back whole', async () => {
  const { A, B } = await two();
  for (let k = 0; k < 120; k++) A.grants.make({ ...site(`s${k}`), says: 'x'.repeat(200) + k });
  const evs = await A.grants.publish();
  assert.ok(evs.length > 1 && evs.every((e) => e.tags.some((t) => t[0] === 'parts')));
  await B.grants.fetch();
  assert.equal(B.grants.all().length, 120);
});

test('the set survives a redeal: re-encrypted under the new data key', async () => {
  const { A, B } = await two();
  A.grants.make(site('y'));
  await A.grants.publish();
  const r: Change[] = [{ redeal: { dealer: A.kp.pub } }];
  await A.submit(r, A.approveLock(r));
  await B.fetch();
  await A.grants.publish();
  await B.grants.fetch();
  assert.deepEqual(B.grants.all().map((e) => e.says), ['y']);
});

test('which scope a request needs (§1)', () => {
  const g = 'ab'.repeat(32);
  assert.equal(scopeForEvent(1), 'post'); assert.equal(scopeForEvent(3), 'lists'); assert.equal(scopeForEvent(10000), 'lists');
  assert.equal(scopeForEvent(22242), 'sign-in'); assert.equal(scopeForEvent(17375), 'wallet'); assert.equal(scopeForEvent(30078), 'post');
  assert.equal(scopeForDecrypt(g, 'cd'.repeat(32)), 'dms');
  assert.equal(scopeForDecrypt(g, g, JSON.stringify([['p', 'x'], ['t', 'y']])), 'lists');
  assert.equal(scopeForDecrypt(g, g, JSON.stringify([['privkey', 'x']])), 'wallet');
  assert.equal(scopeForDecrypt(g, g, JSON.stringify({ kind: 14, pubkey: g, content: 'hi' })), 'dms');
  assert.equal(scopeForDecrypt(g, g, 'a private note'), 'private-data');
});
