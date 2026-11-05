// Review 16's findings (the grant store) and Doors §1's decrypt rules, as regression tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { create, invite } from '../sim/account.ts';
import { scopesForEvent, scopeForDecrypt, Evidence, listPlaintextOk } from '../device/grants.ts';
import { siteGuard } from '../device/doors.ts';
import { newKey } from '../src/event.ts';

const g = 'ab'.repeat(32);
const ct = () => nip44.v2.encrypt('x', nip44.v2.utils.getConversationKey(newKey().sk, newKey().pub));

test('H1: tokens by method, host and blob; deletions by token are never silent', () => {
  const t = (kind: number, tags: string[][], own: string | null = 'site.example') => scopesForEvent(kind, tags, own);
  assert.deepEqual(t(27235, [['u', 'https://site.example/api'], ['method', 'GET']]), ['sign-in']);
  assert.deepEqual(t(27235, [['u', 'https://site.example/api'], ['method', 'PUT']]), ['sign-in', 'post']);
  assert.deepEqual(t(27235, [['u', 'https://other.example/x'], ['method', 'POST']]), ['sign-in', 'host:other.example'], 'another host: asked once per host');
  assert.equal(t(27235, [['u', 'https://site.example/x'], ['method', 'DELETE']]), 'declined');
  assert.deepEqual(t(24242, [['t', 'upload'], ['x', 'ab'.repeat(32)]], null), ['sign-in'], 'a blob-bound upload is silent anywhere');
  assert.deepEqual(t(24242, [['t', 'list'], ['server', 'https://blossom.example']], null), ['sign-in', 'host:blossom.example']);
  assert.equal(t(24242, [['t', 'delete'], ['x', 'ab'.repeat(32)]]), 'declined');
  assert.deepEqual(t(10002, []), ['lists']); assert.deepEqual(t(39089, []), ['lists']); assert.deepEqual(t(30023, []), ['post'], 'articles are ordinary (L3)');
});

test('§1: a decrypt-to-self is judged on evidence: the same grant or the member app; the most private wins', () => {
  const ev = new Evidence();
  const listCt = ct(), walletCt = ct(), notesCt = ct(), plantedCt = ct();
  ev.event(10000, listCt); ev.encrypted(listCt, 'member');
  ev.event(17375, walletCt); ev.encrypted(walletCt, 'member');
  ev.event(30078, notesCt); ev.event(10000, notesCt); ev.encrypted(notesCt, 'member');
  ev.event(10000, plantedCt); ev.encrypted(plantedCt, 'by:grantB');
  const list = JSON.stringify([['p', 'x']]);
  assert.equal(scopeForDecrypt(g, g, list, { payload: listCt, evidence: ev, owner: 'by:grantA' }), 'lists', 'a member list: lists');
  assert.equal(scopeForDecrypt(g, g, list, { payload: walletCt, evidence: ev }), 'wallet', 'a wallet event\'s bytes: wallet, whatever they look like');
  assert.equal(scopeForDecrypt(g, g, list, { payload: notesCt, evidence: ev }), 'private-data', 'both: the most private wins');
  // Another grant's ciphertext proves nothing for this one: a second site can't plant a copy (no record of it here).
  assert.equal(scopeForDecrypt(g, g, list, { payload: plantedCt, evidence: ev, owner: 'by:grantA' }), 'private-data');
  // A list-shaped wallet plaintext, under a list event: not a list after all.
  assert.equal(scopeForDecrypt(g, g, JSON.stringify([['privkey', 'k']]), { payload: listCt, evidence: ev }), 'wallet');
  // A non-canonical payload is refused, never guessed.
  assert.equal(scopeForDecrypt(g, g, list, { payload: listCt + ' ', evidence: ev }), 'malformed');
  assert.ok(listPlaintextOk(list) && !listPlaintextOk(JSON.stringify([['amount', '1']])));
});

test('M3: a site can\'t delete the account\'s grant events by id', () => {
  const ids = new Set(['cd'.repeat(32)]);
  assert.throws(() => siteGuard({ kind: 5, tags: [['e', 'cd'.repeat(32)]] }, g, [], ids), /keykin- data/);
  siteGuard({ kind: 5, tags: [['e', 'ef'.repeat(32)]] }, g, [], ids);
});

test('the gate: a restored copy that never fetched can\'t publish over its newer self; an ended grant stays ended', async () => {
  const acc = await create();
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l)); await B.fetch();
  const e = A.grants.make({ site: 'https://x.example', says: 'x', door: 'nip07', connection: 'c', scopes: ['sign-in'] });
  await A.grants.publish();
  const stale = A.grants.dump();
  A.grants.end(A.kp.pub, e.id); await A.grants.publish();
  // A copy from before the end, restored: its first publish reads first and takes over the newer event.
  const { DeviceNode } = await import('../device/node.ts');
  const copy = DeviceNode.restore(acc.bus, A.snapshot());
  copy.grants.load({ ...stale, lastPublish: 0 }); copy.grants.goodFetchAt = 0;
  await copy.grants.publish();
  await B.grants.fetch();
  assert.equal(B.grants.all().length, 0, 'the ended grant never comes back');
});

test('M4: a grant in daily use stays listed on other devices', async () => {
  const acc = await create();
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l)); await B.fetch();
  const e = A.grants.make({ site: 'https://daily.example', says: 'daily', door: 'nip07', connection: 'c', scopes: ['sign-in'] });
  acc.bus.advance(80 * 86400); A.grants.used(e.id); await A.grants.publish();
  acc.bus.advance(20 * 86400);
  await B.grants.fetch();
  assert.equal(B.grants.all().length, 1, 'used 20 days ago: not expired');
});

test('M11: a NIP-46 grant reaches the relays, and its end does too', async () => {
  const acc = await create();
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l)); await B.fetch();
  const link = A.nip46.mintBunker(['ws://relay.test'], 'coracle');
  const signer = new URL(link).hostname, secret = new URL(link).searchParams.get('secret')!;
  const { bytesToHex, randomBytes } = await import('../src/bytes.ts');
  const { finalizeEvent } = await import('nostr-tools/pure');
  const key = newKey(), ck = nip44.v2.utils.getConversationKey(key.sk, signer);
  await acc.bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: acc.bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id: bytesToHex(randomBytes(8)), method: 'connect', params: [signer, secret] }), ck) }, key.sk));
  await new Promise((r) => setTimeout(r, 1500));
  await B.grants.fetch();
  assert.deepEqual(B.grants.all().map((x) => x.door), ['nip46'], 'published on bind');
  await A.nip46.end(signer);
  await new Promise((r) => setTimeout(r, 1500));
  await B.grants.fetch();
  assert.equal(B.grants.all().length, 0, 'and its end');
});
