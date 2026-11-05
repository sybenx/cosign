// Doors §2's remaining parts: the counted relays' majorities, ends delivered to their home, "Sign out of every site",
// re-encryption after a redeal, and helper grants (Helper module §2, §4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create, invite, addHelper } from '../sim/account.ts';
import { RelayHealth, majority } from '../device/relays.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { DeviceNode } from '../device/node.ts';
import type { Change } from '../src/types.ts';

const site = (n: string) => ({ site: `https://${n}.example`, says: n, door: 'nip07' as const, connection: 'chrome', scopes: ['sign-in', 'post'] as any });
async function two() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  await B.fetch(); await acc.A.fetch();
  return { acc, A: acc.A, B };
}
/** A NIP-46 client of `signer`, through the bus's relay. */
function client(bus: any) {
  const key = newKey();
  return async (signer: string, method: string, params: string[] = []) => {
    const id = bytesToHex(randomBytes(8)), ck = nip44.v2.utils.getConversationKey(key.sk, signer);
    const reply = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (r: any) => { const x = JSON.parse(nip44.v2.decrypt(r.content, ck)); if (x.id === id) { w.close(); res(x); } }); });
    await bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, key.sk));
    return reply;
  };
}
const retries = (d: DeviceNode) => { const q: (() => void)[] = []; (d.grants.h as any).later = (f: () => void) => q.push(f); return q; };

test('the counted relays: a publish counts once more than half accept every part, and is retried until then', async () => {
  const { acc, A } = await two();
  const q = retries(A);
  // Writes time out at two relays that still answer reads (a publish fetches first, and that fetch is good).
  acc.bus.relayFaults.set('wss://r2.test', 'writedown'); acc.bus.relayFaults.set('wss://r3.test', 'writedown');
  A.grants.make(site('a'));
  await A.grants.publish();
  assert.equal(A.recordedRelays().length, 4, 'the record\'s 3 and the seat holders\' 1');
  assert.equal(A.grants.counted, false, '2 of 4'); assert.equal(q.length, 1, 'a retry is scheduled');
  acc.bus.relayFaults.delete('wss://r2.test');
  q.shift()!(); await new Promise((r) => setTimeout(r, 20));
  assert.equal(A.grants.counted, true, '3 of 4');
  assert.ok(!A.grants.lastSet.includes('wss://r3.test') && A.grants.lastSet.includes('wss://r2.test'));
});

test('a fetch is good only with a majority of the counted relays and of the last publish\'s set', async () => {
  const { acc, A } = await two();
  A.grants.goodFetchAt = 0;
  acc.bus.relayFaults.set('wss://r1.test', 'down'); acc.bus.relayFaults.set('wss://r2.test', 'down');
  await A.grants.fetch();
  assert.equal(A.grants.goodFetchAt, 0, '2 of 4 answered');
  await assert.rejects(A.grants.publish(), /try_later|did not answer/, 'never publishes after a failed fetch');
  acc.bus.relayFaults.delete('wss://r2.test');
  await A.grants.fetch();
  assert.ok(A.grants.goodFetchAt > 0);
});

test('a relay that keeps failing while others answer is dropped after 10 tries over 7 days, and retried weekly', () => {
  const h = new RelayHealth(), rec = ['a', 'b', 'c'];
  for (let k = 0; k < 10; k++) h.fetched(rec, ['a', 'b'], rec, 1000 + k * 86400);
  assert.deepEqual(h.counted(rec), ['a', 'b']);
  assert.deepEqual(h.toFetch(rec, 1000 + 10 * 86400), ['a', 'b'], 'not yet due its retry');
  assert.deepEqual(h.toFetch(rec, 1000 + 17 * 86400), rec, 'weekly retry');
  h.fetched(rec, rec, rec, 1000 + 17 * 86400);
  assert.deepEqual(h.counted(rec), rec, 'it answered: counts again');
  // The device's own downtime (nobody answered) never counts against a relay.
  const own = new RelayHealth(); for (let k = 0; k < 20; k++) own.fetched(rec, [], rec, k * 86400);
  assert.deepEqual(own.counted(rec), rec);
  // blocked:/restricted: on three tries over 12 hours makes it fetch-only, retried for writes weekly; a timeout or a
  // passing refusal never counts (review 19 H4).
  const b = new RelayHealth();
  for (const t of [0, 6 * 3600, 13 * 3600]) b.published(new Map([['c', 'blocked: no']]), t);
  assert.deepEqual(b.writable(rec, 14 * 3600), ['a', 'b']); assert.deepEqual(b.counted(rec), rec, 'still fetched from');
  assert.deepEqual(b.writable(rec, 13 * 3600 + 7 * 86400), rec, 'weekly write retry');
  const w = new RelayHealth(); for (const r of ['publish timed out', 'rate-limited: slow down', 'auth-required: sign in', 'error: busy']) w.published(new Map([['c', r]]), 0);
  assert.deepEqual(w.writable(rec, 1), rec);
  // A relay that stays dead through 5-minute fetches is dropped after 7 days (review 19 H3).
  const dead = new RelayHealth();
  for (let t = 0; t <= 8 * 86400; t += 300) dead.fetched(rec, ['a', 'b'], rec, t);
  assert.deepEqual(dead.counted(rec), ['a', 'b']);
  assert.ok(majority(['a', 'b'], rec)); assert.ok(!majority(['a'], rec)); assert.ok(!majority([], []));
});

test('an end made on another device reaches the home at once, as a delivery: the site is revoked there', async () => {
  const { acc, A, B } = await two();
  const call = client(acc.bus);
  const u = new URL(A.nip46.mintBunker(['ws://relay.test'], 'coracle')), signer = u.hostname;
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  const entry = A.nip46.grants.get(signer)!.entry!;
  await A.grants.publish(); await B.grants.fetch();
  await B.signOut([{ by: A.kp.pub, id: entry }]);
  assert.equal(A.grants.own.has(entry), false, 'dropped on the home at once');
  assert.match((await call(signer, 'get_public_key')).error, /^revoked:/);
  // A sleeping home gets the same from its inbox.
  const e2 = A.grants.make(site('b')); await A.grants.publish(); await B.grants.fetch();
  acc.bus.kill(A.kp.pub); await B.signOut([{ by: A.kp.pub, id: e2.id }]); acc.bus.revive(A.kp.pub);
  assert.equal(A.grants.own.has(e2.id), true);
  await A.fetch();
  assert.equal(A.grants.own.has(e2.id), false, 'from the inbox');
});

test('sign out of every site: every grant everywhere ends, by a wildcard each home applies; later ones stay', async () => {
  const { acc, A, B } = await two();
  A.grants.make(site('a')); A.grants.make(site('b')); B.grants.make(site('c'));
  await A.grants.publish(); await B.grants.publish(); await B.grants.fetch();
  acc.bus.advance(5);
  await B.signOutEverywhere();
  assert.equal(B.grants.own.size, 0); assert.equal(A.grants.own.size, 0, 'the wildcard reached A');
  assert.equal(B.grants.all().length, 0, 'listed as ended');
  acc.bus.advance(200);                                   // past the wildcard's two minutes' clock slack
  const later = A.grants.make(site('d'));
  await A.grants.fetch();
  assert.equal(A.grants.own.has(later.id), true, 'made after the wildcard');
});

test('the grant event is re-encrypted after a redeal: published again under the new state', async () => {
  const { acc, A, B } = await two();
  A.grants.make(site('a')); await A.grants.publish();
  const before = A.grants.lastSent[0].tags.find((t) => t[0] === 'state')![1];
  { const r: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: A.kp.pub } }]; await A.submit(r, A.approveLock(r)); }
  await new Promise((r) => setTimeout(r, 1200));
  const after = A.grants.lastSent[0].tags.find((t) => t[0] === 'state')![1];
  assert.notEqual(after, before);
  assert.equal(after, A.dataKeys.current().state);
  void acc;
});

test('helper grants: the helper is the home; ends by signer key reach it; its report lists them; a wildcard ends them all', async () => {
  const { acc, A } = await two();
  const H = await addHelper(acc, A, (l) => A.approveLock(l));
  await H.fetch(); await A.fetch();
  const call = client(acc.bus);
  const bunker = await A.helperSite('bot', ['ws://relay.test']);
  const u = new URL(bunker), signer = u.hostname;
  const e = [...A.grants.own.values()].find((x) => x.helper)!;
  assert.equal(e.signer, signer);
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  assert.equal((await call(signer, 'get_public_key')).result, A.g, 'the helper answers');
  assert.match((await call(signer, 'nip44_encrypt', [A.g, 'x'])).error, /^unsupported:/);
  // The report reaches the devices.
  await H.helperReportNow(true); await A.fetch();
  assert.equal(A.helperReport?.grants[0].signer, signer);
  // Sign it out on A: the tombstone names the signer key, and the helper revokes it.
  await A.signOut([{ by: A.kp.pub, id: e.id }]);
  assert.match((await call(signer, 'get_public_key')).error, /^revoked:/);
  // A second helper site, then sign out of every site: the helper's wildcard ends it.
  const u2 = new URL(await A.helperSite('bot2', ['ws://relay.test'])), s2 = u2.hostname;
  assert.equal((await call(s2, 'connect', [s2, u2.searchParams.get('secret')!])).result, 'ack');
  acc.bus.advance(2);
  await A.signOutEverywhere();
  assert.match((await call(s2, 'get_public_key')).error, /^revoked:/);
});

test('the helper ends every grant whose asking device left', async () => {
  const { acc, A, B } = await two();
  const H = await addHelper(acc, A, (l) => A.approveLock(l));
  await H.fetch(); await B.fetch();
  const call = client(acc.bus);
  const u = new URL(await B.helperSite('bot', ['ws://relay.test'])), signer = u.hostname;
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  { const r: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: A.kp.pub } }]; await A.submit(r, A.approveLock(r)); }
  await H.fetch();
  assert.match((await call(signer, 'get_public_key')).error, /^revoked:/);
});
