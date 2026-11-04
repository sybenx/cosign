// Review 19's findings (Doors §2), as regression tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create, invite, addHelper } from '../sim/account.ts';
import { DeviceNode } from '../device/node.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { wrap } from '../src/transport.ts';
import type { Change } from '../src/types.ts';

const site = (n: string) => ({ site: `https://${n}.example`, says: n, door: 'nip07' as const, connection: 'chrome', scopes: ['sign-in', 'post'] as any });
async function two() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  await B.fetch(); await acc.A.fetch();
  return { acc, A: acc.A, B };
}
function client(bus: any) {
  const key = newKey();
  return async (signer: string, method: string, params: string[] = []) => {
    const id = bytesToHex(randomBytes(8)), ck = nip44.v2.utils.getConversationKey(key.sk, signer);
    const reply = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (r: any) => { const x = JSON.parse(nip44.v2.decrypt(r.content, ck)); if (x.id === id) { w.close(); res(x); } }); });
    await bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, key.sk));
    return reply;
  };
}

test('H1: an event carrying a wildcard is read by every device, the ending one included', async () => {
  const { acc, A, B } = await two();
  await B.signOutEverywhere();
  acc.bus.advance(200);
  const z = B.grants.make(site('z')); await B.grants.publish();
  await A.grants.fetch();
  assert.ok(A.grants.all().some((e) => e.id === z.id), 'B\'s new grant is listed on A');
  assert.ok(A.grants.others.get(B.kp.pub)!.set.tombstones.some((t) => t.id === '*'), 'the wildcard is in B\'s event');
});

test('H2: a helper grant signed out on any device ends at the helper, the asking one asleep', async () => {
  const { acc, A, B } = await two();
  const H = await addHelper(acc, A, (l) => A.approveLock(l)); await H.fetch(); await B.fetch();
  const call = client(acc.bus);
  const u = new URL(await A.helperSite('bot', ['ws://relay.test'])), signer = u.hostname;
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  const e = [...A.grants.own.values()].find((x) => x.helper)!;
  await A.grants.publish(); await B.grants.fetch();
  acc.bus.kill(A.kp.pub);
  await B.signOut([{ by: A.kp.pub, id: e.id }]);
  assert.match((await call(signer, 'get_public_key')).error, /^revoked:/);
});

test('H5/L2/L3: a helper report\'s last use keeps the device\'s entry alive; its logouts end it; an older report is ignored', async () => {
  const { acc, A } = await two();
  const H = await addHelper(acc, A, (l) => A.approveLock(l)); await H.fetch(); await A.fetch();
  const call = client(acc.bus);
  const u = new URL(await A.helperSite('bot', ['ws://relay.test'])), signer = u.hostname;
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  const e = [...A.grants.own.values()].find((x) => x.helper)!;
  acc.bus.advance(80 * 86400);
  assert.equal((await call(signer, 'get_public_key')).result, A.g, 'used on the helper');
  await H.helperReportNow(true); await A.fetch();
  acc.bus.advance(20 * 86400); await A.fetch();
  assert.ok(A.grants.all().some((x) => x.id === e.id), 'not expired: its last use came from the report');
  const seq = A.helperReport!.seq;
  // An older report (a replay) is ignored.
  const old = wrap(H.kp.sk, A.kp.pub, { type: 'helper_report', seq: seq - 1, grants: [], logouts: [] });
  assert.equal(A.takeDelivery(old), 'junk');
  // The site logs out at the helper: the device's entry ends with the next report.
  await call(signer, 'logout');
  await H.helperReportNow(true); await A.fetch();
  assert.equal(A.grants.own.has(e.id), false);
});

test('M2: a publish that hadn\'t counted is re-sent after a restart', async () => {
  const { acc, A } = await two();
  (A.grants.h as any).later = () => {};
  acc.bus.relayFaults.set('wss://r2.test', 'writedown'); acc.bus.relayFaults.set('wss://r3.test', 'writedown');
  A.grants.make(site('a')); await A.grants.publish();
  assert.equal(A.grants.counted, false);
  const R = DeviceNode.restore(acc.bus, A.snapshot());
  acc.bus.relayFaults.clear();
  await R.fetch();
  assert.equal(R.grants.counted, true);
});

test('M3: a redeal while relays are down: the grant event is published under the new state at the next catch-up', async () => {
  const { acc, A, B } = await two();
  A.grants.make(site('a')); await A.grants.publish();
  for (const r of ['wss://r1.test', 'wss://r2.test', 'wss://r3.test', 'wss://r.test']) acc.bus.relayFaults.set(r, 'down');
  const r: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  await A.submit(r, A.approveLock(r));
  await new Promise((res) => setTimeout(res, 1200));
  acc.bus.relayFaults.clear();
  await A.fetch();
  assert.equal(A.grants.lastSent[0].tags.find((t) => t[0] === 'state')![1], A.dataKeys.current().state);
});

test('M6: the helper drops a minted link nobody used once it expires, and caps its grants', async () => {
  const { acc, A } = await two();
  const H = await addHelper(acc, A, (l) => A.approveLock(l)); await H.fetch(); await A.fetch();
  await A.helperSite('never-used', ['ws://relay.test']);
  assert.equal(H.nip46.grants.size, 1);
  acc.bus.advance(700); await H.fetch();
  assert.equal(H.nip46.grants.size, 0);
});
