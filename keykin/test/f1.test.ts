// Core §6.7.7: when a device counts a seated server as dead and shows the F1 card. Quiet for 7 days; a
// host-signed shutdown notice; or a day of `deleted` that doesn't verify, or "unknown account", while
// its peers serve the account. A `deleted` that verifies destroys the device's copy instead.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, replaceServer } from '../sim/account.ts';
import { verifyEvent, schnorrSign } from '../src/event.ts';
import { msg } from '../sim/nodes.ts';
import { signShutdown, F1Watch } from '../src/f1.ts';
import { deletedDigest } from '../src/requests.ts';
import { newKey } from '../src/event.ts';

const seatOf = (acc: any, i: number) => `server:${acc.servers[i].co!.myIndices[0]}`;

test('F1: a server answering "unknown account" for a day while its peers serve brings the card; the seat moves', async () => {
  const acc = await create();
  const S2 = acc.servers[2];
  S2.co = null as any;                                // it lost or dropped the account
  assert.deepEqual(await acc.A.checkServers(), [], 'not on the first denial');
  acc.bus.advance(86400 - 60);
  assert.deepEqual(await acc.A.checkServers(), [], 'not before a day');
  acc.bus.advance(120);
  const card = (await acc.A.checkServers())!;
  assert.deepEqual(card.map((c) => [c.host, c.why]), [[S2.host.pub, 'denied']]);
  const idx = Number(card[0].seat.split(':')[1]);
  await replaceServer(acc, acc.A, idx, (l) => acc.A.approveLock(l));
  assert.deepEqual(await acc.A.checkServers(), [], 'the new server serves');
  assert.ok(verifyEvent(await acc.A.sign({ content: 'after the move' })));
});

test('F1: a forged `deleted` counts as a denial, never as a delete; a genuine one destroys the copy', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const S1 = acc.servers[1];
  // S1 answers a host-signed `deleted` whose request carries no valid approval.
  const request = { ...msg('account_delete', acc.g, acc.epochId, 'member', {}), approval: { lock: { member: acc.A.kp.pub, assertion: { authData: '', clientData: '', sig: '' } } } };
  const real = S1.handle.bind(S1);
  S1.handle = async (from: string, body: any, at: number) => body.type === 'state_get'
    ? { type: 'deleted', request, changes: [], host: S1.host.pub, host_sig: schnorrSign(deletedDigest(acc.g, request), S1.host.sk) } : real(from, body, at);
  await B.checkServers();
  acc.bus.advance(86400 + 1);
  const card = (await B.checkServers())!;
  assert.ok(!B.wiped, 'a forged deleted deletes nothing');
  assert.deepEqual(card.map((c) => [c.host, c.why]), [[S1.host.pub, 'denied']]);
  S1.handle = real;
  // A genuine delete by A: B checks the proof and destroys its copy.
  await acc.A.deleteAccount();
  assert.equal(await B.checkServers(), null);
  assert.ok(B.wiped);
});

test('F1: quiet for 7 days; a peer down for less is not dead', async () => {
  const acc = await create();
  assert.deepEqual(await acc.A.checkServers(), [], 'the device counts quiet from what it has seen');
  acc.bus.kill(acc.servers[0].kp.pub);
  acc.bus.advance(6 * 86400);
  assert.deepEqual(await acc.A.checkServers(), []);
  acc.bus.advance(86400);
  assert.deepEqual((await acc.A.checkServers())!.map((c) => [c.seat, c.why]), [[seatOf(acc, 0), 'quiet']]);
});

test('Server profile §5: a host-signed shutdown notice counts as dead; a later seq cancels; others are ignored', async () => {
  const acc = await create();
  const S = acc.servers[1];
  await acc.A.checkServers();
  const send = (n: any) => acc.bus.send(S.kp, acc.A.kp.pub, n);
  await send({ ...signShutdown(acc.g, S.host, acc.bus.now + 30 * 86400, 1), host_sig: '00'.repeat(64) });
  assert.deepEqual(await acc.A.checkServers(), [], 'a bad signature is ignored');
  await send({ ...signShutdown(acc.g, newKey(), acc.bus.now + 30 * 86400, 1), host: S.host.pub });
  assert.deepEqual(await acc.A.checkServers(), [], 'another key\'s signature is ignored');
  await send(signShutdown(acc.g, S.host, acc.bus.now + 30 * 86400, 1));
  assert.deepEqual((await acc.A.checkServers())!.map((c) => [c.host, c.why]), [[S.host.pub, 'shutdown']]);
  await send(signShutdown(acc.g, S.host, null, 2));
  assert.deepEqual(await acc.A.checkServers(), [], 'cancelled by a higher seq');
  await send(signShutdown(acc.g, S.host, acc.bus.now + 30 * 86400, 2));
  assert.deepEqual(await acc.A.checkServers(), [], 'the same seq again is ignored');
  await send(signShutdown(acc.g, S.host, acc.bus.now + 40 * 86400, 3));
  assert.equal((await acc.A.checkServers())!.length, 1);
});

test('F1Watch: a denial counts only while a peer serves; every server denying is not one server dead', () => {
  const g = newKey().pub;
  const w = new F1Watch(g);
  for (const h of ['a', 'b', 'c']) w.seat(h, 0);
  for (const h of ['a', 'b', 'c']) w.saw(h, 'denied', 10);
  for (const h of ['a', 'b', 'c']) w.saw(h, 'denied', 86500);
  assert.equal(w.dead('a', 86500), null, 'nobody serves: not a denial (quiet comes after 7 days)');
  assert.equal(w.dead('a', 7 * 86400), 'quiet');
  const v = new F1Watch(g);
  for (const h of ['a', 'b']) v.seat(h, 0);
  v.saw('a', 'denied', 10); v.saw('b', 'serving', 10);
  assert.equal(v.dead('a', 86420), null, 'the peer served only before the day passed');
  v.saw('b', 'serving', 86420);
  assert.equal(v.dead('a', 86420), 'denied');
  v.saw('a', 'serving', 86430);
  assert.equal(v.dead('a', 86430), null, 'serving again clears it');
});
