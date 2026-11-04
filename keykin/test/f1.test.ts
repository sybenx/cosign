// Core §6.7.7: when a device counts a seated server as dead and shows the F1 card. Quiet for 7 days; a
// host-signed shutdown notice; or a day of `deleted` that doesn't verify, or "unknown account", while
// its peers serve the account. A `deleted` that verifies destroys the device's copy instead.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, replaceServer } from '../sim/account.ts';
import { verifyEvent, schnorrSign } from '../src/event.ts';
import { msg } from '../sim/nodes.ts';
import { signNotice, signAnswer, signRefusal, checkRefusal, F1Watch } from '../src/f1.ts';
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

test('Server profile §4.1 (draft 8): only the live answer to notice_get counts; a pushed notice only prompts it', async () => {
  const acc = await create();
  const S = acc.servers[1];
  await acc.A.checkServers();
  // A server closing in 40 days: shown on Backup, no card yet; within 30 days, the card.
  await S.announceShutdown(acc.bus.now + 40 * 86400);
  assert.deepEqual(await acc.A.checkServers(), []);
  assert.equal(acc.A.f1().closing(S.host.pub), acc.bus.now + 40 * 86400, 'the date is known from the answer');
  acc.bus.advance(11 * 86400);
  assert.deepEqual((await acc.A.checkServers())!.map((c) => [c.host, c.why]), [[S.host.pub, 'shutdown']]);
  // Cancelled: the next answer removes the card.
  await S.announceShutdown(null);
  assert.deepEqual(await acc.A.checkServers(), []);
});

test('Server profile §4.1: a pushed notice alone never counts; answers only for the request asked, sealed by the seat', async () => {
  const acc = await create();
  const S = acc.servers[1], other = acc.servers[2];
  await acc.A.checkServers();
  const w = acc.A.f1();
  const n = signNotice(acc.g, S.host, { shutdown: acc.bus.now, seq: acc.bus.now + 5, member: S.kp.pub });
  // Pushed: a reason to ask, at most once an hour; never a card by itself.
  assert.equal(w.pushed(n, acc.bus.now + 3601), true);
  assert.equal(w.pushed({ ...n, host_sig: '00'.repeat(64) }, acc.bus.now + 3601), false);
  assert.equal(w.pushed({ ...n, member: other.kp.pub }, acc.bus.now + 3601), false, 'signed for another seat');
  assert.equal(w.dead(S.host.pub, acc.bus.now), null);
  // An answer: only to the outstanding request, only sealed by that seat, only with the answer signature.
  w.asked(S.host.pub, 'aa'.repeat(16), acc.bus.now);
  const ans = signAnswer(acc.g, S.host, { shutdown: acc.bus.now, seq: acc.bus.now + 5, member: S.kp.pub }, 'aa'.repeat(16));
  assert.equal(w.answer({ ...n, re: 'aa'.repeat(16) }, S.kp.pub, acc.bus.now), false, 'an old notice sealed as an answer');
  assert.equal(w.answer(signAnswer(acc.g, S.host, { shutdown: acc.bus.now, seq: 9, member: S.kp.pub }, 'bb'.repeat(16)), S.kp.pub, acc.bus.now), false, 'another request');
  assert.equal(w.answer(ans, other.kp.pub, acc.bus.now), false, 'sealed by another seat');
  assert.equal(w.answer(ans, S.kp.pub, acc.bus.now + 151), false, 'after the request\'s lifetime');
  assert.equal(w.answer(ans, S.kp.pub, acc.bus.now), true);
  assert.equal(w.dead(S.host.pub, acc.bus.now), 'shutdown');
  assert.equal(w.answer(signAnswer(acc.g, S.host, { shutdown: null, seq: 3, member: S.kp.pub }, 'aa'.repeat(16)), S.kp.pub, acc.bus.now), false, 'a lower seq for the same request');
  // A non-member can't ask.
  assert.equal((await acc.bus.send(newKey(), S.kp.pub, msg('notice_get', acc.g, acc.epochId, 'ask'))).code, 'not_member');
});

test('Server profile §4.1: host-signed refusals of enroll are checked, and only for the enroll asked', () => {
  const g = newKey().pub, host = newKey();
  const r = signRefusal(g, host, 'cc'.repeat(16), 'refused: closing');
  assert.ok(checkRefusal(g, r, host.pub, 'cc'.repeat(16)));
  assert.ok(!checkRefusal(g, r, host.pub, 'dd'.repeat(16)), 'another enroll');
  assert.ok(!checkRefusal(g, r, newKey().pub, 'cc'.repeat(16)), 'another host');
  assert.ok(!checkRefusal(g, { ...r, code: 'refused: expired' }, host.pub, 'cc'.repeat(16)), 'no such code');
});

test('F1Watch: a denial counts only while a peer serves; every server denying is not one server dead', () => {
  const g = newKey().pub;
  const w = new F1Watch(g);
  for (const h of ['a', 'b', 'c']) w.seat(h, `k${h}`, 0);
  for (const h of ['a', 'b', 'c']) w.saw(h, 'denied', 10);
  for (const h of ['a', 'b', 'c']) w.saw(h, 'denied', 86500);
  assert.equal(w.dead('a', 86500), null, 'nobody serves: not a denial');
  for (const h of ['a', 'b', 'c']) w.saw(h, 'denied', 7 * 86400);
  assert.equal(w.dead('a', 7 * 86400 + 10), null, 'answering, even denying, is not quiet (review 8 M2)');
  assert.equal(w.dead('a', 14 * 86400 + 20), 'quiet', 'silence is');
  const v = new F1Watch(g);
  for (const h of ['a', 'b']) v.seat(h, `k${h}`, 0);
  v.saw('a', 'denied', 10); v.saw('b', 'serving', 10);
  assert.equal(v.dead('a', 86420), null, 'the peer served only before the day passed');
  v.saw('b', 'serving', 86420);
  assert.equal(v.dead('a', 86420), 'denied');
  v.saw('a', 'serving', 86430);
  assert.equal(v.dead('a', 86430), null, 'serving again clears it');
});

test('review 8 M3: being seated is not serving', async () => {
  const g = newKey().pub;
  const w = new F1Watch(g);
  w.seat('a', 'ka', 0); w.saw('a', 'denied', 0);
  w.seat('d', 'kd', 86405);
  assert.equal(w.dead('a', 86410), null, 'a silent newcomer is no peer serving');
  // Review 8 M4 (a replayed notice) is now draft 8's rule: only a live answer counts (tests above).
});
