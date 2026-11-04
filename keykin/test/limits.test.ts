// Server profile §3's limits, and the push sender's allowlist and 404/410 handling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Limits, powBits } from '../server/limits.ts';
import { PushSender } from '../server/push.ts';

test('Server profile §3: per key for members, per IP for newcomers, never-counted types never counted', () => {
  const L = new Limits({ memberPerKeyPerMinute: 3, newcomerPerIpPerMinute: 2, creationsPerIpPerDay: 1, creationsPerHour: 2, junkPerIpPerMinute: 1 });
  for (let k = 0; k < 3; k++) assert.ok(L.member('a', 'sign', 0));
  assert.ok(!L.member('a', 'sign', 1), 'the fourth in a minute');
  assert.ok(L.member('b', 'sign', 1), 'another key has its own count: a thief can\'t use up the owner\'s');
  for (const t of ['cancel', 'withdraw', 'change', 'changes_get', 'upload', 'upload_held', 'inbox_get', 'inbox_ack']) assert.ok(L.member('a', t, 2), t);
  assert.ok(!L.member('a', 'challenge', 2) && L.member('a', 'challenge', 2, true), 'challenge is free only from the backup key');
  assert.ok(L.member('a', 'sign', 61), 'a minute later');
  assert.ok(L.newcomer(0, '1.1.1.1') && L.newcomer(0, '1.1.1.1') && !L.newcomer(0, '1.1.1.1'));
  assert.ok(L.newcomer(0), 'over relays, never refused per account or IP');
  assert.ok(L.creation(0, 'x') && !L.creation(0, 'x'), 'one per IP per day');
  assert.ok(L.creation(0, 'y') && !L.creation(0, 'z'), 'and the server-wide hourly cap');
  assert.ok(L.junk('j', 0) && !L.junk('j', 0));
  assert.ok(L.push('u', 0, true) && L.push('u', 0, true), 'wait notices always');
  assert.equal(powBits('000f' + 'f'.repeat(60)), 12);
  assert.equal(powBits('8' + '0'.repeat(63)), 0);
  assert.equal(powBits('1' + '0'.repeat(63)), 3);
});

test('PushSender: only allowed hosts; an address answering 410 is dropped', async () => {
  const calls: string[] = []; const gone: string[] = [];
  const fake = (async (url: any) => { calls.push(String(url)); return { status: String(url).includes('dead') ? 410 : 201 }; }) as any;
  const P = new PushSender({ allow: ['gw.example', '127.0.0.1:9999'], onGone: (u) => gone.push(u), fetch: fake });
  const p = (url: string) => ({ url, authorization: 'vapid t=x, k=y', body: new Uint8Array(10), at: 0 });
  P.push(p('https://gw.example/a')); P.push(p('https://evil.example/a')); P.push(p('http://gw.example/a')); P.push(p('http://127.0.0.1:9999/a')); P.push(p('https://gw.example/dead'));
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(calls, ['https://gw.example/a', 'http://127.0.0.1:9999/a', 'https://gw.example/dead']);
  assert.equal(P.refused, 2);
  assert.deepEqual(gone, ['https://gw.example/dead']);
});
