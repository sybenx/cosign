// Review 9's findings, each as a regression test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { create, invite, restartServer } from '../sim/account.ts';
import { FileStore, KeyRing } from '../runtime/store.ts';
import { msg, DeviceNode, ServerNode } from '../sim/nodes.ts';
import { newKey, wireEvent, verifyEvent } from '../src/event.ts';
import { bytesToHex, randomBytes, b64u, utf8ToBytes } from '../src/bytes.ts';
import { F1Watch, signAnswer } from '../src/f1.ts';
import { encryptPush } from '../src/webpush.ts';
import { TRANSPORT_FAILED, unreachable } from '../sim/bus.ts';
import { p256 } from '@noble/curves/nist.js';

const store = () => { const d = mkdtempSync(join(tmpdir(), 'r9-')); return new FileStore(join(d, 'data'), new KeyRing(join(d, 'keys'))); };

test('H1: a server that took a delete keeps only the tombstone and its keys, in memory and on disk', async () => {
  const acc = await create();
  await acc.A.newPaper((l) => acc.A.approveLock(l), { heir: newKey().pub });
  await acc.A.registerPush();
  await acc.A.deleteAccount();
  const S = acc.servers[1];
  assert.equal(S.co, null);
  assert.equal(S.pushReg.get(acc.A.kp.pub), null);
  const snap = JSON.parse(S.snapshot());
  assert.deepEqual(Object.keys(snap).sort(), ['enrolSecret', 'host', 'kp', 'name', 'tombstone', 'v']);
  const back = restartServer(acc, 1, store());
  assert.ok(back.tombstone && back.co === null);
  assert.equal((await acc.bus.send(acc.A.kp, back.kp.pub, msg('state_get', acc.g, acc.epochId, 'ask'))).type, 'deleted');
});

test('H2: a device that deleted its account keeps only the request, the first deleted and the endpoints', async () => {
  const acc = await create({ lockless: true });
  assert.ok(acc.A.keptSecret);
  await acc.A.registerPush();
  assert.equal(await acc.A.deleteAccount({ paper: acc.paper }), 3);
  assert.ok(acc.A.wiped && !acc.A.keptSecret && acc.A.pushKeys.size === 0);
  const x = JSON.parse(acc.A.snapshot());
  assert.deepEqual(Object.keys(x).sort(), ['deleted', 'name', 'v', 'wiped']);
  assert.deepEqual(Object.keys(x.deleted).sort(), ['endpoints', 'first', 'request']);
  assert.equal(x.deleted.endpoints.length, 3);
  const d = DeviceNode.restore(acc.bus, acc.A.snapshot());
  assert.ok(d.wiped && d.deleted && !d.keptSecret);
});

test('M1: a running heir wait survives a restart', async () => {
  const acc = await create();
  const heir = newKey();
  const K = await acc.A.newPaper((l) => acc.A.approveLock(l), { heir: heir.pub });
  const S = acc.servers[0];
  const ch = await acc.bus.send(heir, S.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
  const n = await acc.bus.send(heir, S.kp.pub, msg('heir_request', acc.g, acc.epochId, 'member', { set: K.pub, request: bytesToHex(randomBytes(16)), challenge: ch.challenge }));
  assert.equal(n.kind, 'heir');
  const R = restartServer(acc, 0, store());
  assert.equal(R.co!.heirWaits.size, 1);
  assert.equal((await acc.bus.send(acc.A.kp, R.kp.pub, msg('cancel', acc.g, acc.epochId, 'member', { wait: n.wait }))).type, 'notice', 'the owner can still cancel it');
});

test('M2: an off-curve p256dh is refused at registration; a failing push never replaces an answer', async () => {
  const acc = await create();
  const S = acc.servers[0];
  const bad = new Uint8Array(65); bad[0] = 4; bad[1] = 1;
  const addresses = ['sign', 'ask', 'notice'].map((cls) => ({ cls, url: 'https://gw.test/' + cls, p256dh: b64u(bad), auth: b64u(randomBytes(16)) }));
  assert.equal((await acc.bus.send(acc.A.kp, S.kp.pub, msg('push_register', acc.g, acc.epochId, 'member', { addresses }))).code, 'malformed');
  // Even if a bad address got in, the hold still answers.
  (S.pushReg as any).load([[acc.A.kp.pub, { at: 0, addrs: addresses }]]);
  const vanish = wireEvent({ pubkey: acc.g, created_at: acc.bus.now, kind: 62, tags: [], content: '' });
  assert.equal((await acc.bus.send(acc.A.kp, S.kp.pub, { ...msg('hold', acc.g, acc.epochId, 'member'), event: vanish })).kind, 'hold');
});

test('M4: the transport\'s own timeout counts as silence for §6.7.9; a sealed error never does', async () => {
  const acc = await create();
  const first = acc.A.servers()[0];
  const S = acc.servers.find((x) => x.kp.pub === first.key)!;
  const bus = acc.bus as any, send = bus.send.bind(bus);
  bus.send = async (from: any, to: string, body: any) => (to === S.kp.pub && body.type === 'sign' ? unreachable() : send(from, to, body));
  for (const d of [0, 0, 1]) { acc.bus.advance(d * 86400 + 60); assert.ok(verifyEvent(await acc.A.sign({ content: `d${d}` }))); }
  assert.deepEqual(acc.A.notHelping(), [S.host.pub]);
  // A server can't forge the marker: what it seals arrives as JSON.
  assert.equal(JSON.parse(JSON.stringify(unreachable()))[TRANSPORT_FAILED], undefined);
  bus.send = send;
});

test('L1: a new member key for a host drops the answer kept for the old seat', () => {
  const host = newKey(), k1 = newKey().pub, k2 = newKey().pub, g = newKey().pub, now = 1_800_000_000;
  const w = new F1Watch(g);
  w.seat(host.pub, k1, now);
  w.asked(host.pub, 'aa'.repeat(16), now);
  assert.ok(w.answer(signAnswer(g, host, { shutdown: now + 10 * 86400, seq: now, member: k1 }, 'aa'.repeat(16)), k1, now));
  w.seat(host.pub, k2, now + 60);
  assert.equal(w.dead(host.pub, now + 60), null);
});

test('L2: a removed member\'s push addresses are dropped', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  await B.registerPush();
  const S = acc.servers[0];
  assert.equal(S.pushReg.get(B.kp.pub)!.length, 3);
  const list: any[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  assert.ok(S.co!.m.removed.has(B.kp.pub));
  assert.equal(S.pushTo(B.kp.pub, 'ask', 'aa'.repeat(16)), false);
  assert.equal(S.pushReg.get(B.kp.pub), null);
});

test('L4: RFC 8291 §4, a record exactly rs long is refused both ways', () => {
  const sk = p256.utils.randomSecretKey();
  const to = { p256dh: b64u(p256.getPublicKey(sk, false)), auth: b64u(randomBytes(16)) };
  assert.throws(() => encryptPush(new Uint8Array(4079), to), /one record/);
  assert.doesNotThrow(() => encryptPush(new Uint8Array(4078), to));
});

test('L7: a server snapshot whose seat key is not the seat\'s is refused on restore', async () => {
  const acc = await create();
  const x = JSON.parse(acc.servers[0].snapshot());
  const y = JSON.parse(acc.servers[1].snapshot());
  x.kp = y.kp;
  assert.throws(() => ServerNode.restore(acc.bus, JSON.stringify(x)), /not_member|share/);
  void utf8ToBytes;
});
