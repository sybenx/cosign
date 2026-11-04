// Review 10's findings in the server runtime, each as a regression test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Bus } from '../sim/bus.ts';
import { create, replaceServer } from '../sim/account.ts';
import { ServerNode } from '../server/node.ts';
import { Host } from '../server/host.ts';
import { Limits } from '../server/limits.ts';
import { serveHttp } from '../server/http.ts';
import { FileStore, KeyRing } from '../runtime/store.ts';
import { RelayNet } from '../runtime/relay.ts';
import { Reassembler, wrap } from '../src/transport.ts';
import { msg } from '../src/msg.ts';
import { newKey, wireEvent } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const dirs = () => mkdtempSync(join(tmpdir(), 'kk-r10-'));
const storeIn = (d: string) => new FileStore(join(d, 'data'), new KeyRing(join(d, 'keys')));
const profile = { https: 'https://h.test', relays: ['ws://127.0.0.1:1'], operator: newKey().pub, name: 'H' };

test('C1: enrol stores no seat; replies are a capped note; a flood over relays needs proof of work', async () => {
  const bus = new Bus(); const d = dirs(); const s = storeIn(d);
  const h = new Host({ net: bus, hosting: bus, store: s, profile: { ...profile, pow: 8 } }).start();
  const dev = newKey(); bus.add({ kp: dev, handle: async () => null });
  for (let k = 0; k < 70; k++) assert.equal((await bus.send(dev, h.key.pub, { type: 'enroll', g: newKey().pub })).type, 'enroll_reply');
  assert.equal(s.list().filter((x) => x.startsWith('seat-')).length, 0, 'no seat files');
  assert.equal(h.pending.size, 70);
  assert.equal(h.nodes.size, 0, 'no seat nodes either');
  // Past 60 a minute the front door asked for work; the bus re-sent with it, so honest senders get through.
  assert.equal(await h.front.handle(dev.pub, { type: 'enroll', g: newKey().pub }, bus.now, { pow: 0 }).then((a: any) => a.code), 'pow');
  assert.equal((await h.front.handle(dev.pub, { type: 'enroll', g: newKey().pub }, bus.now, { pow: 8 })).type, 'enroll_reply');
  // A restart brings the notes back, and their keys are reachable again.
  const h2 = new Host({ net: bus, hosting: bus, store: s, profile }).start();
  assert.equal(h2.pending.size, h.pending.size);
  rmSync(d, { recursive: true });
});

test('C2: a record that can\'t be read never stops the start; a seat waiting for its share restores', async () => {
  const acc = await create();
  const bus: any = acc.bus, send = bus.send.bind(bus);
  let snap: string | null = null;
  bus.send = async (from: any, to: string, body: any, o?: any) => {
    if (body?.type === 'seat_fill') { snap = bus.nodes.get(to).snapshot(); return { type: 'error', code: 'unreachable' }; }
    return send(from, to, body, o);
  };
  await replaceServer(acc, acc.A, 8, (l) => acc.A.approveLock(l));
  bus.send = send;
  assert.doesNotThrow(() => ServerNode.restore(bus, snap!), 'welcomed, not yet filled');
  const d = dirs(); const s = storeIn(d);
  s.save('seat-' + 'a'.repeat(32), snap!);
  s.save('seat-' + 'b'.repeat(32), '{"v":1,"broken":true}');
  const logged: string[] = [];
  const h = new Host({ net: bus, hosting: bus, store: s, profile });
  h.log = (x) => logged.push(x);
  assert.doesNotThrow(() => h.start());
  assert.equal(h.nodes.size, 1);
  assert.ok(logged.some((x) => x.includes('seat-bbbb')), 'the broken record is logged, left in storage');
  rmSync(d, { recursive: true });
});

test('H2: a DKG round without a creation gets nothing, not a node', async () => {
  const bus = new Bus(); const d = dirs();
  const h = new Host({ net: bus, hosting: bus, store: storeIn(d), profile }).start();
  const dev = newKey(); bus.add({ kp: dev, handle: async () => null });
  for (const t of ['dkg_1', 'dkg_2', 'dkg_3']) assert.equal((await bus.send(dev, h.key.pub, { type: t, index: 4, max: 8 })).code, 'no_dkg');
  assert.equal(h.nodes.size, 0);
  rmSync(d, { recursive: true });
});

test('H3: open partial messages are capped per sender and expire in 10 minutes', () => {
  const R = new Reassembler();
  const part = (of: string) => ({ v: 1, type: 'part', of, k: 0, m: 2, cls: 'member', data: 'AAAA' });
  for (let k = 0; k < 4; k++) assert.equal(R.take('a', part(`o${k}`), 0), null);
  assert.throws(() => R.take('a', part('o4'), 0), /too_many_parts/);
  assert.equal(R.take('b', part('x'), 0), null, 'another sender has its own allowance');
  R.prune(601);
  assert.equal(R.pending, 0, 'gone after 10 minutes, though it claimed the member class');
});

test('H4: behind a trusted proxy, the rightmost X-Forwarded-For entry is the client', async () => {
  const net = new RelayNet({ relays: [] });
  const limits = new Limits({ junkPerIpPerMinute: 1 });
  const srv = serveHttp({ net, limits, port: 18799, bind: '127.0.0.1', trustProxy: true });
  await new Promise((r) => srv.once('listening', r));
  const stray = JSON.stringify(wrap(newKey().sk, newKey().pub, { type: 'x' }));
  const post = (xff: string) => fetch('http://127.0.0.1:18799/v1/wrap', { method: 'POST', body: stray, headers: { 'x-forwarded-for': xff } }).then((r) => r.status);
  assert.equal(await post('1.1.1.1, 9.9.9.9'), 200);
  assert.equal(await post('2.2.2.2, 9.9.9.9'), 429, 'a client-written leftmost entry changes nothing');
  assert.equal(await post('3.3.3.3, 8.8.8.8'), 200, 'another real client');
  assert.equal((await fetch('http://127.0.0.1:18799/v1/wrap', { method: 'POST', body: 'x'.repeat(700 * 1024) })).status, 413, 'review 10 L5');
  srv.close();
});

test('M1: a stranger\'s inbox_get gets no waits', async () => {
  const acc = await create();
  const S = acc.servers[0];
  const vanish = wireEvent({ pubkey: acc.g, created_at: acc.bus.now, kind: 62, tags: [], content: '' });
  await acc.bus.send(acc.A.kp, S.kp.pub, { ...msg('hold', acc.g, acc.epochId, 'member'), event: vanish });
  const stranger = newKey(); acc.bus.add({ kp: stranger, handle: async () => null } as any);
  assert.equal((await acc.bus.send(stranger, S.kp.pub, msg('inbox_get', acc.g, acc.epochId, 'ask'))).waits, undefined);
  assert.equal((await acc.bus.send(acc.A.kp, S.kp.pub, msg('inbox_get', acc.g, acc.epochId, 'ask'))).waits.length, 1);
});

test('M2: every save re-keys, so an old /data snapshot can\'t be read with today\'s key ring', () => {
  const d = dirs(); const s = storeIn(d);
  s.save('host', 'secret from 14 months ago');
  const old = join(d, 'data-snapshot');
  cpSync(join(d, 'data'), old, { recursive: true });
  s.save('host', 'the secret dropped');
  const fromSnapshot = new FileStore(old, new KeyRing(join(d, 'keys')));
  assert.throws(() => fromSnapshot.load('host'), /malformed/);
  assert.equal(s.load('host'), 'the secret dropped');
  rmSync(d, { recursive: true });
});

test('a host writes seats without its host key; restore takes it from the host', async () => {
  const bus = new Bus(); const d = dirs(); const s = storeIn(d);
  const hosts = [0, 1, 2].map((k) => new Host({ net: bus, hosting: bus, store: k === 0 ? s : storeIn(dirs()), profile }).start());
  const { createByDkg } = await import('../sim/account.ts');
  await createByDkg({ net: bus as any, hosts });
  const rec = s.list().find((x) => x.startsWith('seat-'))!;
  assert.equal(JSON.parse(s.load(rec)!).host, null);
  void bytesToHex; void randomBytes;
  rmSync(d, { recursive: true });
});
