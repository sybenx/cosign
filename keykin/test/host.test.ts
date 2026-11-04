// server/host.ts: one server process, a front door at the host key, a seat node per account, sealed
// storage, restarts. Over the in-memory Bus; the Docker e2e runs the same over relays.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Bus } from '../sim/bus.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { Host } from '../server/host.ts';
import { FileStore, KeyRing } from '../runtime/store.ts';
import { verifyEvent, newKey } from '../src/event.ts';

const stores = () => [0, 1, 2].map(() => { const d = mkdtempSync(join(tmpdir(), 'kk-host-')); return new FileStore(join(d, 'data'), new KeyRing(join(d, 'keys'))); });
const profile = (k: number) => ({ https: `https://h${k}.test`, relays: ['ws://127.0.0.1:1'], operator: newKey().pub, name: `H${k}` });

test('Host: an account created by DKG through three front doors; restarts from sealed storage; it goes on', async () => {
  const bus = new Bus();
  const st = stores(), pr = [0, 1, 2].map(profile);
  let hosts = [0, 1, 2].map((k) => new Host({ net: bus, hosting: bus, store: st[k], profile: pr[k] }).start());
  const acc = await createByDkg({ net: bus as any, hosts });
  assert.ok(verifyEvent(await acc.A.sign({ content: 'through the front door' })));
  for (const [k, h] of hosts.entries()) {
    assert.equal(h.nodes.size, 1, 'one seat for one account');
    const e = acc.A.m!.members.get([...h.nodes.keys()][0])!;
    assert.equal(e.host, h.key.pub);
    assert.equal(e.https, pr[k].https);
  }
  // Every host restarts: same host keys, seats rebuilt from storage, nothing else carried.
  const keys = hosts.map((h) => h.key.pub);
  hosts = [0, 1, 2].map((k) => new Host({ net: bus, hosting: bus, store: st[k], profile: pr[k] }).start());
  assert.deepEqual(hosts.map((h) => h.key.pub), keys);
  acc.servers = hosts.map((h) => [...h.nodes.values()][0]);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'after every host restarted' })));
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.ok(verifyEvent(await B.sign({ content: 'B, joined after the restart' })));
});

test('Host: enrol secrets by month, destroyed after 13 months; the front door takes only creation and enrolment', async () => {
  const bus = new Bus();
  const [s] = stores();
  const h = new Host({ net: bus, hosting: bus, store: s, profile: profile(0) }).start();
  const a = h.secret();
  bus.advance(40 * 86400);
  const b = h.secret();
  assert.notEqual(a.id, b.id);
  assert.equal(h.secrets.length, 2);
  bus.advance(14 * 31 * 86400);
  h.secret();
  assert.ok(!h.secrets.some((x) => x.id === a.id), 'the old secret is gone');
  const dev = newKey();
  bus.add({ kp: dev, handle: async () => null });
  assert.equal((await bus.send(dev, h.key.pub, { type: 'sign' })).code, 'unsupported');
  const r = await bus.send(dev, h.key.pub, { type: 'enroll', g: newKey().pub });
  assert.equal(r.type, 'enroll_reply');
  assert.equal(r.reply.secret_id, h.secret().id);
  assert.ok(h.nodes.has(r.reply.member_key), 'the enrolled seat is hosted at its member key');
});
