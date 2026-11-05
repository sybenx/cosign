// Task step 3: the same nodes over real relays: two local `nak serve` relays, nothing else.
// Skipped when nak isn't installed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { RelayNet } from '../runtime/relay.ts';
import { create, invite, replaceServer } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const haveNak = spawnSync('nak', ['--version']).status === 0;
const ports = [17111, 17112];
let relays: ChildProcess[] = [];
let net: RelayNet;

before(async () => {
  if (!haveNak) return;
  relays = ports.map((p) => spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(p)], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1200));
  net = new RelayNet({ relays: ports.map((p) => `ws://127.0.0.1:${p}`), timeoutMs: 7000, resendMs: 1500, log: process.env.KK_LOG ? (s) => console.log(Date.now() % 100000, s) : undefined });
  await net.connect();
});
after(() => { net?.close(); relays.forEach((r) => r.kill()); });

test('over relays: create, sign, add a device, report it lost, replace a dead server', { skip: !haveNak && 'nak not installed', timeout: 180_000 }, async () => {
  const acc = await create({ net: net as any, relays: ports.map((p) => `ws://127.0.0.1:${p}`) });
  const e = await acc.A.sign({ content: 'gm over relays' });
  assert.ok(verifyEvent(e));
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.ok(verifyEvent(await B.sign({ content: 'B over relays' })));
  const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  assert.equal(acc.A.state!.ids.size, 1);
  for (const s of acc.servers) assert.equal(s.co!.state.ids.size, 1);
  await assert.rejects(B.sign({ content: 'thief' }), /removed|stale/);
  net.kill(acc.servers[2].kp.pub);
  const Y = await replaceServer(acc, acc.A, 8, (l) => acc.A.approveLock(l));
  assert.equal(Y.co!.state.ids.size, 2);
  net.kill(acc.servers[0].kp.pub); net.kill(acc.servers[1].kp.pub);
  assert.ok(verifyEvent(await acc.A.sign({ content: 'via the new server Y' })));
});
