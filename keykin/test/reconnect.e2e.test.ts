// Review 10 H1: a relay that goes away and comes back is reconnected and re-subscribed; one that is
// down at the start doesn't stop it. A local `nak serve` relay only.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { RelayNet } from '../runtime/relay.ts';
import { newKey } from '../src/event.ts';

const haveNak = spawnSync('nak', ['--version']).status === 0;
const port = 17231, url = `ws://127.0.0.1:${port}`;
let relay: ChildProcess | undefined; const nets: RelayNet[] = [];
after(() => { nets.forEach((n) => n.close()); relay?.kill(); });
const start = () => { relay = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' }); return new Promise((r) => setTimeout(r, 1200)); };
const until = async (f: () => boolean, ms = 15000) => { const t = Date.now(); while (!f() && Date.now() - t < ms) await new Promise((r) => setTimeout(r, 200)); return f(); };

test('a relay down at the start, then up, then restarted: reconnected and re-subscribed each time', { skip: !haveNak && 'nak not installed', timeout: 60_000 }, async () => {
  const a = new RelayNet({ relays: [url], timeoutMs: 6000, resendMs: 800 }), b = new RelayNet({ relays: [url], timeoutMs: 6000, resendMs: 800 });
  nets.push(a, b);
  await a.connect(); await b.connect();                     // nothing listening yet: no throw
  assert.deepEqual(a.status(), [{ url, up: false }]);
  const ka = newKey(), kb = newKey();
  a.add({ kp: ka, handle: async () => null });
  b.add({ kp: kb, handle: async (_f: string, body: any) => ({ type: 'pong', n: body.n }) });
  await start();
  assert.ok(await until(() => a.status()[0].up && b.status()[0].up), 'both connected once the relay came up');
  assert.equal((await a.send(ka, kb.pub, { type: 'ping', n: 1 })).type, 'pong');
  relay!.kill(); await new Promise((r) => relay!.once('exit', r));
  assert.ok(await until(() => !a.status()[0].up), 'noticed the drop');
  await start();
  assert.ok(await until(() => a.status()[0].up && b.status()[0].up), 'reconnected');
  assert.equal((await a.send(ka, kb.pub, { type: 'ping', n: 2 })).n, 2, 're-subscribed: the message gets through');
});
