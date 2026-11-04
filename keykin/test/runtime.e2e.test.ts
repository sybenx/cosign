// Step A: the server runtime as real processes. Two local `nak serve` relays, three `server/main.ts`
// processes with sealed storage, and a device in this process over the relays. Local only.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg } from '../sim/account.ts';
import { msg } from '../src/msg.ts';
import { wrap, unwrap } from '../src/transport.ts';
import { verifyEvent } from '../src/event.ts';

const haveNak = spawnSync('nak', ['--version']).status === 0;
const procs: ChildProcess[] = [];
let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });

const relayPorts = [17201, 17202];
const relays = relayPorts.map((p) => `ws://127.0.0.1:${p}`);
const dirs = [0, 1, 2].map(() => mkdtempSync(join(tmpdir(), 'kk-rt-')));
const httpPort = (k: number) => 18711 + k;

function startServer(k: number): Promise<{ host: string; proc: ChildProcess }> {
  const proc = spawn(process.execPath, [join(import.meta.dirname, '../server/main.ts')], {
    env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dirs[k], 'data'), KEYKIN_KEYS: join(dirs[k], 'keys'),
      KEYKIN_PORT: String(httpPort(k)), KEYKIN_HTTPS: `https://s${k}.test`, KEYKIN_NAME: `S${k}` },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  procs.push(proc);
  return new Promise((res, rej) => {
    let out = '';
    proc.stdout!.on('data', (c) => { out += c; const line = out.split('\n').find((l) => l.includes('"started"')); if (line) res({ host: JSON.parse(line).host, proc }); });
    proc.on('exit', (code) => rej(new Error(`server ${k} exited ${code}`)));
  });
}

test('the server runtime: three processes, create by DKG through their front doors, sign, HTTPS, restart', { skip: !haveNak && 'nak not installed', timeout: 240_000 }, async () => {
  for (const p of relayPorts) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(p)], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const started = await Promise.all([0, 1, 2].map(startServer));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts: started.map((s) => s.host) });
  assert.ok(verifyEvent(await acc.A.sign({ content: 'gm from three Keykin server processes' })));
  const seats = acc.A.servers();
  assert.deepEqual(seats.map((s) => s.host).sort(), started.map((s) => s.host).sort());

  // HTTPS: the same sealed request, POSTed to the server, answered with the wraps of the reply.
  const s0 = seats.find((s) => s.host === started[0].host)!;
  const req = msg('state_get', acc.g, acc.epochId, 'ask');
  const r = await fetch(`http://127.0.0.1:${httpPort(0)}/v1/wrap`, { method: 'POST', body: JSON.stringify(wrap(acc.A.kp.sk, s0.key, req)) });
  assert.equal(r.status, 200);
  const back = (await r.json() as any[]).map((w) => unwrap(acc.A.kp.sk, w).body);
  assert.equal(back[0].type, 'state');
  assert.equal(back[0].re, req.id);
  // Junk over HTTPS is refused, not answered.
  assert.equal((await fetch(`http://127.0.0.1:${httpPort(0)}/v1/wrap`, { method: 'POST', body: '{"not":"a wrap"' })).status, 400);
  assert.equal((await fetch(`http://127.0.0.1:${httpPort(0)}/health`)).status, 200);

  // A server restarts: the same host key and seat from sealed storage; the account signs on.
  started[0].proc.removeAllListeners('exit');
  started[0].proc.kill('SIGTERM');
  await new Promise((r) => started[0].proc.once('exit', r));
  const again = await startServer(0);
  assert.equal(again.host, started[0].host);
  const st = await net.send(acc.A.kp, s0.key, msg('state_get', acc.g, acc.epochId, 'ask'));
  assert.equal(st.type, 'state', 'the restarted seat answers over the relays');
  assert.ok(verifyEvent(await acc.A.sign({ content: 'after a server process restarted' })));
});
