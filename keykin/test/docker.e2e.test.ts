// Step A8: the Keykin server image as a local compose stack (deploy/local): three servers on an
// internal network, two strfry relays published to 127.0.0.1, a push-gateway stub. A device in this
// process drives a whole account through it. Skipped without Docker; never touches a public relay.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { msg } from '../src/msg.ts';
import { wireEvent, verifyEvent } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const dir = join(import.meta.dirname, '../deploy/local');
const dc = (...a: string[]) => spawnSync('docker', ['compose', '-p', 'keykin-e2e', '-f', join(dir, 'compose.yaml'), ...a], { encoding: 'utf8' });
const haveDocker = spawnSync('docker', ['version', '--format', '{{.Server.Version}}']).status === 0;
const relays = ['ws://127.0.0.1:17771', 'ws://127.0.0.1:17772'];
let net: RelayNet | undefined;
const hosts = (): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const s of ['s1', 's2', 's3']) {
    const line = dc('logs', '--no-log-prefix', s).stdout.split('\n').reverse().find((x) => x.includes('"started"'));
    if (line) out[s] = JSON.parse(line).host;
  }
  return out;
};
const waitStarted = async () => { for (let k = 0; k < 60; k++) { const h = hosts(); if (Object.keys(h).length === 3) return h; await new Promise((r) => setTimeout(r, 1000)); } throw new Error('servers did not start'); };

// Up, retried once: the previous run's teardown may still hold the relay ports.
before(async () => {
  if (!haveDocker) return;
  dc('down', '-v');
  let r = dc('up', '-d', '--build');
  if (r.status !== 0) { await new Promise((ok) => setTimeout(ok, 5000)); dc('down', '-v'); r = dc('up', '-d', '--build'); }
  if (r.status !== 0) throw new Error(`docker compose up failed: ${r.stderr.slice(-800)}`);
});
after(() => { net?.close(); if (haveDocker) dc('down', '-v'); });

test('the compose stack: DKG, sign, push, add and report lost, restart mid-hold, delete', { skip: !haveDocker && 'no Docker', timeout: 420_000 }, async () => {
  const h = await waitStarted();
  await new Promise((r) => setTimeout(r, 1500));
  net = new RelayNet({ relays, timeoutMs: 12000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts: [h.s1, h.s2, h.s3] });
  assert.ok(verifyEvent(await acc.A.sign({ content: 'gm from the compose stack' })));
  const seatOf = (name: string) => acc.A.servers().find((s) => s.host === h[name])!.key;

  // Push: the device registers gateway addresses at the stub inside the stack; a hold pushes to each member.
  assert.equal(await acc.A.registerPush({ gateway: 'http://pushstub:8080' }), 3);
  const vanish = wireEvent({ pubkey: acc.g, created_at: net.now, kind: 62, tags: [], content: '' });
  const hold = await net.send(acc.A.kp, seatOf('s1'), { ...msg('hold', acc.g, acc.epochId, 'member'), event: vanish });
  assert.equal(hold.kind, 'hold', hold.code);
  await new Promise((r) => setTimeout(r, 1500));
  const pushes = dc('logs', '--no-log-prefix', 'pushstub').stdout.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l));
  assert.ok(pushes.length >= 1 && pushes.every((p) => p.bytes === 2400), `pushes reached the stub, each 2,400 bytes: ${JSON.stringify(pushes)}`);

  // Restart s1 in the middle of the hold: the wait is still running there.
  assert.equal(dc('restart', 's1').status, 0);
  await new Promise((r) => setTimeout(r, 3000));
  const inbox = await net.send(acc.A.kp, seatOf('s1'), msg('inbox_get', acc.g, acc.epochId, 'ask'));
  assert.ok(inbox.waits?.some((w: any) => w.wait === hold.wait), 'the hold survived the restart');

  // A second device, then reported lost.
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.ok(verifyEvent(await B.sign({ content: 'B over the stack' })));
  const lost: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(lost, acc.A.approveLock(lost));
  await assert.rejects(B.sign({ content: 'B after being reported lost' }));
  assert.ok(verifyEvent(await acc.A.sign({ content: 'A after the redeal' })));

  // Delete the account; a restarted server still answers deleted.
  assert.equal(await acc.A.deleteAccount(), 3);
  assert.equal(dc('restart', 's2').status, 0);
  await new Promise((r) => setTimeout(r, 3000));
  assert.equal((await net.send(acc.A.kp, seatOf('s2'), msg('state_get', acc.g, acc.epochId, 'ask'))).type, 'deleted');
});
