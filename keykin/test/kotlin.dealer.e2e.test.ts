// B1, the Kotlin device as a dealer (core §6.1, §6.7.3, §6.7.6, §6.7.10): TS devices A, B (with a lock) and
// C share an account over three server processes; B's state, its soft lock included, goes to a Kotlin
// process, which removes C with a redeal it deals and approves with its lock. The TS servers check the
// approval, hold the upload and co-sign the list; A follows the redeal as any device does, reports C's
// removal at the Kotlin dealer's state, and both sign at that state.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';
import { stateOf } from '../src/redeal.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17281, 17282].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18781 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('a Kotlin device deals and submits a removal; TS servers co-sign it and a TS device follows', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kd-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts });
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  const C = await invite(acc, A, (l) => A.approveLock(l));
  await B.fetch();
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-kd-')), 'device.json');
  writeFileSync(snap, B.snapshot());
  net.kill(B.kp.pub);

  const cmds = join(dirname(snap), 'cmds.json');
  writeFileSync(cmds, JSON.stringify([{ cmd: 'remove', key: C.kp.pub }, { cmd: 'members' }, { cmd: 'datakey' }, { cmd: 'sign', content: 'gm from the Kotlin dealer' }]));
  const r = spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${snap} ${relays.join(',')} ${cmds}`], { env: { ...process.env, JAVA_HOME: java }, encoding: 'utf8', timeout: 300_000 });
  const all = r.stdout.trim().split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l));
  assert.equal(all[0]?.device, B.kp.pub, r.stdout + r.stderr.slice(-800));
  const [removed, members, dk, ev] = all.slice(1);
  assert.equal(removed.error, undefined, `the Kotlin dealer's list: ${JSON.stringify(removed)}`);
  assert.equal(removed.events.length, 2, 'the remove and its redeal, co-signed as one list');
  assert.deepEqual([members.removed[0]?.key, members.removed[0]?.state], [C.kp.pub, removed.state]);
  assert.equal(ev.error, undefined, JSONSON(ev));

  // A follows as any device: the list and its delivery from the servers.
  await A.fetch();
  assert.equal(stateOf(A.state!), removed.state, 'A is at the Kotlin dealer\'s state');
  assert.ok(A.m!.removed.has(C.kp.pub));
  assert.deepEqual(A.members.removed(0).map((e) => [e.key, e.state]), [[C.kp.pub, removed.state]]);
  const ts = A.dataKeys.current();
  assert.deepEqual([dk.state, dk.key], [ts.state, Buffer.from(ts.key).toString('hex')], 'the same data key from the Kotlin dealer\'s seed');
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g);
  assert.ok(verifyEvent(await A.sign({ content: 'A at the new state' })));
  // C, removed, can no longer sign.
  await assert.rejects(C.sign({ content: 'C after its removal' }));
});
const JSONSON = JSON.stringify;
