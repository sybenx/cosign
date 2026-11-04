// B1: a Kotlin device joins an account (core §4.1–§4.2) over real relays. A TS device invites; the
// Kotlin process scans the code, shows the check, which the TS side types; the add is approved and
// repaired with a TS server; the welcome and the sigmas reach the Kotlin device, which checks them and
// signs as a member.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg } from '../sim/account.ts';
import { Inviter } from '../src/join.ts';
import { pickSalt } from '../src/codes.ts';
import { takenIndices } from '../src/membership.ts';
import { msg } from '../src/msg.ts';
import { verifyEvent, newKey } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17261, 17262].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18761 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('a Kotlin device joins by invite code, checked both ways, and signs', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kj-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts, relays });
  const A = acc.A;
  // A redeal first: the welcome then names a state after it, whose commitment the Kotlin device rebuilds.
  const r0: Change[] = [{ redeal: { dealer: A.kp.pub } }];
  await A.submit(r0, A.approveLock(r0));
  assert.equal(A.state!.ids.size, 1);
  A.inviter = new Inviter({ g: A.g, m: A.kp.pub, now: net.now });
  const code = A.inviter.invite(relays);

  const cmds = join(mkdtempSync(join(tmpdir(), 'kk-kj-')), 'cmds.json');
  writeFileSync(cmds, JSON.stringify([{ cmd: 'sign', content: 'gm from a Kotlin device that joined' }, { cmd: 'datakey' }]));
  // Gradle's own start, then the Kotlin process; its stdout read line by line as it goes.
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'classes'], { env: { ...process.env, JAVA_HOME: java } });
  const kt = spawn(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=join:${code} ${relays.join(',')} ${cmds}`], { env: { ...process.env, JAVA_HOME: java }, stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(kt);
  const lines = createInterface({ input: kt.stdout! });
  const next = () => new Promise<any>((res) => lines.once('line', (l) => res(JSON.parse(l))));

  const shown = await next();
  assert.match(shown.check, /^\d{6}$/);
  assert.ok(A.inviter.typed(shown.check), 'the inviter types the number the Kotlin device shows');
  assert.ok(!A.inviter.typed('000000'.slice(0, 6) === shown.check ? '111111' : '000000'), 'a wrong number goes nowhere');
  const n = A.inviter.accepted!.n;
  const { salt, indices } = pickSalt(A.g, A.epochId, n, takenIndices(A.m!));
  const add: Change[] = [{ add: { key: n, kind: 'device', lock: null, salt } }];
  await A.submit(add, A.approveLock(add));
  // Review 12 K1: `n` is public, so a stranger races a junk welcome; the Kotlin device ignores it.
  const stray = net.send(newKey(), n, msg('welcome', A.g, A.epochId, 'member', { record: A.recEv, changes: [], state: [] }));
  // The inviter's welcome overtakes the sigmas: the Kotlin device waits for them.
  const welcomed = net.send(A.kp, n, msg('welcome', A.g, A.epochId, 'member', { record: A.recEv, changes: A.changes, state: [...A.state!.ids], base_dk: A.baseDk, dk: A.dkSeeds }));
  assert.equal((await welcomed).type, 'ack');
  const server0 = A.servers()[0];
  for (const i of indices)
    for (const w of await A.repairFor([{ key: A.kp.pub, indices: [...A.state!.shares.keys()] }, { key: server0.key, indices: server0.shares }], i, n, 'add'))
      await net.events.publishEvent(w);

  const joined = await next();
  assert.notEqual((await stray).type, 'ack', 'a stranger\'s welcome gets no answer');
  assert.equal(joined.device, n, JSON.stringify(joined));
  const ev = await next();
  assert.equal(ev.error, undefined, JSON.stringify(ev));
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g, 'the joined Kotlin device signs as the account');
  assert.equal(A.m!.devices.size, 2);
  const dk = await next();
  assert.equal(dk.key, Buffer.from(A.dataKeys.current().key).toString('hex'), 'the joined Kotlin device holds the account\'s data key');
});
