// B1: the Kotlin device signs through TS Keykin servers over real relays. A TS device creates the
// account through three server processes, hands its state to a Kotlin process (as an extension hands
// its membership to the app, core §4.4), and the Kotlin device signs a note the TS side verifies.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17241, 17242].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18751 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('a Kotlin device signs through three TS server processes over relays', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kt-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts });
  // The TS device steps aside: its state goes to the Kotlin device (one member, core §4.6).
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-kt-')), 'device.json');
  writeFileSync(snap, acc.A.snapshot());
  net.kill(acc.A.kp.pub);
  const r = spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${snap} ${relays.join(',')} gm-from-kotlin`], { env: { ...process.env, JAVA_HOME: java }, encoding: 'utf8', timeout: 300_000 });
  const line = r.stdout.trim().split('\n').pop()!;
  const ev = JSON.parse(line);
  assert.equal(ev.error, undefined, `Kotlin refused: ${line} ${r.stderr.slice(-500)}`);
  assert.equal(ev.pubkey, acc.g);
  assert.equal(ev.content, 'gm-from-kotlin');
  assert.ok(verifyEvent(ev), 'the TS side verifies what the Kotlin device signed with a TS server');
});
