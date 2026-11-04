// B2, the pair approval between a Kotlin and a TS device (core §6.2): TS devices A, B and C share an account
// over three server processes. B's state goes to a Kotlin process, which asks A to approve removing C with it
// and shows the 6-digit code; the test types that code on A, as the person would; A signs only then, and the
// Kotlin device deals and submits the list with the pair approval, which the TS servers check.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { stateOf } from '../src/redeal.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const lib = join(root, 'frost/target/release/' + (process.platform === 'darwin' ? 'libkeykin_frost.dylib' : 'libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17321, 17322].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18831 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}
/** A headless Kotlin device, its stdout read a JSON line at a time. */
function kotlin(args: string[]) {
  const p = spawn(join(root, 'kotlin/build/install/keykin-kotlin/bin/keykin-kotlin'), args, { env: { ...process.env, JAVA_HOME: java, JAVA_OPTS: `-Dkeykin.frostlib=${lib}` }, stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(p);
  let err = ''; p.stderr!.on('data', (c) => { err += c; });
  const lines: any[] = []; const waiting: ((x: any) => void)[] = [];
  createInterface({ input: p.stdout! }).on('line', (l) => { if (!l.startsWith('{')) return; const x = JSON.parse(l); const w = waiting.shift(); if (w) w(x); else lines.push(x); });
  const next = () => new Promise<any>((res, rej) => { const x = lines.shift(); if (x) return res(x); waiting.push(res); setTimeout(() => rej(new Error('no line: ' + err.slice(-800))), 200_000); });
  return { p, next };
}

test('a Kotlin device and a TS device approve a removal together: a code shown on one, typed on the other', { skip: (!haveNak && 'nak not installed') || (!existsSync(lib) && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 480_000 }, async () => {
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'installDist'], { env: { ...process.env, JAVA_HOME: java } });
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kpr-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts, relays });
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l));
  const C = await invite(acc, A, (l) => A.approveLock(l));
  await B.fetch(); await A.fetch();
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-kpr-')), 'device.json');
  writeFileSync(snap, B.snapshot());
  net.kill(B.kp.pub);
  writeFileSync(join(dirname(snap), 'cmds.json'), JSON.stringify([{ cmd: 'pair_remove', key: C.kp.pub, with: A.kp.pub, seconds: 120 }]));
  const k = kotlin([snap, relays.join(','), join(dirname(snap), 'cmds.json')]);
  assert.equal((await k.next()).device, B.kp.pub);
  const { code } = await k.next();
  assert.match(code, /^\d{6}$/);
  // A hears the request (live), shows it; the person types the code the Kotlin device shows.
  for (let t = 0; t < 100 && A.pairAsks.size === 0; t++) await new Promise((r) => setTimeout(r, 100));
  const [ask] = [...A.pairAsks.values()];
  assert.equal(ask?.from, B.kp.pub, 'A was asked by the Kotlin device');
  assert.equal(await A.pairApprove(ask.id, code), true);
  const done = await k.next();
  assert.equal(done.error, undefined, JSON.stringify(done));
  await A.fetch();
  assert.ok(A.m!.removed.has(C.kp.pub), 'C removed with the pair approval');
  assert.equal(stateOf(A.state!), done.state);
});
