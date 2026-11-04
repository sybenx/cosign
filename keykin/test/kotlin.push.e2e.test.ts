// B1, push wake on the Kotlin device (core §8.1–§8.3): a Kotlin device registers an address per server and
// wake class with three TS server processes (plain-http push allowed for this local test gateway, which
// the headless device runs itself, standing in for UnifiedPush). A TS device deals a redeal while the
// Kotlin device is asleep; the servers push; the Kotlin device decrypts the push, checks it is from a
// seated server, and takes its delivery from it (or fetches), reaching the dealer's state.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import type { Change } from '../src/types.ts';
import { stateOf } from '../src/redeal.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const lib = join(root, 'frost/target/release/' + (process.platform === 'darwin' ? 'libkeykin_frost.dylib' : 'libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const gw = 18811;
const relays = [17301, 17302].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18801 + k), KEYKIN_PUSH_HTTP: '1', KEYKIN_PUSH_HOSTS: `127.0.0.1:${gw}` }, stdio: ['ignore', 'pipe', 'inherit'] });
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

test('a Kotlin device is woken by a TS server\'s push and follows the redeal it carries', { skip: (!haveNak && 'nak not installed') || (!existsSync(lib) && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 480_000 }, async () => {
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'installDist'], { env: { ...process.env, JAVA_HOME: java } });
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kp-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts });
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l));
  await B.fetch();
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-kp-')), 'device.json');
  writeFileSync(snap, B.snapshot());
  net.kill(B.kp.pub);
  writeFileSync(join(dirname(snap), 'cmds.json'), JSON.stringify([{ cmd: 'push', port: gw, seconds: 120, until: 'state' }, { cmd: 'datakey' }]));
  const k = kotlin([snap, relays.join(','), join(dirname(snap), 'cmds.json')]);
  assert.equal((await k.next()).device, B.kp.pub);
  assert.equal((await k.next()).registered, 3, 'every server took the addresses');
  // The Kotlin device is asleep (it hears nothing on the relays as B): A deals a redeal, the servers push.
  const r: Change[] = [{ redeal: { dealer: A.kp.pub } }];
  await A.submit(r, A.approveLock(r));
  const woke = await k.next();
  assert.ok(woke.pushes >= 1, JSON.stringify(woke));
  assert.equal(woke.state, stateOf(A.state!), 'woken by the push, the Kotlin device reached A\'s state');
  const dk = await k.next();
  assert.equal(dk.key, Buffer.from(A.dataKeys.current().key).toString('hex'));
});
