// B1, the Kotlin device as inviter (core §4.1–§4.2): TS devices A and B (with a lock) share an account
// over three server processes. B's state goes to a Kotlin process, which shows an invite code; a second,
// new Kotlin process joins with it, and the test types the digits the joiner shows into the inviter, as
// the person would. The inviter adds the new device with its lock, repairs each index with a TS server,
// and welcomes it. The joined device signs; A follows the add and signs too.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';
import { stateOf } from '../src/redeal.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const lib = join(root, 'frost/target/release/' + (process.platform === 'darwin' ? 'libkeykin_frost.dylib' : 'libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17291, 17292].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18791 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
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

test('a Kotlin device invites and adds a new Kotlin device, repaired with a TS server', { skip: (!haveNak && 'nak not installed') || (!existsSync(lib) && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 480_000 }, async () => {
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'installDist'], { env: { ...process.env, JAVA_HOME: java } });
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-ki-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts, relays });
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  await B.fetch();
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-ki-')), 'device.json');
  writeFileSync(snap, B.snapshot());
  net.kill(B.kp.pub);

  const dir = dirname(snap);
  writeFileSync(join(dir, 'inviter.json'), JSON.stringify([{ cmd: 'invite' }, { cmd: 'members' }]));
  writeFileSync(join(dir, 'joiner.json'), JSON.stringify([{ cmd: 'sign', content: 'gm from the invited Kotlin device' }, { cmd: 'datakey' }]));
  const inviter = kotlin([snap, relays.join(','), join(dir, 'inviter.json')]);
  assert.equal((await inviter.next()).device, B.kp.pub);
  const { invite: code } = await inviter.next();
  assert.match(code, /^keykin:join\?/);
  const joiner = kotlin([`join:${code}`, relays.join(','), join(dir, 'joiner.json')]);
  const { check } = await joiner.next();
  assert.match(check, /^\d{6}$/);
  inviter.p.stdin!.write(check + '\n');                      // the person types the number the new device shows
  const added = await inviter.next();
  assert.equal(added.error, undefined, JSON.stringify(added));
  const n = added.added;
  assert.equal((await joiner.next()).device, n, 'the joiner is the device the inviter added');
  const ev = await joiner.next();
  assert.equal(ev.error, undefined, JSON.stringify(ev));
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g, 'the invited Kotlin device signs as the account');
  const dk = await joiner.next();
  const members = await inviter.next();
  assert.ok(members.keys.some((k: any) => k.key === n && k.added_by === B.kp.pub), 'added by the Kotlin inviter');

  await A.fetch();
  assert.ok(A.m!.devices.has(n) && !A.m!.removed.has(n), 'A follows the add');
  assert.equal(stateOf(A.state!), added.state);
  assert.equal(dk.key, Buffer.from(A.dataKeys.current().key).toString('hex'), 'the new device holds the account\'s data key');
  assert.ok(verifyEvent(await A.sign({ content: 'A after the Kotlin add' })));
});
