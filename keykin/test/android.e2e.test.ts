// B3, the keykin-android demo on one emulator (KEYKIN_ANDROID_SERIAL names it; skipped otherwise, so the test
// never takes a device another session uses): a TS device invites over local relays and three server
// processes; the demo app, driven by intents and read from logcat, joins with the code, shows the check, which
// the TS side types; the TS side adds it and repairs with a server; the app checks its welcome and sigmas with
// Android's own runtime (libsecp256k1, the APK's FROST, Android's org.json), seals its state, and signs.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg } from '../sim/account.ts';
import { Inviter } from '../src/join.ts';
import { pickSalt } from '../src/codes.ts';
import { takenIndices } from '../src/membership.ts';
import { msg } from '../src/msg.ts';
import { verifyEvent } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const root = join(import.meta.dirname, '..');
const serial = process.env.KEYKIN_ANDROID_SERIAL;
const adb = '/opt/homebrew/share/android-commandlinetools/platform-tools/adb';
const apk = join(root, 'android/demo/build/outputs/apk/debug/demo-debug.apk');
const haveNak = spawnSync('nak', ['--version']).status === 0;
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
// The demo's default relays: the emulator reaches the host's loopback as 10.0.2.2.
const ports = [17311, 17312];
const relays = ports.map((p) => `ws://127.0.0.1:${p}`);
const appRelays = ports.map((p) => `ws://10.0.2.2:${p}`).join(',');

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18821 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}
const sh = (...a: string[]) => spawnSync(adb, ['-s', serial!, ...a], { encoding: 'utf8' });
/** The app's JSON lines from logcat (tag KeykinDemo), one at a time. */
function logcat() {
  sh('logcat', '-c');
  const p = spawn(adb, ['-s', serial!, 'logcat', '-v', 'raw', '-s', 'KeykinDemo:I'], { stdio: ['ignore', 'pipe', 'ignore'] });
  procs.push(p);
  const lines: any[] = []; const waiting: ((x: any) => void)[] = [];
  createInterface({ input: p.stdout! }).on('line', (l) => { if (!l.startsWith('{')) return; const x = JSON.parse(l); const w = waiting.shift(); if (w) w(x); else lines.push(x); });
  return () => new Promise<any>((res, rej) => { const x = lines.shift(); if (x) return res(x); waiting.push(res); setTimeout(() => rej(new Error('no line from the app')), 180_000); });
}
const run = (cmd: string, extra: string[] = []) => sh('shell', 'am', 'start', '-n', 'cc.aaro.keykin.demo/.Main', '--es', 'cmd', cmd, '--es', 'relays', appRelays, ...extra);

test('the keykin-android demo joins by invite code on an emulator, checked both ways, and signs', { skip: (!serial && 'set KEYKIN_ANDROID_SERIAL to an emulator this test may use') || (!haveNak && 'nak not installed') || (!existsSync(apk) && 'build the demo: (cd android && ./gradlew :demo:assembleDebug)'), timeout: 600_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-an-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts });
  const A = acc.A;
  A.inviter = new Inviter({ g: A.g, m: A.kp.pub, now: net.now });
  const code = A.inviter.invite(relays);

  assert.equal(sh('install', '-r', apk).status, 0, 'installed');
  sh('shell', 'pm', 'clear', 'cc.aaro.keykin.demo');
  const next = logcat();
  run('open');
  assert.equal((await next()).ready, true);
  run('join', ['--es', 'code', code]);
  const shown = await next();
  assert.match(shown.check, /^\d{6}$/, JSON.stringify(shown));
  assert.ok(A.inviter.typed(shown.check), 'the inviter types the number the phone shows');
  const n = A.inviter.accepted!.n;
  const { salt, indices } = pickSalt(A.g, A.epochId, n, takenIndices(A.m!));
  const add: Change[] = [{ add: { key: n, kind: 'device', lock: null, salt } }];
  await A.submit(add, A.approveLock(add));
  const server0 = A.servers()[0];
  for (const i of indices)
    for (const w of await A.repairFor([{ key: A.kp.pub, indices: [...A.state!.shares.keys()] }, { key: server0.key, indices: server0.shares }], i, n, 'add'))
      await net.events.publishEvent(w);
  assert.equal((await net.send(A.kp, n, msg('welcome', A.g, A.epochId, 'member', { record: A.recEv, changes: A.changes, state: [...A.state!.ids], base_dk: A.baseDk, dk: A.dkSeeds }))).type, 'ack');
  const joined = await next();
  assert.equal(joined.device, n, JSON.stringify(joined));

  run('sign', ['--es', 'content', 'gm from keykin-android']);
  const ev = await next();
  assert.equal(ev.error, undefined, JSON.stringify(ev));
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g, 'the phone signs as the account, with a TS server');
  run('datakey');
  assert.equal((await next()).key, Buffer.from(A.dataKeys.current().key).toString('hex'), 'and holds the account\'s data key');
  // Its state is sealed: the app, restarted, signs again from it.
  sh('shell', 'am', 'force-stop', 'cc.aaro.keykin.demo');
  run('sign', ['--es', 'content', 'gm again, after a restart']);
  const again = await next();
  assert.ok(verifyEvent(again), JSON.stringify(again));
});
