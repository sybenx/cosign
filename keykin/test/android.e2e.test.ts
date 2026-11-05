// B3, the keykin-android demo on one emulator (KEYKIN_ANDROID_SERIAL names it; skipped otherwise, so the test
// never takes a device another session uses): a TS device invites over local relays and three server
// processes; the demo app, driven by intents and read from logcat, joins with the code, shows the check, which
// the TS side types; the TS side adds it and repairs with a server; the app checks its welcome and sigmas with
// Android's own runtime (libsecp256k1, the APK's FROST, Android's org.json) in its signer process, which the
// app's main process reaches only through KeykinService; it seals its state, and signs.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { backupWords } from '../src/backup.ts';
import { Inviter } from '../src/join.ts';
import { pickSalt } from '../src/codes.ts';
import { takenIndices } from '../src/membership.ts';
import { msg } from '../src/msg.ts';
import { verifyEvent, newKey } from '../src/event.ts';
import * as nip44 from 'nostr-tools/nip44';
import type { Change } from '../src/types.ts';

const root = join(import.meta.dirname, '..');
const serial = process.env.KEYKIN_ANDROID_SERIAL;
const adb = '/opt/homebrew/share/android-commandlinetools/platform-tools/adb';
const apk = join(root, 'android/demo/build/outputs/apk/debug/demo-debug.apk');
const haveNak = spawnSync('nak', ['--version']).status === 0;
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
// The demo's default relays: the emulator reaches the host's loopback as 10.0.2.2. Each test has its own stack.
let ports = [17311, 17312], serverBase = 18821;
let relays = ports.map((p) => `ws://127.0.0.1:${p}`);
let appRelays = ports.map((p) => `ws://10.0.2.2:${p}`).join(',');

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(serverBase + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}
/** nak, run on the host; its output once it exits (or after 60 seconds). */
const nak = (args: string[]) => new Promise<{ out: string; err: string }>((res) => {
  const p = spawn('nak', args, { stdio: ['ignore', 'pipe', 'pipe'] }); let out = '', err = '';
  p.stdout.on('data', (c) => (out += c)); p.stderr.on('data', (c) => (err += c));
  const t = setTimeout(() => p.kill(), 60_000); p.on('exit', () => { clearTimeout(t); res({ out, err }); });
});
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
// `adb shell` hands the line to the device's shell: every value is quoted (an invite code has `&` in it).
const q = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`;
const run = (cmd: string, extra: string[] = []) => sh('shell', 'am', 'start', '-n', 'cc.aaro.keykin.demo/.Drive', '--es', 'cmd', cmd, '--es', 'relays', q(appRelays),
  ...extra.map((x) => (x.startsWith('--') ? x : q(x))));

/** A stack on `ports`, an account made by DKG, and the demo app joined to it by invite code (the person's digits typed). */
async function joined() {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-an-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  // The record names the relays as the phone reaches them (the emulator sees the host's loopback as 10.0.2.2).
  const acc = await createByDkg({ net: net as any, fronts, relays: appRelays.split(',') });
  const A = acc.A;
  A.inviter = new Inviter({ g: A.g, m: A.kp.pub, now: net.now });
  const code = A.inviter.invite(relays);

  assert.equal(sh('install', '-r', apk).status, 0, 'installed');
  sh('shell', 'pm', 'clear', 'cc.aaro.keykin.demo');
  const next = logcat();
  run('open');
  assert.equal((await next()).ready, true, 'the app is up and the signer process bound');
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
  assert.equal((await net.send(A.kp, n, msg('welcome', A.g, A.epochId, 'member', { record: A.recEv, changes: A.changes, state: [...A.state!.ids], base_dk: A.baseDk, dk: A.seedRecords(), seeds: [...A.seeds], items: A.items, base: A.base }))).type, 'ack');
  const joined = await next();
  assert.equal(joined.device, n, JSON.stringify(joined));

  return { acc, A, next, n, net };
}

test('the keykin-android demo joins by invite code on an emulator, checked both ways, and signs', { skip: (!serial && 'set KEYKIN_ANDROID_SERIAL to an emulator this test may use') || (!haveNak && 'nak not installed') || (!existsSync(apk) && 'build the demo: (cd android && ./gradlew :demo:assembleDebug)'), timeout: 600_000 }, async () => {
  const { acc, A, next, n, net } = await joined();
  run('sign', ['--es', 'content', 'gm from keykin-android']);
  const ev = await next();
  assert.equal(ev.error, undefined, JSON.stringify(ev));
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g, 'the phone signs as the account, with a TS server');
  // The data key never leaves the signer process: the state it names is what the main process sees.
  run('state');
  const st = await next();
  assert.equal(st.state, A.dataKeys.current().state, 'at the account\'s state');
  assert.equal(st.account, A.g);
  // NIP-55 in the background: an app without a grant hears nothing; once granted (the debug hook stands in
  // for the screen), it gets the account's key and a NIP-44 encryption the peer can open.
  const query = (type: string, projection: string) => sh('shell', 'content', 'query', '--uri', `content://cc.aaro.keykin.demo.${type}`, '--projection', q(projection)).stdout;
  assert.doesNotMatch(query('GET_PUBLIC_KEY', 'x:y:z'), /result=/, 'no grant, no answer');
  // Scopes as Doors §1 names them: signing in and messages; not the account's private data.
  sh('shell', 'am', 'broadcast', '-n', 'cc.aaro.keykin.demo/.DebugGrant', '--es', 'pkg', 'com.android.shell', '--es', 'scopes', 'sign-in,dms');
  assert.equal((await next()).granted, true);
  assert.match(query('GET_PUBLIC_KEY', `x:y:${A.g}`), new RegExp(`result=${A.g}`), 'the granted app gets the account\'s key');
  const peer = newKey();
  const ct = /result=(\S+)/.exec(query('NIP44_ENCRYPT', `hello-from-the-phone:${peer.pub}:${A.g}`))?.[1];
  assert.ok(ct, 'an encryption');
  assert.equal(nip44.v2.decrypt(ct!, nip44.v2.utils.getConversationKey(peer.sk, A.g)), 'hello-from-the-phone', 'the peer opens what the phone encrypted as the account');
  // The grant is listed through the signer service (Doors §1–§2), with the scopes it was given.
  run('grants');
  let listed = await next(); while (!listed.grants) listed = await next();
  assert.deepEqual(listed.grants.map((x: any) => [x.door, x.scopes]), [['nip55', ['dms', 'sign-in']]]);
  // The account's own data is never an app's to read.
  const own = nip44.v2.encrypt('to-self', nip44.v2.utils.getConversationKey(newKey().sk, A.g));
  assert.doesNotMatch(query('NIP44_DECRYPT', `${own}:${A.g}:${A.g}`), /result=/, 'the account\'s own data stays the account\'s');
  // Its state is sealed: the app, restarted, signs again from it.
  sh('shell', 'am', 'force-stop', 'cc.aaro.keykin.demo');   // both processes
  run('sign', ['--es', 'content', 'gm again, after a restart']);
  // A new process reports its membership again first; the signature follows.
  let again = await next();
  while (again.sig === undefined && again.error === undefined) again = await next();
  assert.ok(verifyEvent(again), JSON.stringify(again));

  // The phone as a NIP-46 home (Doors §3.3): it mints a bunker link, and nak on the host signs through it.
  run('bunker', ['--es', 'scopes', 'sign-in,post,lists']);
  let b = await next(); while (b.bunker === undefined) b = await next();
  assert.ok(b.bunker, JSON.stringify(b));
  const link = String(b.bunker).replace(/10\.0\.2\.2/g, '127.0.0.1');
  const lineOf = (o: { out: string; err: string }) => { const l = o.out.trim().split('\n').find((x) => x.startsWith('{')); assert.ok(l, 'nak said: ' + o.out + o.err); return JSON.parse(l!); };
  const posted = lineOf(await nak(['event', '--sec', link, '-k', '1', '-c', 'gm through the phone\'s home', relays[0]]));
  assert.ok(verifyEvent(posted) && posted.pubkey === A.g, 'the phone answered as the account');
  // Device policy on the phone (§2): the person's 12 follows, then the site cuts them to 1: a Confirm card, which
  // the person allows; only then does the site get its event.
  const follows = Array.from({ length: 12 }, (_, k) => ['p', k.toString(16).padStart(64, '0')]);
  await net.events.publishEvent(await A.sign({ kind: 3, tags: follows, content: '' }));
  const cut = nak(['event', '--sec', link, '-k', '3', '-t', `p=${follows[0][1]}`, relays[0]]);
  const first: any = await Promise.race([(async () => { let c = await next(); while (!c.card) c = await next(); return c; })(), cut.then((o) => ({ nak: o }))]);
  assert.ok(first.card, 'no card; nak said: ' + JSON.stringify(first.nak));
  const card = first;
  assert.match(card.card.reason, /Remove 11 of your 12 follows/, JSON.stringify(card));
  run('answer', ['--es', 'id', String(card.card.id), '--es', 'allow', 'true']);
  const listEv = lineOf(await cut);
  assert.ok(verifyEvent(listEv) && listEv.kind === 3 && listEv.tags.length === 1, JSON.stringify(listEv));

});

test('on the emulator, the phone reports a device lost after another joined unseen, and checks the paper', { skip: (!serial && 'set KEYKIN_ANDROID_SERIAL to an emulator this test may use') || (!haveNak && 'nak not installed') || (!existsSync(apk) && 'build the demo: (cd android && ./gradlew :demo:assembleDebug)'), timeout: 900_000 }, async () => {
  net?.close();
  ports = [17331, 17332]; serverBase = 18841;
  relays = ports.map((p) => `ws://127.0.0.1:${p}`); appRelays = ports.map((p) => `ws://10.0.2.2:${p}`).join(',');
  const { acc, A } = await joined();
  // Report lost on the phone (the dry run's real path, result 6): a tablet joins while the phone isn't told; the phone
  // reports the laptop lost on its Devices and paper screen with the paper's words (it is lockless); the redeal must
  // include the tablet, which the phone first learns of by fetching. Then the paper check, right and wrong words.
  const C = await invite(acc, A, (l) => A.approveLock(l));
  const words = backupWords(acc.paper.sk).join(' ');
  const tap = (text: string) => {
    sh('shell', 'uiautomator', 'dump', '/sdcard/kk.xml');
    const xml = sh('shell', 'cat', '/sdcard/kk.xml').stdout; sh('shell', 'rm', '-f', '/sdcard/kk.xml');
    const node = xml.split('>').find((x) => x.toLowerCase().includes(`text="${text.toLowerCase()}"`) && x.includes('package="cc.aaro.keykin.demo"'));
    const m = node && /bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/.exec(node);
    assert.ok(m, `no "${text}" on screen`);
    sh('shell', 'input', 'tap', String((+m![1] + +m![3]) >> 1), String((+m![2] + +m![4]) >> 1));
  };
  const screenText = () => { sh('shell', 'uiautomator', 'dump', '/sdcard/kk.xml'); const x = sh('shell', 'cat', '/sdcard/kk.xml').stdout; sh('shell', 'rm', '-f', '/sdcard/kk.xml'); return x.toLowerCase(); };
  const typeWords = (w: string) => { tap('the paper\'s 24 words'); sh('shell', 'input', 'text', q(w.replace(/ /g, '%s'))); sh('shell', 'input', 'keyevent', '111'); };
  const until = async (f: () => boolean, ms = 90_000) => { for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 2000))) if (f()) return true; return false; };
  sh('shell', 'am', 'start', '-W', '-n', 'cc.aaro.keykin.demo/.Main');
  await new Promise((r) => setTimeout(r, 3000));
  tap('Devices and paper');
  assert.ok(await until(() => screenText().includes(`report ${A.kp.pub.slice(0, 12)}`)), 'the Devices screen lists the laptop');
  typeWords(words);
  tap(`Report ${A.kp.pub.slice(0, 12)}… lost`);
  assert.ok(await until(() => screenText().includes('reported lost with the paper'), 240_000), 'not reported; the screen: ' + (screenText().match(/text="[^"]+"/g) ?? []).slice(0, 4).join(' ') + ' log: ' + sh('logcat', '-d', '-t', '40', '-s', 'KeykinSigner', 'Keykin', 'AndroidRuntime').stdout.slice(-800));
  await C.fetch();
  assert.ok(C.m!.removed.has(A.kp.pub) && !C.wiped, 'the tablet applied the redeal: it was dealt to');
  assert.equal((await C.sign({ kind: 1, content: 'the tablet still posts', tags: [] })).pubkey, acc.g);
  typeWords(words); tap('Check the paper');
  assert.ok(await until(() => screenText().includes('the paper is this account\'s')), 'the paper checks');
  typeWords(words.replace(/^\S+/, 'zoo')); tap('Check the paper');
  assert.ok(await until(() => screenText().includes('not this account\'s paper')), 'a wrong word doesn\'t');
  sh('shell', 'input', 'keyevent', '4');
  sh('uninstall', 'cc.aaro.keykin.demo');
});
