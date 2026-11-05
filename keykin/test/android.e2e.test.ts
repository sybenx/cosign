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
  // The home subscribes on its relays once the link is minted: a moment for that, and one retry, as a site retries
  // (the root causes, a gap while re-subscribing and an unbounded catch-up before answering, are fixed in the homes).
  await new Promise((r) => setTimeout(r, 3000));
  let said = await nak(['event', '--sec', link, '-k', '1', '-c', 'gm through the phone\'s home', relays[0]]);
  if (!said.out.includes('{')) said = await nak(['event', '--sec', link, '-k', '1', '-c', 'gm through the phone\'s home', relays[0]]);
  const posted = lineOf(said);
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

// keykin-android's own screens and calls (the Marble hand-off's library side): the opening state after a restart; refresh
// shows a device that joined unseen; an invite from the phone, which a Kotlin device joins, the add approved on the
// library's KeykinApprove screen with the paper (the emulator is lockless); report lost and the paper check on that
// screen; a pair request from the Kotlin device, approved on the phone with the digits.
const ktBin = join(root, 'kotlin/build/install/keykin-kotlin/bin/keykin-kotlin');
const frostLib = ['dylib', 'so'].map((x) => join(root, `frost/target/release/libkeykin_frost.${x}`)).find(existsSync);
test('keykin-android: opening, refresh, invite from the phone, and the approval screen for report lost, the paper and a pair', { skip: (!serial && 'set KEYKIN_ANDROID_SERIAL to an emulator this test may use') || (!haveNak && 'nak not installed') || (!existsSync(apk) && 'build the demo') || ((!existsSync(ktBin) || !frostLib) && 'run `gradlew installDist` in kotlin/ and build frost'), timeout: 1_200_000 }, async () => {
  ports = [17351, 17352]; serverBase = 18861;
  relays = ports.map((p) => `ws://127.0.0.1:${p}`); appRelays = ports.map((p) => `ws://10.0.2.2:${p}`).join(',');
  const { acc, A, next, n } = await joined();
  const words = backupWords(acc.paper.sk).join(' ');
  const until = async <T>(f: () => Promise<T | undefined> | T | undefined, ms = 120_000): Promise<T> => {
    for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 1000))) { const x = await f(); if (x !== undefined && x !== null && (x as any) !== false) return x as T; }
    throw new Error('timed out');
  };
  const line = async (pred: (x: any) => boolean, ms = 180_000) => until(async () => { const x = await next().catch(() => undefined); return x && pred(x) ? x : undefined; }, ms);
  const screen = () => { sh('shell', 'uiautomator', 'dump', '/sdcard/kk.xml'); const x = sh('shell', 'cat', '/sdcard/kk.xml').stdout; sh('shell', 'rm', '-f', '/sdcard/kk.xml'); return x; };
  const tap = (text: string) => {
    const node = screen().split('>').find((x) => x.toLowerCase().includes(`text="${text.toLowerCase()}"`) && x.includes('package="cc.aaro.keykin.demo"'));
    const m = node && /bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/.exec(node);
    assert.ok(m, `no "${text}" on screen`);
    sh('shell', 'input', 'tap', String((+m![1] + +m![3]) >> 1), String((+m![2] + +m![4]) >> 1));
  };
  const type = (hint: string, text: string) => { tap(hint); sh('shell', 'input', 'text', q(text.replace(/ /g, '%s'))); sh('shell', 'input', 'keyevent', '111'); };
  const onScreen = (text: string) => until(() => screen().toLowerCase().includes(text.toLowerCase()) || undefined, 60_000);
  const lastAction = (action: string) => line((x) => x.last_action?.action === action, 240_000).then((x) => x.last_action);

  console.error('step: opening');
  // After a restart the slot is never silent: it says it is opening (a slow open, as over Tailscale), or its full state
  // comes at once (a quick one, as here).
  sh('shell', 'am', 'force-stop', 'cc.aaro.keykin.demo');
  run('open');
  assert.ok(await line((x) => x.opening === true || x.device === n, 30_000), 'a state soon after the restart');
  console.error('step: refresh');
  // Refresh: a tablet joins while the phone isn't told; refresh lists it.
  const C = await invite(acc, A, (l) => A.approveLock(l));
  run('refresh');
  const fresh = await line((x) => x.refreshed !== undefined);
  assert.ok(fresh.refreshed.devices.some((x: any) => x.key === C.kp.pub), 'refresh shows the unseen tablet: ' + JSON.stringify(fresh));

  console.error('step: invite');
  // Invite from the phone: a Kotlin device joins with the code; the phone types its digits and approves the add.
  run('invite', ['--es', 'invite_relays', relays.join(',')]);
  const { invite: code } = await line((x) => x.invite !== undefined);
  assert.ok(code, 'a code');
  const kt = spawn(ktBin, [`join:${code}`, relays.join(','), '-'], { env: { ...process.env, JAVA_HOME: '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home', JAVA_OPTS: `-Dkeykin.frostlib=${frostLib}` }, stdio: ['pipe', 'pipe', 'ignore'] });
  procs.push(kt);
  const ktLines: any[] = []; const ktWait: ((x: any) => void)[] = [];
  createInterface({ input: kt.stdout! }).on('line', (l) => { let x: any; try { x = JSON.parse(l); } catch { return; } const w = ktWait.shift(); if (w) w(x); else ktLines.push(x); });
  const ktNext = () => new Promise<any>((ok, no) => { const x = ktLines.shift(); if (x) return ok(x); ktWait.push(ok); setTimeout(() => no(new Error('no line from the Kotlin device')), 240_000); });
  const ktCmd = (c: object) => { kt.stdin!.write(JSON.stringify(c) + '\n'); return ktNext(); };
  console.error('step: kt check');
  const { check } = await ktNext();
  run('invite_typed', ['--es', 'digits', check]);
  assert.equal((await line((x) => x.typed !== undefined)).typed, true, 'the digits match');
  console.error('step: approve add');
  run('approve', ['--es', 'action', 'add_invited']);
  await onScreen('add the new device');
  type('the paper\'s 24 words', words);
  tap('Add device');
  const added = await lastAction('add_invited');
  assert.equal(added.ok, true, JSON.stringify(added));
  const { device: K } = await ktNext();
  assert.match(K, /^[0-9a-f]{64}$/);
  assert.equal((await ktCmd({ cmd: 'sign', content: 'invited by the phone' })).pubkey, acc.g, 'the device the phone invited signs');

  console.error('step: report lost');
  // Report lost on the library screen: the laptop, with the paper.
  run('approve', ['--es', 'action', 'report_lost', '--es', 'key', A.kp.pub]);
  await onScreen(`report ${A.kp.pub.slice(0, 12)}`);
  type('the paper\'s 24 words', words);
  tap('Report lost');
  const lost = await lastAction('report_lost');
  assert.equal(lost.ok, true, JSON.stringify(lost));
  await C.fetch();
  assert.ok(C.m!.removed.has(A.kp.pub) && !C.wiped, 'the tablet followed the redeal');
  assert.equal((await C.sign({ kind: 1, content: 'the tablet still posts', tags: [] })).pubkey, acc.g);

  console.error('step: paper check');
  // The paper check on the library screen, right and wrong.
  for (const [w, want] of [[words, 'this account\'s paper'], [words.replace(/^\S+/, 'zoo'), 'not this account\'s paper']] as const) {
    run('approve', ['--es', 'action', 'paper_check']);
    await onScreen('type the 24 words');
    type('the paper\'s 24 words', w);
    tap('Check the paper');
    assert.equal((await lastAction('paper_check')).detail, want);
  }

  console.error('step: pair');
  // A pair: the Kotlin device asks the phone to approve removing the tablet; the phone types its code on the screen.
  kt.stdin!.write(JSON.stringify({ cmd: 'pair_remove', key: C.kp.pub, with: n, seconds: 300 }) + '\n');
  const { code: pc } = await ktNext();
  assert.match(pc, /^\d{6}$/);
  const id = await until(async () => { run('fetch'); run('pair_asks'); const a = await line((x) => x.pair_asks !== undefined, 30_000).catch(() => undefined); return a?.pair_asks?.[0]?.id; }, 120_000);
  run('approve', ['--es', 'action', 'pair_approve', '--es', 'id', id]);
  await onScreen('asks this phone to approve');
  type('6 digits', pc);
  tap('Approve');
  assert.equal((await lastAction('pair_approve')).ok, true);
  const removed = await ktNext();
  assert.equal(removed.error, undefined, JSON.stringify(removed));
  await C.fetch();
  assert.ok(C.wiped, 'the tablet was removed with the pair');
  kt.kill('SIGKILL');
  sh('uninstall', 'cc.aaro.keykin.demo');
});
