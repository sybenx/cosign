// The dry run's sequences, automated (dry-run result 6: the person is the last check, not the test suite). Each scenario
// runs against its own local stack, as on the Mac mini: two nak relays, three server processes, the laptop as the CLI
// (cli/account.ts), and the phone and tablet as Kotlin devices (the code keykin-android runs), driven one command at a
// time over stdin. Android's own screens are checked on an emulator separately.
//   A  laptop creates; phone joins; tablet joins while the phone hears nothing; both post, fetch, list devices; the phone
//      reports the laptop lost from its stale list; the tablet still posts; the laptop says it was removed.
//   B  the chaos run: the phone reports every other device lost, then forgets the account; the laptop can't invite.
//   C  forget, then rejoin with a fresh invite; the same invite scanned twice adds one device only.
//   D  a stale list: the tablet joins while the phone's Devices list is open (A's report runs from that list).
//   E  a restart in the middle of a report-lost, relays 1-3 s slow, and clocks 30 s fast and slow.
//   F  the extension's member (a TS device, device/join.ts) joins by invite over the relays; a Kotlin phone joins
//      unseen; the extension reports the laptop lost from its stale list with the paper; both still post.
//   G  the other direction: the extension shows its own hello code (a QR), the phone scans it, the person types the
//      extension's digits on the phone, and the phone approves the add with the paper.
//   H  account creation on the phone: a Kotlin device creates an account by DKG with three servers and shows its paper
//      once; it signs as the new account; an extension joins it by showing its QR, approved with the new paper; the
//      phone reports the extension lost.
//   I  paper recovery over the relays (a test W of 20 s): the laptop and the phone are lost; a new device finds the
//      account from the paper alone, waits out W, is added and repaired, reports both lost, and signs; the old phone
//      can't sign any more.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createServer, connect, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { joinByCode, joinByShowing } from '../device/join.ts';
import { recoverWithPaper } from '../device/recover.ts';
import { setTestW } from '../src/approval.ts';
import { readBackupWords } from '../src/backup.ts';
import { pubOf } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const here = join(import.meta.dirname, '..');
// DRYRUN_ROOT: another copy's CLI and servers (the pinned dry run's); DRYRUN_KT: its Kotlin device. This tree's by default.
const root = process.env.DRYRUN_ROOT ?? here;
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const kt = process.env.DRYRUN_KT ?? join(here, 'kotlin/build/install/keykin-kotlin/bin/keykin-kotlin');
// This tree's Kotlin device is rebuilt first (Gradle skips it when nothing changed), and the run refuses to start on a
// jar older than any Kotlin source: a stale jar once failed G and H for reasons that weren't the code's.
if (!process.env.DRYRUN_KT && existsSync(java)) {
  const b = spawnSync(join(here, 'kotlin/gradlew'), ['-q', '-p', join(here, 'kotlin'), 'installDist'], { env: { ...process.env, JAVA_HOME: java }, encoding: 'utf8' });
  if (b.status !== 0) throw new Error(`installDist failed: ${(b.stderr || b.stdout).slice(-2000)}`);
  const jar = join(here, 'kotlin/build/install/keykin-kotlin/lib/keykin-kotlin.jar');
  const newest = (d: string): number => readdirSync(d, { withFileTypes: true }).reduce((m, e) => Math.max(m, e.isDirectory() ? newest(join(d, e.name)) : statSync(join(d, e.name)).mtimeMs), 0);
  if (!existsSync(jar) || statSync(jar).mtimeMs < newest(join(here, 'kotlin/src/main'))) throw new Error('the Kotlin device jar is older than its sources: run `gradlew installDist` in kotlin/');
}
// The whole file at most 45 minutes: a pending join or a dead relay never hangs a run again.
const SUITE_MS = Number(process.env.DRYRUN_SUITE_MS ?? 45 * 60_000);
setTimeout(() => { console.error(`dryrun: the whole suite passed ${SUITE_MS / 60_000} minutes; stopping`); procs.forEach((p) => p.kill('SIGKILL')); process.exit(1); }, SUITE_MS).unref();
const frost = ['dylib', 'so'].map((x) => join(here, `frost/target/release/libkeykin_frost.${x}`)).find(existsSync);
const haveNak = spawnSync('nak', ['--version']).status === 0;
const skip = (!haveNak && 'nak not installed') || (!frost && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21') || (!existsSync(kt) && 'run `gradlew installDist` in kotlin/ first');
const procs: ChildProcess[] = []; const servers: Server[] = [];
after(() => { procs.forEach((p) => p.kill('SIGKILL')); servers.forEach((s) => s.close()); });
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Lines of JSON from a process, one at a time, with a timeout. */
class Lines {
  #q: any[] = []; #w: ((x: any) => void)[] = [];
  constructor(rl: Interface) { rl.on('line', (l) => { let x: any; try { x = JSON.parse(l); } catch { return; } const w = this.#w.shift(); if (w) w(x); else this.#q.push(x); }); }
  next(ms = 240_000, what = 'a line'): Promise<any> {
    if (this.#q.length) return Promise.resolve(this.#q.shift());
    return new Promise((ok, no) => { const t = setTimeout(() => { this.#w = this.#w.filter((f) => f !== w); no(new Error(`timed out waiting for ${what}`)); }, ms); const w = (x: any) => { clearTimeout(t); ok(x); }; this.#w.push(w); });
  }
}

/** A relay port that holds every chunk for 1-3 s each way (slow relays, scenario E). */
function slowProxy(port: number, to: number): Promise<void> {
  const s = createServer((c) => {
    const up = connect(to, '127.0.0.1');
    const later = (dst: any) => (b: Buffer) => setTimeout(() => dst.writable && dst.write(b), 1000 + Math.random() * 2000);
    c.on('data', later(up)); up.on('data', later(c));
    c.on('error', () => up.destroy()); up.on('error', () => c.destroy()); c.on('close', () => up.destroy()); up.on('close', () => c.destroy());
  });
  servers.push(s);
  return new Promise((ok) => s.listen(port, '127.0.0.1', () => ok()));
}

/** A port nothing listens on now (the OS's pick): fixed ports clashed with other runs on this machine. */
const freePort = () => new Promise<number>((ok, no) => { const t = createServer(); t.on('error', no); t.listen(0, '127.0.0.1', () => { const p = (t.address() as any).port; t.close(() => ok(p)); }); });

/** One scenario's stack and laptop. `slow`: the devices reach the relays through the slow proxy. (`_base` was a fixed
 *  port range; the ports are now free ones.) */
async function stack(_base: number, o: { slow?: boolean; testW?: number } = {}) {
  const ports = [await freePort(), await freePort()];
  const direct = ports.map((p) => `ws://127.0.0.1:${p}`);
  for (const p of ports) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(p)], { stdio: 'ignore' }));
  const proxied = o.slow ? [await freePort(), await freePort()] : [];
  for (const [k, p] of proxied.entries()) await slowProxy(p, ports[k]);
  const devRelays = o.slow ? proxied.map((p) => `ws://127.0.0.1:${p}`) : direct;
  await wait(1500);
  const fronts = await Promise.all([0, 1, 2].map((k) => new Promise<string>((res, rej) => {
    const d = mkdtempSync(join(tmpdir(), 'kk-dr-s-'));
    const p = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: direct.join(','), KEYKIN_DATA: join(d, 'data'), KEYKIN_KEYS: join(d, 'keys'), KEYKIN_PORT: '0', ...(o.testW ? { KEYKIN_TEST_W: String(o.testW) } : {}) }, stdio: ['ignore', 'pipe', 'inherit'] });
    procs.push(p);
    let out = ''; p.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); p.on('exit', (c) => rej(new Error(`server exited ${c}`)));
  })));
  const dir = mkdtempSync(join(tmpdir(), 'kk-dr-'));
  const cli = (args: string[]) => spawnSync(process.execPath, [join(root, 'cli/account.ts'), ...args, '--dir', dir], { encoding: 'utf8', timeout: 180_000 });
  const made = cli(['create', '--relays', direct.join(','), '--fronts', fronts.join(',')]);
  assert.equal(made.status, 0, made.stderr);
  const created = JSON.parse(made.stdout.split('\n')[0]);
  return { dir, cli, g: created.g as string, laptop: created.device as string, devRelays, fronts, words: readFileSync(join(dir, 'paper.txt'), 'utf8').trim() };
}
type Stack = Awaited<ReturnType<typeof stack>>;

/** A Kotlin device: joins by a fresh invite from the laptop (the person types its digits), then takes commands. */
class Device {
  p!: ChildProcess; lines!: Lines; key = '';
  readonly s: Stack; readonly name: string; readonly o: { skew?: number; state?: string };
  constructor(s: Stack, name: string, o: { skew?: number; state?: string } = {}) { this.s = s; this.name = name; this.o = o; }
  /** Create a new account by DKG with the stack's three servers; the paper's words come back once. */
  async create(): Promise<{ g: string; words: string }> {
    this.#start(`create:${this.s.fronts.join(',')}`);
    const made = await this.lines.next(240_000, `${this.name} created`);
    assert.ok(made.paper && made.g, JSON.stringify(made));
    assert.match(made.signpost, /^[0-9a-f]{64}$/, 'the signpost, published at creation: ' + made.signpost);
    const { device } = await this.lines.next(60_000, `${this.name}'s key`);
    this.key = device;
    return { g: made.g, words: made.paper };
  }
  #start(first: string) {
    this.p = spawn(kt, [first, this.s.devRelays.join(','), '-'], { env: { ...process.env, JAVA_HOME: java, JAVA_OPTS: `-Dkeykin.frostlib=${frost}`,
      ...(this.o.skew ? { KEYKIN_CLOCK_SKEW: String(this.o.skew) } : {}), ...(this.o.state ? { KEYKIN_STATE: this.o.state } : {}) }, stdio: ['pipe', 'pipe', 'ignore'] });
    procs.push(this.p);
    this.lines = new Lines(createInterface({ input: this.p.stdout! }));
  }
  async join() {
    const inv = spawn(process.execPath, [join(root, 'cli/account.ts'), 'invite', '--dir', this.s.dir, '--app-relays', this.s.devRelays.join(',')], { stdio: ['pipe', 'pipe', 'ignore'] });
    procs.push(inv);
    const il = new Lines(createInterface({ input: inv.stdout! }));
    const { invite } = await il.next(120_000, 'the invite');
    this.#start(`join:${invite}`);
    const { check } = await this.lines.next(180_000, `${this.name}'s digits`);
    inv.stdin!.write(check + '\n');
    const added = await il.next(180_000, 'the laptop\'s add');
    assert.equal(added.welcomed, true, `${this.name}: ${JSON.stringify(added)}`);
    const { device } = await this.lines.next(180_000, `${this.name} joined`);
    assert.equal(device, added.added);
    this.key = device;
    return invite as string;
  }
  /** Start again from the kept state (an app restarted). */
  async restart() {
    this.p.kill('SIGKILL'); await wait(500);
    this.#start(this.o.state!);
    const { device } = await this.lines.next(120_000, `${this.name} restarted`);
    assert.equal(device, this.key);
  }
  async cmd(c: object, ms = 240_000) { this.p.stdin!.write(JSON.stringify(c) + '\n'); return this.lines.next(ms, `${this.name} ${JSON.stringify(c).slice(0, 40)}`); }
  async post(text: string) { const ev = await this.cmd({ cmd: 'sign', content: text }); assert.equal(ev.pubkey, this.s.g, `${this.name} posts: ${JSON.stringify(ev)}`); return ev; }
  async devices(fetch = true) { if (fetch) await this.cmd({ cmd: 'fetch' }); return (await this.cmd({ cmd: 'devices' })).devices as string[]; }
  forget() { this.p.kill('SIGKILL'); }
}
const removedMsg = /removed from the account/;

test('A + D: report-lost from a stale list after another device joined', { skip, timeout: 900_000 }, async () => {
  const s = await stack(17400);
  const phone = new Device(s, 'phone'); await phone.join();
  assert.deepEqual((await phone.devices()).sort(), [s.laptop, phone.key].sort());
  const tablet = new Device(s, 'tablet'); await tablet.join();                       // the phone hears nothing of it
  const stale = await phone.devices(false);                                           // D: the phone's Devices list, opened earlier
  assert.ok(!stale.includes(tablet.key), 'the phone\'s list is stale, as on the user\'s phone');
  await phone.post('gm from the phone'); await tablet.post('gm from the tablet');
  assert.equal((await tablet.devices()).length, 3);
  // Report lost straight from that list, with no fetch between: as the user's phone did.
  const r = await phone.cmd({ cmd: 'report_lost', key: s.laptop, words: s.words });
  assert.equal(r.error, undefined, `report lost: ${JSON.stringify(r)}`);
  assert.deepEqual([...r.devices].sort(), [phone.key, tablet.key].sort());
  assert.deepEqual((await tablet.devices()).sort(), [phone.key, tablet.key].sort());
  await tablet.post('the tablet still posts'); await phone.post('and the phone');
  const shown = s.cli(['show']);
  assert.equal(shown.status, 3, shown.stderr + shown.stdout); assert.match(shown.stderr, removedMsg);
});

test('B: the chaos run: report every other device lost, then forget the last; the laptop can\'t invite', { skip, timeout: 900_000 }, async () => {
  const s = await stack(17420);
  const phone = new Device(s, 'phone'); await phone.join();
  const tablet = new Device(s, 'tablet'); await tablet.join();
  for (const k of [tablet.key, s.laptop]) { const r = await phone.cmd({ cmd: 'report_lost', key: k, words: s.words }); assert.equal(r.error, undefined, JSON.stringify(r)); }
  assert.deepEqual(await phone.devices(), [phone.key], 'the phone is the only device');
  const t = await tablet.cmd({ cmd: 'sign', content: 'the tablet was reported lost' });
  assert.ok(t.error, 'the removed tablet can\'t sign');
  phone.forget();                                                                    // Forget on the last device
  const inv = s.cli(['invite']);
  assert.equal(inv.status, 3, 'no device can invite: only the paper gets the person back in'); assert.match(inv.stderr, removedMsg);
});

test('C: forget, then rejoin with a fresh invite; the same invite scanned twice adds one device', { skip, timeout: 900_000 }, async () => {
  const s = await stack(17440);
  const phone = new Device(s, 'phone'); const code = await phone.join();
  await phone.post('before forget');
  phone.forget();
  const again = new Device(s, 'phone again'); await again.join();
  assert.notEqual(again.key, phone.key);
  assert.deepEqual((await again.devices()).sort(), [s.laptop, phone.key, again.key].sort(), 'the forgotten copy stays listed');
  const r = await again.cmd({ cmd: 'report_lost', key: phone.key, words: s.words });
  assert.equal(r.error, undefined, JSON.stringify(r));
  await again.post('after rejoin');
  // The first invite again (a second scan of an old code): it gets nowhere, and adds nobody.
  const dup = spawn(kt, [`join:${code}`, s.devRelays.join(','), '-'], { env: { ...process.env, JAVA_HOME: java, JAVA_OPTS: `-Dkeykin.frostlib=${frost}` }, stdio: ['pipe', 'pipe', 'ignore'] });
  procs.push(dup);
  const dl = new Lines(createInterface({ input: dup.stdout! }));
  const first = await dl.next(60_000).catch(() => null);
  assert.ok(first === null || first.error || first.check, `no device from an old code: ${JSON.stringify(first)}`);
  dup.kill('SIGKILL');
  assert.deepEqual((await again.devices()).sort(), [s.laptop, again.key].sort());
});

test('E: a restart in the middle of a report-lost, slow relays, clocks 30 s off', { skip, timeout: 1_200_000 }, async () => {
  const s = await stack(17460, { slow: true });
  const phone = new Device(s, 'phone', { skew: 30, state: join(mkdtempSync(join(tmpdir(), 'kk-dr-p-')), 'device.json') }); await phone.join();
  const tablet = new Device(s, 'tablet', { skew: -30 }); await tablet.join();
  await phone.post('a fast clock'); await tablet.post('a slow clock');
  // The app is killed a moment after Report lost: started again, it reports the laptop lost (again, if it got through).
  phone.p.stdin!.write(JSON.stringify({ cmd: 'report_lost', key: s.laptop, words: s.words }) + '\n');
  await wait(1500);
  await phone.restart();
  const now = await phone.devices();
  if (now.includes(s.laptop)) { const r = await phone.cmd({ cmd: 'report_lost', key: s.laptop, words: s.words }); assert.equal(r.error, undefined, JSON.stringify(r)); }
  assert.deepEqual((await phone.devices()).sort(), [phone.key, tablet.key].sort());
  assert.deepEqual((await tablet.devices()).sort(), [phone.key, tablet.key].sort());
  await phone.post('after the restart'); await tablet.post('the tablet too');
});

test('F: the extension\'s TS member joins by invite and reports the laptop lost from a stale list', { skip, timeout: 900_000 }, async () => {
  const s = await stack(17480);
  // The extension: a TS device on its own relay connection, joining with the laptop's code (the person types its digits).
  const net = new RelayNet({ relays: s.devRelays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  try {
    const inv = spawn(process.execPath, [join(root, 'cli/account.ts'), 'invite', '--dir', s.dir, '--app-relays', s.devRelays.join(',')], { stdio: ['pipe', 'pipe', 'ignore'] });
    procs.push(inv);
    const il = new Lines(createInterface({ input: inv.stdout! }));
    const { invite } = await il.next(120_000, 'the invite');
    const joined = joinByCode(net as any, invite, { onCheck: (digits) => inv.stdin!.write(digits + '\n'), name: 'extension' });
    const added = await il.next(180_000, 'the laptop\'s add');
    assert.equal(added.welcomed, true, JSON.stringify(added));
    const ext = await joined;
    assert.equal(ext.kp.pub, added.added);
    assert.equal((await ext.sign({ kind: 1, content: 'gm from the extension', tags: [] })).pubkey, s.g);
    const phone = new Device(s, 'phone'); await phone.join();                         // the extension hears nothing of it
    assert.ok(!ext.memberKeys().includes(phone.key), 'the extension\'s list is stale');
    await phone.post('gm from the phone');
    // Report the laptop lost from that list, with the paper's words: the redeal must reach the phone.
    const sk = readBackupWords(s.words.split(/\s+/));
    const list: Change[] = [{ remove: s.laptop }, { redeal: { dealer: ext.kp.pub } }];
    await ext.submit(list, await ext.approveWithPaper(list, { sk, pub: pubOf(sk) }));
    assert.deepEqual(ext.memberKeys().sort(), [ext.kp.pub, phone.key].sort());
    assert.deepEqual((await phone.devices()).sort(), [ext.kp.pub, phone.key].sort());
    await phone.post('the phone still posts');
    assert.equal((await ext.sign({ kind: 1, content: 'and the extension', tags: [] })).pubkey, s.g);
    assert.equal(s.cli(['show']).status, 3, 'the laptop knows it was removed');
  } finally { net.close(); }
});

test('G: the extension shows its hello code, the phone scans it and adds it', { skip, timeout: 900_000 }, async () => {
  const s = await stack(17500);
  const phone = new Device(s, 'phone'); await phone.join();
  const net = new RelayNet({ relays: s.devRelays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  try {
    // Core 14.24: the phone (which scanned) shows the digits; the person types them on the extension, which confirms.
    let code = '', shown = ''; const tries: number[] = [];
    const askDigits = async (k: number) => { tries.push(k); for (let i = 0; !shown && i < 600; i++) await new Promise((r) => setTimeout(r, 100)); return k === 1 ? (shown === '000000' ? '000001' : '000000') : shown; };
    const joined = joinByShowing(net as any, s.devRelays, { name: 'extension', timeoutMs: 120_000, onCode: (c) => { code = c; }, askDigits });
    await new Promise((r) => setTimeout(r, 1500));
    assert.match(code, /^keykin:hello\?/, 'a hello code to show as a QR');
    const offered = await phone.cmd({ cmd: 'invite_scanned', code });
    assert.equal(offered.error, undefined, JSON.stringify(offered));
    shown = offered.check;
    assert.match(shown, /^\d{6}$/);
    assert.equal((await phone.cmd({ cmd: 'invite_typed', digits: shown })).typed, false, 'nothing is typed on the phone in this direction');
    for (let i = 0; i < 60 && !(await phone.cmd({ cmd: 'invite_state' })).confirmed; i++) await new Promise((r) => setTimeout(r, 500));
    assert.deepEqual(tries, [1, 2], 'a wrong entry is asked again');
    const added = await phone.cmd({ cmd: 'add_invited', words: s.words });
    assert.equal(added.error, undefined, JSON.stringify(added));
    const ext = await joined;
    assert.equal(ext.kp.pub, added.added);
    assert.equal((await ext.sign({ kind: 1, content: 'gm from the extension, joined by its own QR', tags: [] })).pubkey, s.g);
    assert.ok(ext.checkPaper(s.words.split(/\s+/)), 'the paper check');
    assert.ok(!ext.checkPaper(s.words.replace(/^\S+/, 'zoo').split(/\s+/)));
    // Account admin §2: each names itself, and each reads the other's name (TS writes, Kotlin reads, and back).
    await ext.setLabel('Chrome on MacBook', 'Chrome');
    assert.equal((await phone.cmd({ cmd: 'set_label', name: 'onn tablet', model: 'onn 11 Pro' })).error, undefined);
    const names = (await phone.cmd({ cmd: 'labels' })).labels;
    assert.equal(names[ext.kp.pub].name, 'Chrome on MacBook'); assert.equal(names[ext.kp.pub].model, 'Chrome');
    await ext.fetchLabels();
    const phoneKey = ext.members.devices().keys.find((k) => k.name === 'onn tablet');
    assert.ok(phoneKey && phoneKey.model === 'onn 11 Pro' && !phoneKey.same_name, JSON.stringify(ext.members.devices().keys));
    assert.deepEqual((await phone.devices()).sort(), [s.laptop, phone.key, ext.kp.pub].sort());
  } finally { net.close(); }
});

test('H: a phone creates an account by DKG, signs, adds an extension by its QR with the new paper', { skip, timeout: 900_000 }, async () => {
  const s = await stack(17520);
  const phone = new Device(s, 'phone');
  const { g, words } = await phone.create();
  assert.notEqual(g, s.g, 'a new account, not the laptop\'s');
  assert.equal(words.split(' ').length, 24);
  const ev = await phone.cmd({ cmd: 'sign', content: 'the first post of an account made on a phone' });
  assert.equal(ev.pubkey, g, JSON.stringify(ev));
  assert.deepEqual(await phone.devices(), [phone.key]);
  const net = new RelayNet({ relays: s.devRelays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  try {
    // Its signpost, published at creation (§6.7.5 route 3): on the relays, and it leads the paper to this account.
    const { findAccount } = await import('../device/recover.ts');
    const { readBackupWords } = await import('../src/backup.ts');
    const psk = readBackupWords(words.split(' '));
    const found = await findAccount(net as any, { sk: psk, pub: pubOf(psk) });
    assert.equal(found.g, g, 'the signpost names this account\'s servers');
    let code = '', shown = '';
    const joined = joinByShowing(net as any, s.devRelays, { name: 'extension', timeoutMs: 120_000, onCode: (c) => { code = c; }, askDigits: async () => { for (let i = 0; !shown && i < 600; i++) await new Promise((r) => setTimeout(r, 100)); return shown; } });
    await new Promise((r) => setTimeout(r, 1500));
    const offered = await phone.cmd({ cmd: 'invite_scanned', code });
    assert.equal(offered.error, undefined, JSON.stringify(offered));
    shown = offered.check;
    for (let i = 0; i < 60 && !(await phone.cmd({ cmd: 'invite_state' })).confirmed; i++) await new Promise((r) => setTimeout(r, 500));
    const added = await phone.cmd({ cmd: 'add_invited', words });
    assert.equal(added.error, undefined, JSON.stringify(added));
    const ext = await joined;
    assert.equal((await ext.sign({ kind: 1, content: 'joined an account a phone made', tags: [] })).pubkey, g);
    assert.ok(ext.checkPaper(words.split(' ')), 'the new paper is the account\'s');
    const r = await phone.cmd({ cmd: 'report_lost', key: ext.kp.pub, words });
    assert.equal(r.error, undefined, JSON.stringify(r));
    assert.deepEqual(r.devices, [phone.key]);
  } finally { net.close(); }
});

test('I: paper recovery over the relays with a test W, reporting the lost devices', { skip, timeout: 900_000 }, async () => {
  setTestW(20);
  try {
    const s = await stack(17540, { testW: 20 });
    const phone = new Device(s, 'phone'); await phone.join();
    await phone.post('before everything was lost');
    // Everything is lost: only the paper's words remain.
    const net = new RelayNet({ relays: s.devRelays, timeoutMs: 9000, resendMs: 1500 });
    await net.connect();
    try {
      let waiting: any = null;
      const D = await recoverWithPaper(net as any, s.words.split(/\s+/), { hosts: s.fronts, name: 'recovered', lost: [s.laptop, phone.key], pollMs: 3000, giveUpAt: Date.now() + 240_000, onWaiting: (w) => { waiting = w; } });
      assert.ok(waiting, 'the person was told the wait');
      assert.equal(D.g, s.g, 'the paper\'s account');
      assert.deepEqual(D.memberKeys(), [D.kp.pub], 'the lost devices were reported');
      assert.equal((await D.sign({ kind: 1, content: 'back in with the paper', tags: [] })).pubkey, s.g);
      assert.ok(D.checkPaper(s.words.split(/\s+/)));
      const old = await phone.cmd({ cmd: 'sign', content: 'the lost phone' });
      assert.ok(old.error, 'the old phone can\'t sign: ' + JSON.stringify(old));
    } finally { net.close(); }
  } finally { setTestW(3 * 86400); }
});

test('J: the phone makes a new paper (F7), approved with the old; the account is recovered from the new paper alone', { skip, timeout: 900_000 }, async () => {
  setTestW(20);
  try {
    const s = await stack(17560, { testW: 20 });
    const phone = new Device(s, 'phone'); await phone.join();
    await phone.post('before the new paper');
    // A new paper the person never types back is abandoned: nothing is committed, and the old paper stays.
    assert.equal((await phone.cmd({ cmd: 'new_paper', words: s.words, read_back: false })).error, 'not_read_back');
    assert.equal((await phone.cmd({ cmd: 'paper_is', words: s.words })).current, true);
    const made = await phone.cmd({ cmd: 'new_paper', words: s.words });
    assert.equal(made.error, undefined, JSON.stringify(made));
    const words: string = made.paper;
    assert.equal(words.split(' ').length, 24);
    assert.notEqual(words, s.words);
    assert.equal((await phone.cmd({ cmd: 'paper_is', words })).current, true);
    assert.equal((await phone.cmd({ cmd: 'paper_is', words: s.words })).current, false);
    // Then everything is lost, and only the new paper's words remain.
    const net = new RelayNet({ relays: s.devRelays, timeoutMs: 9000, resendMs: 1500 });
    await net.connect();
    try {
      const D = await recoverWithPaper(net as any, words.split(' '), { hosts: s.fronts, name: 'recovered', lost: [s.laptop, phone.key], pollMs: 3000, giveUpAt: Date.now() + 240_000 });
      assert.equal(D.g, s.g);
      assert.ok(D.checkPaper(words.split(' ')), 'the new paper is the account\'s');
      assert.ok(!D.checkPaper(s.words.split(/\s+/)), 'the old paper no longer is');
      assert.equal((await D.sign({ kind: 1, content: 'back in with the new paper', tags: [] })).pubkey, s.g);
    } finally { net.close(); }
  } finally { setTestW(3 * 86400); }
});
