// The dry-run CLI (cli/account.ts) against three server processes and local relays: `create` makes a throwaway
// account by DKG and prints its paper; `invite` adds a Kotlin device that joins by the code, as a phone would, and
// that device signs; `show` lists both devices. A live host is refused.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { readBackupWords } from '../src/backup.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = [];
after(() => procs.forEach((p) => p.kill('SIGTERM')));
const relays = [17291, 17292].map((p) => `ws://127.0.0.1:${p}`);
const cli = (args: string[]) => spawnSync(process.execPath, [join(root, 'cli/account.ts'), ...args], { encoding: 'utf8', timeout: 120_000 });

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18921 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('the dry-run CLI refuses a live host', () => {
  const r = cli(['create', '--dir', mkdtempSync(join(tmpdir(), 'kk-cli-')), '--relays', 'wss://relay.syb.lol', '--fronts', 'aa,bb,cc']);
  assert.notEqual(r.status, 0); assert.match(r.stderr, /refused: .* live server/);
});

test('the dry-run CLI: create by DKG, print the paper, invite a device that joins by the code, and show both', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-cli-s-')))));
  const dir = mkdtempSync(join(tmpdir(), 'kk-cli-'));
  const made = cli(['create', '--dir', dir, '--relays', relays.join(','), '--fronts', fronts.join(',')]);
  assert.equal(made.status, 0, made.stderr + made.stdout);
  const created = JSON.parse(made.stdout.split('\n')[0]);
  assert.match(created.created, /^npub1/);
  assert.equal(readBackupWords(readFileSync(join(dir, 'paper.txt'), 'utf8').trim().split(' ')).length, 32, 'the paper reads back');

  // `invite` prints the code and waits for the phone's digits on stdin.
  const inv = spawn(process.execPath, [join(root, 'cli/account.ts'), 'invite', '--dir', dir], { stdio: ['pipe', 'pipe', 'inherit'] });
  procs.push(inv);
  const invLines = createInterface({ input: inv.stdout! });
  const invNext = () => new Promise<any>((res) => invLines.once('line', (l) => res(JSON.parse(l))));
  const { invite } = await invNext();
  assert.ok(invite, 'a code');

  const cmds = join(mkdtempSync(join(tmpdir(), 'kk-cli-k-')), 'cmds.json');
  writeFileSync(cmds, JSON.stringify([{ cmd: 'sign', content: 'gm from the phone stand-in' }]));
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'classes'], { env: { ...process.env, JAVA_HOME: java } });
  const kt = spawn(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=join:${invite} ${relays.join(',')} ${cmds}`], { env: { ...process.env, JAVA_HOME: java }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(kt);
  const ktLines = createInterface({ input: kt.stdout! });
  const ktNext = () => new Promise<any>((res) => ktLines.once('line', (l) => res(JSON.parse(l))));
  const shown = await ktNext();
  assert.match(shown.check, /^\d{6}$/);
  inv.stdin!.write(shown.check + '\n');
  const added = await invNext();
  assert.equal(added.welcomed, true, JSON.stringify(added));
  const joined = await ktNext();
  assert.equal(joined.device, added.added);
  const signed = await ktNext();
  assert.equal(signed.pubkey, created.g, JSON.stringify(signed));

  const shownBoth = cli(['show', '--dir', dir]);
  const s = JSON.parse(shownBoth.stdout.trim().split('\n').pop()!);
  assert.equal(s.devices.length, 2);
});
