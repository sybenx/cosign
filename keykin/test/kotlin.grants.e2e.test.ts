// Doors §2 across languages: a TS device signs out a Kotlin device's grant, and the end reaches the Kotlin home as a
// delivery; then the Kotlin device signs out of every site, and its wildcard ends the TS device's grants.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { create, invite } from '../sim/account.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const url = 'ws://127.0.0.1:17284';
const site = (n: string) => ({ site: `https://${n}.example`, says: n, door: 'nip07' as const, connection: 'chrome', scopes: ['sign-in', 'post'] as any });

test('a TS device ends a Kotlin home\'s grant by a delivery; a Kotlin wildcard ends a TS device\'s grants', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', '17284'], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1200));
  net = new RelayNet({ relays: [url], timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await create({ net: net as any, relays: [url] });
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  await B.fetch();
  const dir = mkdtempSync(join(tmpdir(), 'kk-kg-'));
  writeFileSync(join(dir, 'device.json'), acc.A.snapshot());
  net.kill(acc.A.kp.pub);                                    // A goes on in Kotlin
  writeFileSync(join(dir, 'cmds.json'), JSON.stringify([{ cmd: 'grant', site: 'kotlin-app' }, { cmd: 'wait_ends', id: '__ID__', seconds: 90 }, { cmd: 'signout_all' }]));
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'classes'], { env: { ...process.env, JAVA_HOME: java } });
  // The grant id is known only once made: the Kotlin side reads it from its own first line (wait_ends takes '__ID__'
  // as "the grant just made").
  const kt = spawn(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${join(dir, 'device.json')} ${url} ${join(dir, 'cmds.json')}`], { env: { ...process.env, JAVA_HOME: java }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(kt);
  const lines = createInterface({ input: kt.stdout! });
  const seen: any[] = [];
  const waitFor = (f: (x: any) => boolean) => new Promise<any>((res) => { const hit = seen.find(f); if (hit) return res(hit); lines.on('line', (l) => { try { const x = JSON.parse(l); seen.push(x); if (f(x)) res(x); } catch { /* not ours */ } }); });
  const made = await waitFor((x) => x.grant || x.error);
  assert.ok(made.grant, JSON.stringify(made));
  // B reads A's grant event, then signs it out: the end goes to A as a delivery.
  for (let k = 0; k < 20 && !B.grants.all().some((e) => e.id === made.grant); k++) { await B.grants.fetch(); await new Promise((r) => setTimeout(r, 500)); }
  assert.ok(B.grants.all().some((e) => e.id === made.grant), 'B lists the Kotlin grant');
  B.grants.make(site('ts-site')); await B.grants.publish();
  await B.signOut([{ by: acc.A.kp.pub, id: made.grant }]);
  const ended = await waitFor((x) => 'ended' in x);
  assert.equal(ended.ended, true, 'the Kotlin home dropped it');
  // A's sign out of every site: B's own grant ends by A's wildcard.
  await waitFor((x) => 'own' in x);
  for (let k = 0; k < 20 && B.grants.own.size; k++) { await B.fetch(); await new Promise((r) => setTimeout(r, 500)); }
  assert.equal(B.grants.own.size, 0, 'B applied the Kotlin wildcard');
});
