// B1: the Kotlin device as a NIP-46 home (Doors §3.3). It takes over a TS device's state, mints a
// bunker:// link, and nak signs and encrypts as the account through it, over a real relay, with the
// Kotlin device coordinating with TS co-signers.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import * as nip44 from 'nostr-tools/nip44';
import { RelayNet } from '../runtime/relay.ts';
import { create } from '../sim/account.ts';
import { newKey, verifyEvent } from '../src/event.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const url = 'ws://127.0.0.1:17281';
const run = (args: string[]) => new Promise<{ out: string; err: string }>((res) => {
  const p = spawn('nak', args, { stdio: ['ignore', 'pipe', 'pipe'] }); let out = '', err = '';
  p.stdout.on('data', (c) => (out += c)); p.stderr.on('data', (c) => (err += c));
  const t = setTimeout(() => p.kill(), 40_000); p.on('exit', () => { clearTimeout(t); res({ out, err }); });
});

test('nak signs and encrypts as the account through a Kotlin NIP-46 home', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', '17281'], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1200));
  net = new RelayNet({ relays: [url], timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await create({ net: net as any });            // TS servers in this process, over the relay
  const dir = mkdtempSync(join(tmpdir(), 'kk-kn-'));
  writeFileSync(join(dir, 'device.json'), acc.A.snapshot());
  net.kill(acc.A.kp.pub);                                    // the TS device steps aside (one member, §4.6)
  writeFileSync(join(dir, 'cmds.json'), JSON.stringify([{ cmd: 'bunker', seconds: 90 }]));
  spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'classes'], { env: { ...process.env, JAVA_HOME: java } });
  const kt = spawn(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${join(dir, 'device.json')} ${url} ${join(dir, 'cmds.json')}`], { env: { ...process.env, JAVA_HOME: java }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(kt);
  const lines = createInterface({ input: kt.stdout! });
  const link = await new Promise<string>((res) => lines.on('line', (l) => { const x = JSON.parse(l); if (x.bunker) res(x.bunker); }));
  const n1 = await run(['event', '--sec', link, '-k', '1', '-c', 'hello from nak via Kotlin', url]);
  const line = n1.out.trim().split('\n').find((l) => l.startsWith('{'));
  assert.ok(line, 'nak said: ' + n1.out + n1.err);
  const ev = JSON.parse(line!);
  assert.equal(ev.pubkey, acc.g, n1.err);
  assert.ok(verifyEvent(ev));
  const peer = newKey();
  const n2 = await run(['encrypt', '--sec', link, '-p', peer.pub, 'a note through the Kotlin home']);
  assert.equal(nip44.v2.decrypt(n2.out.trim(), nip44.v2.utils.getConversationKey(peer.sk, acc.g)), 'a note through the Kotlin home', n2.err);
});
