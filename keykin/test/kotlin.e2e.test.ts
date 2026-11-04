// B1: the Kotlin device signs through TS Keykin servers over real relays. A TS device creates the
// account through three server processes, hands its state to a Kotlin process (as an extension hands
// its membership to the app, core §4.4), and the Kotlin device signs a note the TS side verifies.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg } from '../sim/account.ts';
import { verifyEvent, newKey } from '../src/event.ts';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17241, 17242].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18751 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('a Kotlin device signs through three TS server processes over relays', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kt-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts });
  // The TS device steps aside: its state goes to the Kotlin device (one member, core §4.6).
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-kt-')), 'device.json');
  writeFileSync(snap, acc.A.snapshot());
  net.kill(acc.A.kp.pub);
  // The Kotlin device signs, and encrypts and decrypts as the account (ECDH with a TS co-signer, §5.5).
  const peer = newKey();
  const fromPeer = nip44.v2.encrypt('from the peer', nip44.v2.utils.getConversationKey(peer.sk, acc.g));
  const fromPeer04 = await nip04.encrypt(peer.sk, acc.g, 'nip04 from the peer');
  const cmds = join(dirname(snap), 'cmds.json');
  writeFileSync(cmds, JSON.stringify([{ cmd: 'sign', content: 'gm-from-kotlin' }, { cmd: 'nip44', peer: peer.pub, text: 'to the peer from kotlin' },
    { cmd: 'nip44', peer: peer.pub, text: fromPeer, encrypt: false }, { cmd: 'nip04', peer: peer.pub, text: 'nip04 from kotlin' }, { cmd: 'nip04', peer: peer.pub, text: fromPeer04, encrypt: false }, { cmd: 'datakey' }]));
  const r = spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${snap} ${relays.join(',')} ${cmds}`], { env: { ...process.env, JAVA_HOME: java }, encoding: 'utf8', timeout: 300_000 });
  const all = r.stdout.trim().split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l));
  assert.equal(all[0]?.device, acc.A.kp.pub, 'the Kotlin device took over this member key');
  const out = all.slice(1);
  assert.equal(out.length, 6, r.stdout + r.stderr.slice(-500));
  const [ev, e44, d44, e04, d04, dk] = out;
  const ts = acc.A.dataKeys.current();
  assert.deepEqual([dk.state, dk.key], [ts.state, Buffer.from(ts.key).toString('hex')], 'Kotlin derives the same data key (core §4.5)');
  assert.equal(ev.error, undefined, `Kotlin refused: ${JSON.stringify(ev)}`);
  assert.equal(ev.pubkey, acc.g);
  assert.equal(ev.content, 'gm-from-kotlin');
  assert.ok(verifyEvent(ev), 'the TS side verifies what the Kotlin device signed with a TS server');
  assert.equal(nip44.v2.decrypt(e44.result, nip44.v2.utils.getConversationKey(peer.sk, acc.g)), 'to the peer from kotlin');
  assert.equal(d44.result, 'from the peer');
  assert.equal(await nip04.decrypt(peer.sk, acc.g, e04.result), 'nip04 from kotlin');
  assert.equal(d04.result, 'nip04 from the peer');
});
