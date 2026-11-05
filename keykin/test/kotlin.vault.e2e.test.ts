// Doors 20 §3.7 in Kotlin: a Kotlin device answers a vault app's calls as a TS device does. A TS account over three
// server processes and two relays; device B's state goes to a Kotlin process, which grants an app, signs its root
// (`ksig`), derives the owner key, signs a device cert, seals an invitation, unwraps one the TS device sealed to the
// account, and decrypts a vault payload but not a DM.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import * as nip44 from 'nostr-tools/nip44';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { verifyEvent, newKey, eventId } from '../src/event.ts';
import { memberVerify } from '../device/membersig.ts';
import { nip44Open } from '../src/nip44.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17311, 17312].map((p) => `ws://127.0.0.1:${p}`);
const APP = 'org.example.notes';

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18941 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('a Kotlin device answers a vault app\'s calls as the TS device does', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-kv-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts, relays });
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l));
  await B.fetch();
  A.vault.allow(APP);
  // An invitation the TS device seals to the account itself, for the Kotlin device to unwrap.
  const toSelf = await A.vault.invite(APP, { pubkey: A.g, created_at: A.now, kind: 4812, tags: [], content: JSON.stringify({ vault: 'd0'.repeat(32), genesis: {} }) }, A.g);
  const peer = newKey();
  const enc = (t: string) => nip44.v2.encrypt(t, nip44.v2.utils.getConversationKey(peer.sk, A.g));
  const payload = JSON.stringify({ vault: 'd0'.repeat(32), keys: { ['aa'.repeat(16)]: 'bb'.repeat(32) } });
  const reader = newKey();
  const vroot = bytesToHex(randomBytes(32)), vid = 'e0'.repeat(32);
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-kv-')), 'device.json');
  writeFileSync(snap, B.snapshot());
  net.kill(B.kp.pub);
  const cmds = join(dirname(snap), 'cmds.json');
  writeFileSync(cmds, JSON.stringify([
    { cmd: 'vault_ksig', app: APP, root: vroot },                         // before the grant: declined
    { cmd: 'vault_allow', app: APP },
    { cmd: 'vault_ksig', app: APP, root: vroot },
    { cmd: 'vault_derive', app: APP, domain: 'nostr-vault/owner/1', bytes: vid },
    { cmd: 'vault_derive', app: APP, domain: 'nostr-vault/ksig/1', bytes: vid },
    { cmd: 'vault_sign', app: APP, kind: 4811, content: JSON.stringify({ root: vroot, type: 'device' }) },
    { cmd: 'vault_sign', app: APP, kind: 1, content: 'not a vault kind' },
    { cmd: 'vault_invite', app: APP, rumor: { kind: 4812, tags: [], content: payload }, to: reader.pub },
    { cmd: 'vault_invite', app: APP, rumor: { kind: 14, tags: [], content: 'a DM' }, to: reader.pub },
    { cmd: 'vault_unwrap', app: APP, wrap: toSelf },
    { cmd: 'vault_decrypt', app: APP, peer: peer.pub, payload: enc(payload) },
    { cmd: 'vault_decrypt', app: APP, peer: peer.pub, payload: enc('a private message') },
  ]));
  const r = spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${snap} ${relays.join(',')} ${cmds}`], { env: { ...process.env, JAVA_HOME: java }, encoding: 'utf8', timeout: 300_000 });
  const all = r.stdout.trim().split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l));
  assert.equal(all[0]?.device, B.kp.pub, r.stdout + r.stderr.slice(-800));
  const [early, allowed, ksig, derived, badDomain, cert, kind1, wrap, badInvite, unwrapped, plain, dm] = all.slice(1);
  assert.equal(early.error, 'declined', 'nothing before the grant');
  assert.deepEqual(allowed.allowed, [APP]);
  assert.equal(ksig.mk, B.kp.pub); assert.ok(memberVerify(ksig.ksig, 'nostr-vault/ksig/1', Buffer.from(vroot, 'hex'), B.kp.pub));
  assert.equal(derived.key, bytesToHex(A.vault.derive(APP, derived.ids, 'nostr-vault/owner/1', Buffer.from(vid, 'hex'))), 'the same owner key as TS');
  assert.equal(badDomain.error, 'declined');
  assert.ok(verifyEvent(cert) && cert.pubkey === A.g && cert.kind === 4811, JSON.stringify(cert));
  assert.equal(kind1.error, 'declined');
  assert.equal(wrap.kind, 1059); assert.ok(verifyEvent(wrap));
  const seal = JSON.parse(nip44Open(wrap.content, nip44.v2.utils.getConversationKey(reader.sk, wrap.pubkey)));
  assert.ok(verifyEvent(seal) && seal.kind === 13 && seal.pubkey === A.g);
  const rumor = JSON.parse(nip44Open(seal.content, nip44.v2.utils.getConversationKey(reader.sk, A.g)));
  assert.deepEqual([rumor.kind, rumor.pubkey, rumor.content, rumor.id], [4812, A.g, payload, eventId(rumor)]);
  assert.equal(badInvite.error, 'declined');
  assert.equal(unwrapped.seal, A.g, JSON.stringify(unwrapped)); assert.equal(unwrapped.rumor.kind, 4812);
  assert.equal(plain.plain, payload);
  assert.equal(dm.error, 'declined');
});
