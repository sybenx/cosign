// B1, Upkeep: a Kotlin device follows a redeal it slept through (core §6.7.1–§6.7.3). TS devices A, B and
// C share an account over three server processes; B's state goes to a Kotlin process before A removes C
// with a redeal. The Kotlin device fetches the list and its delivery from the servers' inboxes, applies
// the redeal, reports the removal with the post-redeal state, derives the new data key, and signs at the
// new state with a TS server.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg, invite } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';
import { stateOf } from '../src/redeal.ts';
import type { Change } from '../src/types.ts';

const root = join(import.meta.dirname, '..');
const java = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home';
const haveNak = spawnSync('nak', ['--version']).status === 0;
const haveJni = existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib')) || existsSync(join(root, 'frost/target/release/libkeykin_frost.so'));
const procs: ChildProcess[] = []; let net: RelayNet | undefined;
after(() => { net?.close(); procs.forEach((p) => p.kill('SIGTERM')); });
const relays = [17271, 17272].map((p) => `ws://127.0.0.1:${p}`);

function server(k: number, dir: string): Promise<string> {
  const proc = spawn(process.execPath, [join(root, 'server/main.ts')], { env: { PATH: process.env.PATH, KEYKIN_RELAYS: relays.join(','), KEYKIN_DATA: join(dir, 'data'), KEYKIN_KEYS: join(dir, 'keys'), KEYKIN_PORT: String(18771 + k) }, stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(proc);
  return new Promise((res, rej) => { let out = ''; proc.stdout!.on('data', (c) => { out += c; const l = out.split('\n').find((x) => x.includes('"started"')); if (l) res(JSON.parse(l).host); }); proc.on('exit', (c) => rej(new Error(`server exited ${c}`))); });
}

test('a Kotlin device applies a redeal it slept through, reports the removal and signs at the new state', { skip: (!haveNak && 'nak not installed') || (!haveJni && 'no JNI FROST library') || (!existsSync(java) && 'no JDK 21'), timeout: 420_000 }, async () => {
  for (const u of relays) procs.push(spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', u.split(':').pop()!], { stdio: 'ignore' }));
  await new Promise((r) => setTimeout(r, 1500));
  const fronts = await Promise.all([0, 1, 2].map((k) => server(k, mkdtempSync(join(tmpdir(), 'kk-ku-')))));
  net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const acc = await createByDkg({ net: net as any, fronts, relays });
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l));
  const C = await invite(acc, A, (l) => A.approveLock(l));
  await B.fetch();
  // B's state goes to the Kotlin process, asleep while A removes C (B's delivery waits in the inboxes).
  const snap = join(mkdtempSync(join(tmpdir(), 'kk-ku-')), 'device.json');
  writeFileSync(snap, B.snapshot());
  net.kill(B.kp.pub);
  const list: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  await A.submit(list, A.approveLock(list));
  const removedAt = stateOf(A.state!);
  // Core 14.21: a new paper while B sleeps; B, waking, re-issues every seed it holds to the new K as seed-only items.
  const K = await A.newPaper((l) => A.approveLock(l));
  const after = stateOf(A.state!);

  const cmds = join(dirname(snap), 'cmds.json');
  writeFileSync(cmds, JSON.stringify([{ cmd: 'fetch' }, { cmd: 'members' }, { cmd: 'datakey' }, { cmd: 'sign', content: 'gm from Kotlin after the redeal' },
    { cmd: 'seeds' }, { cmd: 'derive', domain: 'nostr-vault/keyring/1', bytes: 'vault 1' }]));
  const r = spawnSync(join(root, 'kotlin/gradlew'), ['-q', '-p', join(root, 'kotlin'), 'run', `--args=${snap} ${relays.join(',')} ${cmds}`], { env: { ...process.env, JAVA_HOME: java }, encoding: 'utf8', timeout: 300_000 });
  const all = r.stdout.trim().split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l));
  assert.equal(all[0]?.device, B.kp.pub, r.stdout + r.stderr.slice(-800));
  const [fetched, members, dk, ev, seeds, derived] = all.slice(1);
  assert.equal(fetched.state, after, `the Kotlin device reached A's state: ${JSON.stringify(fetched)}`);
  assert.deepEqual(members.keys.map((k: any) => k.key).sort(), [A.kp.pub, B.kp.pub].sort());
  assert.equal(members.removed.length, 1);
  assert.deepEqual([members.removed[0].key, members.removed[0].why, members.removed[0].state], [C.kp.pub, 'remove', removedAt], 'the removal, with the post-redeal state');
  const ts = A.dataKeys.current();
  assert.deepEqual([dk.state, dk.key], [ts.state, Buffer.from(ts.key).toString('hex')], 'the same data key at the new state');
  assert.equal(ev.error, undefined, JSON.stringify(ev));
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g, 'signed as the account at the new state');
  // The TS servers took the Kotlin device's seed-only items for K (they check the signature), two of them each.
  assert.ok(seeds.records >= 1 && seeds.held.length >= 1 && seeds.held.every((n: number) => n >= 2), JSON.stringify(seeds));
  void K;
  // An app's derived key is the same on a Kotlin and a TS device.
  const app = A.dataKeys.forApps();
  assert.equal(derived.key, Buffer.from(app.derive(derived.ids, 'nostr-vault/keyring/1', new TextEncoder().encode('vault 1'))).toString('hex'));
});
