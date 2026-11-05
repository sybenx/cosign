// keykin/device: browser-safe, attached to a store, restored with the app's own lock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { create, invite } from '../sim/account.ts';
import { DeviceNode, softLock, verifyEvent, type Lock } from '../device/index.ts';

const ALLOWED_PKGS = /^(@noble\/(curves|hashes|ciphers)|@scure\/(base|bip39)|nostr-tools)(\/|$)/;

test('device/ bundles for a browser: no node: imports, no Buffer or process, only the allowed packages', () => {
  const seen = new Set<string>(), todo = [resolve(import.meta.dirname, '../device/index.ts')];
  while (todo.length) {
    const f = todo.pop()!;
    if (seen.has(f)) continue;
    seen.add(f);
    const src = readFileSync(f, 'utf8');
    for (const m of src.matchAll(/(?:import|export)\s[^'"]*?from\s+'([^']+)'|import\('([^']+)'\)/g)) {
      const spec = m[1] ?? m[2];
      if (spec.startsWith('.')) todo.push(resolve(dirname(f), spec));
      else assert.match(spec, ALLOWED_PKGS, `${f} imports ${spec}`);
    }
    const code = src.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    if (!f.endsWith('src/wasm.ts')) assert.doesNotMatch(code, /\bBuffer\.|\bprocess\.|require\(/, `${f} uses a Node global`);
  }
  assert.ok(seen.size > 25, `walked ${seen.size} files`);
  assert.ok(![...seen].some((f) => f.includes('/sim/') || f.includes('/server/')), 'nothing from sim/ or server/');
});

test('a device attached to a store saves itself and comes back from it, checked', async () => {
  const acc = await create();
  const saved = new Map<string, string>();
  const store = { save: (k: string, t: string) => void saved.set(k, t) };
  acc.A.attach(store);
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const key = acc.A.storeKey;
  assert.ok(JSON.parse(saved.get(key)!).changes.length >= 1, 'the add reached the store without an explicit save');
  const A2 = DeviceNode.restore(acc.bus, saved.get(key)!);
  acc.bus.nodes.set(A2.kp.pub, A2);
  assert.equal(A2.m!.devices.size, 2);
  assert.ok(verifyEvent(await A2.sign({ content: 'restored from the attached store' })));
  void B;
});

test('a hardware lock: only its public part is stored; the app reopens it on restore', async () => {
  const acc = await create();
  const soft = acc.A.lock!;
  // An app's lock that keeps its key to itself (as a Keystore or Secure Enclave key would).
  const hw: Lock = { pub: soft.pub, assert: (g, w, f) => soft.assert(g, w, f) };
  acc.A.lock = hw;
  const snap = acc.A.snapshot();
  assert.ok(!snap.includes((soft as any).stored().soft.sk), 'the lock key is not in the snapshot');
  assert.throws(() => DeviceNode.restore(acc.bus, snap), /lock_unavailable/);
  const back = DeviceNode.restore(acc.bus, snap, { lock: (stored) => (stored.pub.pub === hw.pub.pub ? hw : null) });
  assert.equal(back.lock, hw);
  acc.bus.nodes.set(back.kp.pub, back);
  acc.A = back;
  const C = await invite(acc, back, (l) => back.approveLock(l));
  assert.ok(verifyEvent(await C.sign({ content: 'approved by the reopened lock' })));
  void softLock;
});
