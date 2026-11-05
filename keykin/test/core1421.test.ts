// Core 14.21: every data-key seed reaches the paper (§4.5, §7.2, F7, F11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, recover } from '../sim/account.ts';
import { bytesToHex } from '../src/bytes.ts';
import { openSeeds, seedOnlyItem, checkSeedOnly, unpackSeeds, packSeeds } from '../src/upkeep.ts';
import { newKey } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const redeal = async (A: any) => { const r: Change[] = [{ redeal: { dealer: A.kp.pub } }]; await A.submit(r, A.approveLock(r)); };

test('the gap: after a new paper, a paper-only recovery still reads data written under earlier states', async () => {
  const acc = await create();
  const A = acc.A;
  await redeal(A);
  const s1 = A.dataKeys.current();                          // data written under the state after the first redeal
  await redeal(A);
  const K = await A.newPaper((l) => A.approveLock(l));      // its base names the state after the second redeal
  await redeal(A);                                          // a later redeal: its seed comes in its paper item
  const s3 = A.dataKeys.current();
  const pc = A.m!.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === K.pub)!;
  assert.equal((pc.c.change as any).paper.seeds.length, 2, 'the paper lists both earlier redeals\' seeds');
  const { D } = await recover(acc, [A], K);
  assert.equal(bytesToHex(D.dataKeys.forState(s1.state)!), bytesToHex(s1.key), 'the state before the paper');
  assert.equal(bytesToHex(D.dataKeys.forState(s3.state)!), bytesToHex(s3.key), 'the state after it');
});

test('the printer asks for a seed it lacks; the device it asks sees a quiet line, not "restored its pieces"', async () => {
  const acc = await create();
  const A = acc.A, B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  await B.fetch(); await A.fetch();
  await redeal(A); await B.fetch();
  const lost = A.seedRecords()[0].seed;
  A.dkSeeds = A.dkSeeds.filter((x: string) => x !== lost);   // A's copy is gone; B still has it
  await A.newPaper((l) => A.approveLock(l));
  assert.ok(A.dkSeeds.includes(lost), 'asked of B and kept');
  assert.ok(B.notices.some((n) => n.kind === 'making_paper'));
  assert.ok(!B.notices.some((n) => n.kind === 'need_seeds'), 'no "restored its pieces" for the printer\'s own F7');
});

test('every device re-issues every seed it holds to the new K as seed-only items; two servers keep them', async () => {
  const acc = await create();
  const A = acc.A, B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  await B.fetch(); await A.fetch();
  await redeal(A); await B.fetch();
  const K = await A.newPaper((l) => A.approveLock(l));
  await B.fetch();
  const held = acc.servers.filter((s) => s.items.some((x) => x.kind === 'seed-only' && x.by === B.kp.pub && x.to === K.pub));
  assert.ok(held.length >= 2, `held by ${held.length} servers`);
  const item = held[0].items.find((x) => x.kind === 'seed-only' && x.by === B.kp.pub)!;
  const pc = B.m!.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === K.pub)!;
  const pr = [...B.m!.redeals.values()].find((x) => x.listHash === pc.listHash)!.r.id;
  const got = openSeeds([item], B.seeds.get(pr)!, K.sk, [...B.m!.redeals.values()].map((x) => x.r));
  for (const x of B.seedRecords()) assert.equal(got.get(x.id), x.seed, 'K opens every seed B holds');
  // A server keeps the first per device, redeal and K, and refuses one for another key.
  const other = seedOnlyItem(acc.g, B.kp, newKey().pub, pr, B.seeds.get(pr)!, B.seedRecords().map((x) => [x.id, x.seed]));
  assert.equal(checkSeedOnly(acc.g, other, B.m!.backupKey, pr, () => true), 'not_current_backup');
  const forged = { ...item, sig: '00'.repeat(64) };
  assert.equal(checkSeedOnly(acc.g, forged, K.pub, pr, () => true), 'bad_signature');
});

test('welcomes and need_seeds carry seeds as {id, seed}, each kept only if it matches its redeal\'s dk', async () => {
  const acc = await create();
  const A = acc.A; await redeal(A);
  const recs = A.seedRecords();
  assert.ok(recs.length >= 1 && recs.every((x) => /^[0-9a-f]{32}$/.test(x.id) && /^[0-9a-f]{64}$/.test(x.seed)));
  const before = A.dkSeeds.length;
  A.takeSeedRecords([{ id: recs[0].id, seed: 'ab'.repeat(32) }, 'cd'.repeat(32)]);
  assert.equal(A.dkSeeds.length, before, 'a seed matching no dk is refused');
  // Records round-trip as binary id ‖ seed.
  assert.deepEqual(unpackSeeds(packSeeds(recs.map((x) => [x.id, x.seed]))), recs.map((x) => [x.id, x.seed]).sort((a, b) => (a[0] < b[0] ? -1 : 1)));
});

test('dataKeys.derive: a key derived from a real state\'s data key under a granted domain, never the key itself', async () => {
  const { hkdf } = await import('@noble/hashes/hkdf.js');
  const { sha256 } = await import('@noble/hashes/sha2.js');
  const acc = await create();
  const A = acc.A; await redeal(A); await redeal(A);
  const { registerDomain } = await import('../device/membersig.ts');
  registerDomain('nostr-vault/keyring/1');                  // a vault app registers its domain at load
  const app = A.dataKeys.forApps();
  const { ids, state } = app.current();
  assert.equal(state, A.dataKeys.current().state);
  assert.ok(!('key' in app.current()), 'the app never sees dk(S)');
  const bytes = new TextEncoder().encode('vault 1');
  const want = hkdf(sha256, A.dataKeys.current().key, new Uint8Array(0), new Uint8Array([...new TextEncoder().encode('nostr-vault/keyring/1'), 0, ...bytes]), 32);
  assert.equal(bytesToHex(app.derive(ids, 'nostr-vault/keyring/1', bytes)), bytesToHex(want));
  assert.throws(() => app.derive(ids, 'keykin-dk/1', bytes), /bad_domain/, 'Core\'s own domains are never an app\'s');
  assert.throws(() => app.derive(ids, 'some-app/x/1', bytes), /bad_domain/, 'an ungranted domain');
  const later = ids.find((id) => (A.m!.redeals.get(id)!.r.base ?? []).length > 0)!;
  assert.throws(() => app.derive([later], 'nostr-vault/keyring/1', bytes), /not_a_state/, 'a redeal without its base');
  assert.throws(() => app.derive(['ff'.repeat(16)], 'nostr-vault/keyring/1', bytes), /not_a_state/);
  assert.equal(app.states()[0].state, state, 'newest first');
});
