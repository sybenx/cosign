// Review 12's TS findings, each as a regression test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create, invite, recover } from '../sim/account.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { Bus } from '../sim/bus.ts';
import type { Change } from '../src/types.ts';

function client(bus: Bus, key = newKey()) {
  return {
    async call(signer: string, method: string, params: string[] = []) {
      const id = bytesToHex(randomBytes(8)), ck = nip44.v2.utils.getConversationKey(key.sk, signer);
      const reply = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (r) => { const x = JSON.parse(nip44.v2.decrypt(r.content, ck)); if (x.id === id) { w.close(); res(x); } }); });
      await bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, key.sk));
      return Promise.race([reply, new Promise((r) => setTimeout(() => r({ error: 'timeout' }), 1500))]) as Promise<any>;
    },
  };
}
async function site(acc: any) {
  const u = new URL(acc.A.nip46.mintBunker(['ws://relay.test'])); const c = client(acc.bus); const signer = u.hostname;
  await c.call(signer, 'connect', [signer, u.searchParams.get('secret')!]);
  return { c, signer };
}

test('R1: a device recovered after the old devices were lost reads what they wrote', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const r: Change[] = [{ redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(r, acc.A.approveLock(r));
  const k0 = acc.A.dataKeys.current();
  const { D } = await recover(acc, [acc.A, B]);
  assert.equal(bytesToHex(D.dataKeys.forState(k0.state)!), bytesToHex(k0.key));
  assert.ok(D.dataKeys.states().includes(k0.state));
});

test('H1, H2: a held event dies with its grant; held events are capped and one per event', async () => {
  const acc = await create();
  const { c, signer } = await site(acc);
  const vanish = (n: number) => JSON.stringify({ kind: 62, content: '', tags: [['n', String(n)]], created_at: acc.bus.now });
  assert.match((await c.call(signer, 'sign_event', [vanish(0)])).error, /^held:/);
  assert.match((await c.call(signer, 'sign_event', [vanish(0)])).error, /^held:/);
  assert.equal(acc.A.nip46.held.size, 1, 'the same event twice is one entry');
  for (let k = 1; k < 12; k++) await c.call(signer, 'sign_event', [vanish(k)]);
  assert.equal(acc.A.nip46.held.size, 8, 'at most 8 per site');
  const [id] = acc.A.nip46.held.keys();
  await acc.A.nip46.end(signer);
  assert.equal(acc.A.nip46.held.size, 0, 'gone with the grant');
  await assert.rejects(acc.A.nip46.approveHeld(id), /unknown_held/);
});

test('H3: a newer version of a held list makes the site wait; the held one is dropped, never published', async () => {
  const acc = await create({ lockless: true });
  const { c, signer } = await site(acc);
  const at = acc.bus.now;
  assert.match((await c.call(signer, 'sign_event', [JSON.stringify({ kind: 3, content: '', tags: [], created_at: at })])).error, /^held:/);
  const [h] = acc.A.nip46.held.values();
  await acc.A.nip46.holdHeld(h.id);
  assert.match((await c.call(signer, 'sign_event', [JSON.stringify({ kind: 3, content: '', tags: [['p', 'ab'.repeat(32)]], created_at: at + 1 })])).error, /^try-later:/, 'the site waits while the hold runs');
  // The person's own app signs a newer follow list meanwhile.
  await acc.A.sign({ kind: 3, content: '', tags: [['p', 'cd'.repeat(32)]], created_at: at + 2 });
  acc.bus.advance(acc.servers[0].co!.W + 1);
  await assert.rejects(acc.A.nip46.releaseHeld(h.id), /superseded/);
  assert.ok(acc.A.notices.some((n) => n.kind === 'held_dropped'));
  assert.equal(acc.A.nip46.held.size, 0);
});

test('H4: with the last server down, a destructive event is still held, not try-later', async () => {
  const acc = await create();
  acc.bus.kill(acc.A.servers().at(-1)!.key);
  const { c, signer } = await site(acc);
  assert.match((await c.call(signer, 'sign_event', [JSON.stringify({ kind: 62, content: '', tags: [], created_at: acc.bus.now })])).error, /^held:/);
  assert.equal(acc.A.nip46.held.size, 1);
});

test('L3: a library hears when the device holds no data key any more', async () => {
  const acc = await create();
  let gone = 0;
  acc.A.dataKeys.onGone(() => gone++);
  acc.A.wipe();
  assert.equal(gone, 1);
  assert.throws(() => acc.A.dataKeys.current(), /no_data_key/);
});
