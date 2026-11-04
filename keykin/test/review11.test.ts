// Review 11's findings in NIP-46 and watching, each as a regression test (in-memory bus).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create, invite } from '../sim/account.ts';
import { DeviceNode } from '../device/node.ts';
import { parseNostrconnect } from '../device/nip46.ts';
import { newKey } from '../src/event.ts';
import { signpostD } from '../src/codes.ts';
import { msg } from '../src/msg.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { Bus } from '../sim/bus.ts';

function client(bus: Bus, key = newKey()) {
  return {
    key,
    event(signer: string, method: string, params: string[] = [], at = bus.now) {
      const id = bytesToHex(randomBytes(8));
      const ck = nip44.v2.utils.getConversationKey(key.sk, signer);
      return { id, e: finalizeEvent({ kind: 24133, created_at: at, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, key.sk) };
    },
    async call(signer: string, method: string, params: string[] = []) {
      const { id, e } = this.event(signer, method, params);
      const ck = nip44.v2.utils.getConversationKey(key.sk, signer);
      const reply = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (r) => { const x = JSON.parse(nip44.v2.decrypt(r.content, ck)); if (x.id === id) { w.close(); res(x); } }); });
      await bus.events.publishEvent(e);
      return Promise.race([reply, new Promise((r) => setTimeout(() => r({ error: 'timeout' }), 1500))]) as Promise<any>;
    },
  };
}
const connected = async (acc: any) => {
  const u = new URL(acc.A.nip46.mintBunker(['ws://relay.test']));
  const c = client(acc.bus); const signer = u.hostname;
  assert.equal((await c.call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  return { c, signer };
};

test('H1: a site never gets the signpost, keykin- data, a deletion of either, or machinery signed', async () => {
  const acc = await create();
  const { c, signer } = await connected(acc);
  const d = signpostD(acc.A.m!.backupKey!);
  const at = acc.bus.now;
  for (const ev of [
    { kind: 30078, tags: [['d', d], ['n', '9'], ['h', '00']], content: 'attacker-chosen' },
    { kind: 30078, tags: [['d', d.toUpperCase()]], content: 'x' },
    { kind: 30078, tags: [['d', 'keykin-grants']], content: 'x' },
    { kind: 5, tags: [['a', `30078:${acc.g}:${d}`]], content: '' },
    { kind: 5, tags: [['a', `30078:${acc.g}:keykin-grants`]], content: '' },
    { kind: 1244, tags: [], content: '' }, { kind: 30242, tags: [['d', 'keykin']], content: '' }, { kind: 24302, tags: [], content: '{}' },
  ]) assert.match((await c.call(signer, 'sign_event', [JSON.stringify({ ...ev, created_at: at })])).error, /^declined:/, JSON.stringify(ev).slice(0, 60));
  assert.ok((await c.call(signer, 'sign_event', [JSON.stringify({ kind: 30078, tags: [['d', 'some-app']], content: 'ok', created_at: at })])).result, 'other app data is fine');
});

test('H2: no site decrypts what the account encrypted to itself', async () => {
  const acc = await create();
  const { c, signer } = await connected(acc);
  const mine = await acc.A.nip44(acc.g, 'wallet privkey', true);
  // Doors §1: the account's own data needs the scope its plaintext calls for, asked on the home, never silent.
  assert.match((await c.call(signer, 'nip44_decrypt', [acc.g, mine])).error, /^permission: private-data/);
  assert.match((await c.call(signer, 'nip04_decrypt', [acc.g, await acc.A.nip04(acc.g, 'x', true)])).error, /^permission: private-data/);
  assert.match((await c.call(signer, 'nip44_decrypt', [acc.g.toUpperCase(), mine])).error, /^permission: private-data/);
});

test('M1: a catch-up hands a waiting site request to the home', async () => {
  const acc = await create();
  const S = acc.servers[0]; S.watchDelayMs = 10;
  const { c, signer } = await connected(acc);
  await acc.A.nip46.watchSet(S.kp.pub);
  acc.A.nip46.sleep();
  const { e } = c.event(signer, 'ping');
  const ck = nip44.v2.utils.getConversationKey(c.key.sk, signer);
  const got = new Promise<any>((res) => { const w = acc.bus.events.watch({ kinds: [24133], authors: [signer] }, (r) => { w.close(); res(JSON.parse(nip44.v2.decrypt(r.content, ck))); }); });
  await acc.bus.events.publishEvent(e);
  await acc.A.fetch();
  assert.equal((await got).result, 'pong');
});

test('M3, M4: a code with too many relays is trimmed; a watching server that is down never breaks connecting', async () => {
  const many = Array.from({ length: 12 }, (_, k) => `relay=${encodeURIComponent(`wss://r${k % 10}.test`)}`).join('&');
  assert.equal(parseNostrconnect(`nostrconnect://${newKey().pub}?${many}`).relays.length, 8);
  const acc = await create();
  const S = acc.servers[0];
  await acc.A.nip46.watchSet(S.kp.pub);
  acc.bus.kill(S.kp.pub);
  const { c, signer } = await connected(acc);
  assert.equal((await c.call(signer, 'ping')).result, 'pong');
  assert.ok(acc.A.nip46.watchPending, 'sent again on the next wake');
});

test('M5: an old request is ignored, and a seen one stays seen across a restart', async () => {
  const acc = await create();
  const { c, signer } = await connected(acc);
  const { e } = c.event(signer, 'sign_event', [JSON.stringify({ kind: 1, content: 'once', tags: [], created_at: acc.bus.now })]);
  assert.equal(await acc.A.nip46.handle(e), true);
  const back = DeviceNode.restore(acc.bus, acc.A.snapshot());
  assert.equal(await back.nip46.handle(e), false, 'not answered twice');
  assert.equal(await acc.A.nip46.handle(c.event(signer, 'ping', [], acc.bus.now - 600).e), false, 'ten minutes old');
});

test('M6, L1, L2: one site can\'t crowd out another; a stale event never uses up a link; one home per signer key', async () => {
  const acc = await create();
  const S = acc.servers[0]; S.watchDelayMs = 10;
  const a = await connected(acc), b = await connected(acc);
  await acc.A.nip46.watchSet(S.kp.pub);
  acc.A.nip46.sleep();
  for (let k = 0; k < 40; k++) await acc.bus.events.publishEvent(a.c.event(a.signer, 'ping').e);
  await acc.bus.events.publishEvent(b.c.event(b.signer, 'get_public_key').e);
  const items = S.inbox.items.filter((x) => x.to === acc.A.kp.pub);
  assert.equal(items.filter((x) => x.group === `nip46:${a.signer}`).length, 8);
  assert.equal(items.filter((x) => x.group === `nip46:${b.signer}`).length, 1, 'B still got through');
  // L1: a link's single forward isn't spent on a stale event.
  const link = new URL(acc.A.nip46.mintBunker(['ws://relay.test']));
  await acc.A.nip46.watchSet(S.kp.pub);
  const cl = client(acc.bus);
  await acc.bus.events.publishEvent(cl.event(link.hostname, 'connect', [link.hostname, link.searchParams.get('secret')!], acc.bus.now - 600).e);
  await acc.bus.events.publishEvent(cl.event(link.hostname, 'connect', [link.hostname, link.searchParams.get('secret')!]).e);
  assert.equal(S.inbox.items.filter((x) => x.group === `nip46:${link.hostname}`).length, 1);
  // L2: another device can't claim this home's signer key.
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const r = await acc.bus.send(B.kp, S.kp.pub, msg('watch_set', acc.g, acc.epochId, 'ask', { grants: [{ signer: a.signer, client: a.c.key.pub, relays: ['ws://relay.test'] }] }));
  assert.equal(r.code, 'malformed');
});

test('L5: a peer key that is no point is refused before any co-signer is asked', async () => {
  const acc = await create();
  let asked = 0; const send = acc.bus.send.bind(acc.bus);
  (acc.bus as any).send = (f: any, t: string, b: any, o?: any) => { if (b?.type === 'ecdh') asked++; return send(f, t, b, o); };
  await assert.rejects(acc.A.ecdhX('f'.repeat(64)), /malformed/);
  await assert.rejects(acc.A.ecdhX('xyz'), /malformed/);
  assert.equal(asked, 0);
});
