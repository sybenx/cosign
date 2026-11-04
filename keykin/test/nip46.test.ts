// Doors §3.3: NIP-46 at its home, and the wake path through a watching server. Over the in-memory bus,
// with a NIP-46 client written from the NIP (the e2e test adds nak and nostr-tools' BunkerSigner).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create, invite } from '../sim/account.ts';
import { DeviceNode } from '../device/node.ts';
import { newKey, verifyEvent } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import type { Bus } from '../sim/bus.ts';

/** A NIP-46 client: one request at a time, the reply awaited on the bus's relay. */
function client(bus: Bus, key = newKey()) {
  return {
    key,
    async call(signer: string, method: string, params: string[] = []) {
      const id = bytesToHex(randomBytes(8));
      const ck = nip44.v2.utils.getConversationKey(key.sk, signer);
      const reply = new Promise<any>((res) => {
        const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (e) => {
          const r = JSON.parse(nip44.v2.decrypt(e.content, ck)); if (r.id === id) { w.close(); res(r); }
        });
      });
      await bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, key.sk));
      return Promise.race([reply, new Promise((r) => setTimeout(() => r({ error: 'timeout' }), 1500))]) as Promise<any>;
    },
  };
}
const bunker = (link: string) => { const u = new URL(link); return { signer: u.hostname, secret: u.searchParams.get('secret')! }; };

test('a bunker link: connect binds the first client; every method; another client and an old link are refused', async () => {
  const acc = await create();
  const bus = acc.bus as Bus;
  const link = acc.A.nip46.mintBunker(['ws://relay.test'], 'nak');
  const { signer, secret } = bunker(link);
  const c = client(bus);
  assert.equal((await c.call(signer, 'connect', [signer, secret])).result, 'ack');
  assert.equal((await c.call(signer, 'connect', [signer, secret])).result, 'ack', 'the same client may connect again');
  assert.match((await client(bus).call(signer, 'connect', [signer, secret])).error, /^not-connected:/, 'any other key is refused');
  assert.equal((await c.call(signer, 'get_public_key')).result, acc.g, 'the account, not the signer key');
  assert.equal((await c.call(signer, 'ping')).result, 'pong');
  const signed = JSON.parse((await c.call(signer, 'sign_event', [JSON.stringify({ kind: 1, content: 'via nip46', tags: [], created_at: bus.now })])).result);
  assert.ok(verifyEvent(signed) && signed.pubkey === acc.g);
  const peer = newKey();
  const ct = (await c.call(signer, 'nip44_encrypt', [peer.pub, 'secret note'])).result;
  assert.equal(nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(peer.sk, acc.g)), 'secret note');
  assert.equal((await c.call(signer, 'nip44_decrypt', [peer.pub, ct])).result, 'secret note');
  assert.match((await c.call(signer, 'sign_event', [JSON.stringify({ kind: 62, content: '', tags: [], created_at: bus.now })])).error, /^held:/, 'a destructive event is held');
  assert.match((await c.call(signer, 'nip57_whatever')).error, /^unsupported:/);
  assert.match((await client(bus).call(signer, 'get_public_key')).error, /^not-connected:/);
  // A link unused for 10 minutes is dead.
  const late = bunker(acc.A.nip46.mintBunker(['ws://relay.test']));
  bus.advance(601);
  assert.match((await client(bus).call(late.signer, 'connect', [late.signer, late.secret])).error, /^not-connected:/);
  // logout ends the grant: revoked from then on.
  assert.equal((await c.call(signer, 'logout')).result, 'ack');
  assert.match((await c.call(signer, 'get_public_key')).error, /^revoked:/);
});

test('a nostrconnect code: the reply carries its secret, and the grant is bound to its client', async () => {
  const acc = await create();
  const bus = acc.bus as Bus;
  const c = client(bus);
  const got = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], '#p': [c.key.pub] }, (e) => { w.close(); res(e); }); });
  const g = await acc.A.nip46.acceptNostrconnect(`nostrconnect://${c.key.pub}?relay=${encodeURIComponent('ws://relay.test')}&secret=s3cr3t&name=Site`);
  const e = await got;
  assert.equal(JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(c.key.sk, g.signer))).result, 's3cr3t');
  assert.equal((await c.call(g.signer, 'get_public_key')).result, acc.g);
});

test('watching: a sleeping home is woken by one push per burst, drains its inbox, and answers', async () => {
  const acc = await create();
  const bus = acc.bus as Bus;
  const S = acc.servers[0];
  S.watchDelayMs = 30;
  await acc.A.registerPush();
  const { signer, secret } = bunker(acc.A.nip46.mintBunker(['ws://relay.test']));
  const c = client(bus);
  assert.equal((await c.call(signer, 'connect', [signer, secret])).result, 'ack');
  await acc.A.nip46.watchSet(S.kp.pub);
  // Awake and answering: the server sees the reply and doesn't push.
  assert.equal((await c.call(signer, 'ping')).result, 'pong');
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(acc.A.readPushes().length, 0, 'no push while the home answers');
  // Asleep: two requests in a burst, one push; the woken home answers both.
  acc.A.nip46.sleep();
  const p1 = c.call(signer, 'get_public_key'), p2 = c.call(signer, 'ping');
  await new Promise((r) => setTimeout(r, 120));
  const pushes = acc.A.readPushes();
  assert.equal(pushes.length, 1, 'one push for the burst');
  assert.equal(pushes[0].srv, S.host.pub);
  acc.A.nip46.listen();
  assert.equal(await acc.A.nip46.wake(), 2, 'both requests drained from the inbox');
  assert.deepEqual([(await p1).result, (await p2).result], [acc.g, 'pong']);
  // The home's grants survive a restart, and so does the server's watch.
  const back = DeviceNode.restore(bus, acc.A.snapshot());
  assert.equal(back.nip46.grants.size, 1);
  assert.equal(back.nip46.watching, S.kp.pub);
  assert.equal(JSON.parse(S.snapshot()).watches.length, 1);
});

test('watching: only from a current device about its own grants; a removed home is dropped', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const S = acc.servers[0];
  const { msg } = await import('../src/msg.ts');
  assert.equal((await acc.bus.send(acc.paper, S.kp.pub, msg('watch_set', acc.g, acc.epochId, 'ask', { grants: [] }))).code, 'not_device');
  B.nip46.mintBunker(['ws://relay.test']);
  await B.nip46.watchSet(S.kp.pub);
  assert.ok(S.watches.has(B.kp.pub));
  const list: any[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  const g = [...B.nip46.grants.values()][0] ?? { signer: S.watches.get(B.kp.pub)![0].signer };
  const c = client(acc.bus as Bus);
  await c.call(g.signer, 'ping');
  assert.ok(!S.watches.has(B.kp.pub), 'dropped once the home is removed');
});

test('review 11 L4: a held event waits on its home; the lock approves it, or a hold passes; the home publishes it', async () => {
  const acc = await create();
  const bus = acc.bus as Bus;
  const { signer, secret } = bunker(acc.A.nip46.mintBunker(['ws://relay.test']));
  const c = client(bus);
  await c.call(signer, 'connect', [signer, secret]);
  const vanish = { kind: 62, content: '', tags: [['relay', 'ALL_RELAYS']], created_at: bus.now };
  assert.match((await c.call(signer, 'sign_event', [JSON.stringify(vanish)])).error, /^held:/);
  const [h] = [...acc.A.nip46.held.values()];
  assert.ok(h && h.event.kind === 62);
  const published = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [62] }, (e) => { w.close(); res(e); }); });
  const signed = await acc.A.nip46.approveHeld(h.id);
  assert.ok(verifyEvent(signed) && signed.pubkey === acc.g);
  assert.equal((await published).id, signed.id, 'the home published it itself');
  assert.equal(acc.A.nip46.held.size, 0);
  // Declined: gone, nothing signed. And a held event survives a restart.
  await c.call(signer, 'sign_event', [JSON.stringify({ ...vanish, created_at: bus.now + 1 })]);
  const [h2] = [...acc.A.nip46.held.values()];
  assert.equal(DeviceNode.restore(bus, acc.A.snapshot()).nip46.held.size, 1);
  acc.A.nip46.declineHeld(h2.id);
  assert.equal(acc.A.nip46.held.size, 0);
});

test('review 11 L4, lockless: a hold at every server, and once its wait passes the event is signed unchanged', async () => {
  const acc = await create({ lockless: true });
  const bus = acc.bus as Bus;
  const { signer, secret } = bunker(acc.A.nip46.mintBunker(['ws://relay.test']));
  const c = client(bus);
  await c.call(signer, 'connect', [signer, secret]);
  await c.call(signer, 'sign_event', [JSON.stringify({ kind: 62, content: '', tags: [], created_at: bus.now })]);
  const [h] = [...acc.A.nip46.held.values()];
  await assert.rejects(acc.A.nip46.approveHeld(h.id), /needs_approval/);
  await acc.A.nip46.holdHeld(h.id);
  await assert.rejects(acc.A.nip46.releaseHeld(h.id), /hold_not_passed|needs_approval|no_answer/);
  bus.advance(acc.servers[0].co!.W + 1);
  const signed = await acc.A.nip46.releaseHeld(h.id);
  assert.equal(signed.id, h.event.id, 'unchanged: the hold was on its event id');
  assert.ok(verifyEvent(signed));
});
