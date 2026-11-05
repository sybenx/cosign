// Doors 20 §2: vault machinery and vault material never reach a site, whatever the door.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { siteGuard, vaultPlaintext } from '../device/doors.ts';
import { create } from '../sim/account.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const g = 'ab'.repeat(32);
/** The cases every port checks alike (kotlin Doors20Test has the same list). */
export const CASES: [string, boolean][] = [
  [JSON.stringify({ kind: 4812, pubkey: g, content: 'hi', tags: [], created_at: 1 }), true],
  [JSON.stringify({ vault: 'v1', keys: [] }), true],
  [JSON.stringify({ vault: 'v1', secret: 'x' }), true],
  [JSON.stringify({ vault: 'v1', genesis: {} }), true],
  [JSON.stringify({ kind: 14, pubkey: g, tags: [], created_at: 1, content: JSON.stringify({ vault: 'v', inboxes: [] }) }), true],
  [JSON.stringify({ vault: 'v1', name: 'Family' }), false],
  [JSON.stringify({ kind: 14, pubkey: g, tags: [], created_at: 1, content: 'a message' }), false],
  ['a private note', false],
  [JSON.stringify([['p', 'x']]), false],
];

test('vault plaintexts: a kind-4812 rumor, or vault with a secret field at the top or in a rumor\'s content', () => {
  for (const [t, want] of CASES) assert.equal(vaultPlaintext(t), want, t);
});

test('no site signs vault machinery, or deletes it by e, a or k', () => {
  for (const kind of [4810, 4811, 30811]) assert.throws(() => siteGuard({ kind, tags: [] }, g, []), /vault machinery/);
  assert.throws(() => siteGuard({ kind: 5, tags: [['k', '4811']] }, g, []), /vault/);
  assert.throws(() => siteGuard({ kind: 5, tags: [['a', `30811:${g}:keyring`]] }, g, []), /vault/);
  assert.throws(() => siteGuard({ kind: 5, tags: [['e', 'cd'.repeat(32)]] }, g, [], new Set(), () => 4810), /vault/);
  siteGuard({ kind: 5, tags: [['e', 'cd'.repeat(32)]] }, g, [], new Set(), () => 1);
  siteGuard({ kind: 1, tags: [] }, g, []);
});

test('through NIP-46: a dms client can\'t read a vault invitation, nor have one encrypted', async () => {
  const acc = await create();
  const A = acc.A, bus = acc.bus, key = newKey();
  const call = async (signer: string, method: string, params: string[] = []) => {
    const id = bytesToHex(randomBytes(8)), ck = nip44.v2.utils.getConversationKey(key.sk, signer);
    const reply = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (r: any) => { const x = JSON.parse(nip44.v2.decrypt(r.content, ck)); if (x.id === id) { w.close(); res(x); } }); });
    await bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, key.sk));
    return reply;
  };
  const u = new URL(A.nip46.mintBunker(['ws://relay.test'], 'dm-client', ['sign-in', 'dms'])), signer = u.hostname;
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  const peer = newKey();
  const invite = JSON.stringify({ kind: 4812, pubkey: peer.pub, tags: [], created_at: bus.now, content: '{}' });
  const ct = nip44.v2.encrypt(invite, nip44.v2.utils.getConversationKey(peer.sk, A.g));
  assert.match((await call(signer, 'nip44_decrypt', [peer.pub, ct])).error, /^declined: vault/);
  assert.match((await call(signer, 'nip44_encrypt', [peer.pub, invite])).error, /^declined: vault/);
  const note = nip44.v2.encrypt('hello', nip44.v2.utils.getConversationKey(peer.sk, A.g));
  assert.equal((await call(signer, 'nip44_decrypt', [peer.pub, note])).result, 'hello', 'other messages still read');
});
