// The door-neutral request path (device/doors-request.ts): the extension's NIP-07 door asks with a grant entry id, and
// gets exactly the checks the NIP-46 home's sites get (the NIP-46 cases elsewhere run through the same path).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { create } from '../sim/account.ts';
import { newKey, verifyEvent } from '../src/event.ts';
import { KIND_EPOCH } from '../src/types.ts';

const O = { origin: 'https://site.example' };
async function setup(scopes: any[]) {
  const acc = await create();
  const A = acc.A;
  const e = A.grants.make({ site: 'https://site.example', says: 'site.example', door: 'nip07', connection: 'https://site.example', scopes });
  return { acc, A, id: e.id };
}

test('NIP-07: the public key and a post only with their scopes; an ask is recorded for the person', async () => {
  const { A, id } = await setup(['post']);
  assert.match((await A.doors.request(id, 'get_public_key', [], O)).error!, /^permission: sign-in/);
  assert.deepEqual([...A.doors.asks.get(id)!], ['sign-in']);
  A.doors.allowScope(id, 'sign-in');
  assert.equal((await A.doors.request(id, 'get_public_key', [], O)).result, A.g);
  const r = await A.doors.request(id, 'sign_event', [JSON.stringify({ kind: 1, content: 'gm from a NIP-07 site', tags: [], created_at: A.now })], O);
  const ev = JSON.parse(r.result!);
  assert.ok(verifyEvent(ev) && ev.pubkey === A.g);
  assert.match((await A.doors.request(id, 'sign_event', [JSON.stringify({ kind: 10000, content: '', tags: [] })], O)).error!, /^permission: lists/);
});

test('NIP-07: the account\'s machinery and vault kinds are never a site\'s, whatever its scopes', async () => {
  const { A, id } = await setup(['sign-in', 'post', 'lists', 'dms', 'private-data']);
  for (const kind of [KIND_EPOCH, 4810, 4811, 30811]) {
    const r = await A.doors.request(id, 'sign_event', [JSON.stringify({ kind, content: '{}', tags: kind === 30811 ? [['d', 'x']] : [] })], O);
    assert.match(r.error!, /^declined/, `kind ${kind}`);
  }
  assert.match((await A.doors.request(id, 'nip44_encrypt', [A.g, JSON.stringify({ vault: 'v', keys: {} })], O)).error!, /^declined: vault/);
});

test('NIP-07: messages need dms; to-self data is released only under the scope its plaintext needs', async () => {
  const { A, id } = await setup(['sign-in', 'post']);
  const peer = newKey();
  const dm = nip44.v2.encrypt('a private message', nip44.v2.utils.getConversationKey(peer.sk, A.g));
  assert.match((await A.doors.request(id, 'nip44_decrypt', [peer.pub, dm], O)).error!, /^permission: dms/);
  A.doors.allowScope(id, 'dms');
  assert.equal((await A.doors.request(id, 'nip44_decrypt', [peer.pub, dm], O)).result, 'a private message');
  // An encryption to the account itself (post), then its decrypt: this grant made it, but `post` isn't a to-self scope.
  const own = (await A.doors.request(id, 'nip44_encrypt', [A.g, 'my own note'], O)).result!;
  assert.ok(own);
  const back = await A.doors.request(id, 'nip44_decrypt', [A.g, own], O);
  assert.ok(back.result === 'my own note' || /^permission/.test(back.error ?? ''), JSON.stringify(back));
  // To-self ciphertext that no list event of this grant vouches for (Device policy §1's evidence) isn't released under
  // `lists`: it needs `private-data`.
  const items = await A.nip44(A.g, JSON.stringify([['p', newKey().pub]]), true);
  A.doors.allowScope(id, 'lists');
  assert.match((await A.doors.request(id, 'nip44_decrypt', [A.g, items], O)).error!, /^permission/);
  A.doors.allowScope(id, 'private-data');
  assert.equal(JSON.parse((await A.doors.request(id, 'nip44_decrypt', [A.g, items], O)).result!)[0][0], 'p');
});

test('NIP-07: a grant ended (here or on another device) answers nothing more', async () => {
  const { A, id } = await setup(['sign-in', 'post']);
  assert.equal((await A.doors.request(id, 'get_public_key', [], O)).result, A.g);
  A.grants.end(A.kp.pub, id);
  assert.match((await A.doors.request(id, 'get_public_key', [], O)).error!, /^revoked/);
  assert.match((await A.doors.request('ff'.repeat(16), 'get_public_key', [], O)).error!, /^revoked/);
});

test('NIP-07: unknown methods are refused; the asks and held events survive a restart', async () => {
  const { A, id } = await setup(['post']);
  assert.match((await A.doors.request(id, 'connect', [], O)).error!, /^unsupported/);
  await A.doors.request(id, 'get_public_key', [], O);
  const saved: Record<string, string> = {}; A.attach({ save: (k, t) => { saved[k] = t; } });
  const { DeviceNode } = await import('../device/node.ts');
  const B = DeviceNode.restore(A.bus, Object.values(saved)[0]);
  assert.deepEqual([...B.doors.asks.get(id)!], ['sign-in']);
});

// Red team 23: the extension's door only for its own nip07 grant; one held store across doors; a grant ended while the
// guard waits gets nothing signed; the caller can't claim to be the helper.
test('NIP-07: only a nip07 grant, and only for its own origin', async () => {
  const { A, id } = await setup(['sign-in']);
  const n46 = A.grants.make({ site: 'https://other.example', says: 'other.example', door: 'nip46', connection: 'abc', scopes: ['sign-in'] });
  assert.match((await A.doors.request(n46.id, 'get_public_key', [], O)).error!, /^not-connected/);
  assert.equal((await A.doors.request(id, 'get_public_key', [], { origin: 'https://site.example' })).result, A.g);
  assert.match((await A.doors.request(id, 'get_public_key', [], { origin: 'https://evil.example' })).error!, /^not-connected/);
});

test('a held change waiting at the NIP-46 home holds the extension\'s changes to that list too', async () => {
  const { A, id } = await setup(['sign-in', 'lists']);
  A.nip46.held.set('h1', { id: 'h1', signer: 'ab'.repeat(32), event: { kind: 3, tags: [], content: '', created_at: A.now }, at: A.now, wait: 'w' });
  assert.match((await A.doors.request(id, 'sign_event', [JSON.stringify({ kind: 3, content: '', tags: [] })], O)).error!, /^try-later: a held change/);
});

test('a site disconnected while the guard waits (Undo, a card) gets nothing signed', async () => {
  const { A, id } = await setup(['sign-in', 'post']);
  const serve = A.guard.serve.bind(A.guard);
  (A.guard as any).serve = async (ev: any, owner: string, scopes: any, sign: () => Promise<any>, ...rest: any[]) => (serve as any)(ev, owner, scopes, async () => { A.grants.end(A.kp.pub, id); return sign(); }, ...rest);
  const r = await A.doors.request(id, 'sign_event', [JSON.stringify({ kind: 1, content: 'late', tags: [] })], O);
  assert.match(r.error!, /^declined: this site was disconnected/);
});

test('a caller saying it is the helper is not believed on a device', async () => {
  const { A } = await setup([]);
  const caller = { entry: null, key: 'x', helper: true, has: () => false, hold: () => ({ error: 'held' }), heldWaiting: () => false };
  assert.match((await A.doors.answer(caller, 'sign_event', [JSON.stringify({ kind: 1, content: 'x', tags: [] })])).error!, /^not-connected/);
});
