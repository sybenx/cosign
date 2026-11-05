// Doors 20 §3.7: the device calls for vault apps on the same machine, against ~/nostr-sync-nip/vectors/vaults.json
// (draft 7.13) where a vector applies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import * as nip44 from 'nostr-tools/nip44';
import { create } from '../sim/account.ts';
import { DeviceNode } from '../device/node.ts';
import { deriveFrom } from '../device/datakey.ts';
import { memberVerify } from '../device/membersig.ts';
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.ts';
import { eventId, newKey, verifyEvent, type NostrEvent } from '../src/event.ts';
import { finalizeEvent } from 'nostr-tools/pure';
import { nip44Open } from '../src/nip44.ts';

const VEC = join(homedir(), 'nostr-sync-nip/vectors/vaults.json');
const vec = existsSync(VEC) ? JSON.parse(readFileSync(VEC, 'utf8')) : null;
const APP = 'org.example.notes';
const reject = (p: Promise<unknown> | (() => unknown), code: string) =>
  typeof p === 'function' ? assert.throws(p as () => unknown, (e: any) => e.code === code) : assert.rejects(p, (e: any) => e.code === code);
const sealOf = (wrap: NostrEvent, sk: Uint8Array) => JSON.parse(nip44Open(wrap.content, nip44.v2.utils.getConversationKey(sk, wrap.pubkey)));

test('nothing until the person grants the set; the grant survives a restart and goes with a wipe', async () => {
  const acc = await create();
  const A = acc.A;
  reject(() => A.vault.ksig(APP, randomBytes(32)), 'declined');
  await reject(A.vault.sign(APP, { kind: 4811, content: '{}', tags: [] }), 'declined');
  A.vault.allow(APP);
  assert.deepEqual(A.vault.allowed(), [APP]);
  const saved: Record<string, string> = {}; A.attach({ save: (k, t) => { saved[k] = t; } });
  const B = DeviceNode.restore(A.bus, Object.values(saved)[0]);
  assert.deepEqual(B.vault.allowed(), [APP]);
  reject(() => A.vault.ksig('org.example.other', randomBytes(32)), 'declined');
  A.vault.revoke(APP);
  reject(() => A.vault.ksig(APP, randomBytes(32)), 'declined');
  B.wipe();
  assert.deepEqual(B.vault.allowed(), []);
});

test('ksig: the member key over nostr-vault/ksig/1 and the root\'s 32 bytes', async () => {
  const { A } = await create();
  A.vault.allow(APP);
  const root = randomBytes(32);
  const { mk, ksig } = A.vault.ksig(APP, root);
  assert.equal(mk, A.kp.pub, 'the device\'s own member key, never the account\'s');
  assert.ok(memberVerify(ksig, 'nostr-vault/ksig/1', root, mk));
  assert.ok(!memberVerify(ksig, 'nostr-vault/ksig/1', randomBytes(32), mk));
  reject(() => A.vault.ksig(APP, randomBytes(31)), 'malformed');
});

test('derive: the owner and keyring domains only, as vaults.json computes V and the keyring seal key', { skip: !vec && 'no vaults.json' }, async () => {
  const dk = hexToBytes(vec.inputs.dk_S);
  assert.equal(bytesToHex(deriveFrom(dk, 'nostr-vault/owner/1', hexToBytes(vec.inputs.vault_id))), vec.owner_secret.V);
  assert.equal(bytesToHex(deriveFrom(dk, 'nostr-vault/keyring/1', hexToBytes(vec.keyring.d))), vec.keyring.seal_key);
  const acc = await create();
  const A = acc.A;
  A.vault.allow(APP);
  const { ids, state } = A.vault.current(APP);
  assert.equal(state, A.dataKeys.current().state);
  const id = hexToBytes(vec.inputs.vault_id);
  assert.equal(bytesToHex(A.vault.derive(APP, ids, 'nostr-vault/owner/1', id)), bytesToHex(deriveFrom(A.dataKeys.current().key, 'nostr-vault/owner/1', id)));
  reject(() => A.vault.derive(APP, ids, 'nostr-vault/ksig/1', id), 'declined');
  reject(() => A.vault.derive(APP, ids, 'other-app/x/1', id), 'declined');
  assert.ok(A.vault.states(APP).length >= 1);
});

test('sign: a device cert as vaults.json has it, co-signed; nothing outside the vault kinds; kind 5 only of them', { skip: !vec && 'no vaults.json' }, async () => {
  const acc = await create({ nsec: vec.inputs.owner_npub_secret });
  const A = acc.A;
  assert.equal(A.g, vec.inputs.owner_npub);
  A.vault.allow(APP);
  const c = vec.owner_device.device_cert;
  const signed = await A.vault.sign(APP, { kind: c.kind, created_at: c.created_at, tags: c.tags, content: c.content });
  assert.equal(signed.id, c.id, 'the vector\'s id'); assert.ok(verifyEvent(signed));
  const kr = await A.vault.sign(APP, { kind: 30811, tags: [['d', vec.keyring.d]], content: vec.keyring.event_content });
  await reject(A.vault.sign(APP, { kind: 1, content: 'hi', tags: [] }), 'declined');
  await reject(A.vault.sign(APP, { kind: 13, content: 'x', tags: [] }), 'declined');
  const note = await A.sign({ kind: 1, content: 'a note', tags: [] });
  await reject(A.vault.sign(APP, { kind: 5, tags: [['e', note.id]], content: '' }), 'declined');
  await reject(A.vault.sign(APP, { kind: 5, tags: [['a', `30811:${A.g}:${vec.keyring.d}`], ['a', `30023:${A.g}:x`]], content: '' }), 'declined');
  await reject(A.vault.sign(APP, { kind: 5, tags: [['a', `30811:${newKey().pub}:x`]], content: '' }), 'declined');
  await reject(A.vault.sign(APP, { kind: 5, tags: [['k', '1']], content: '' }), 'declined');
  await reject(A.vault.sign(APP, { kind: 5, tags: [], content: '' }), 'declined');
  // A deletion of the account's own cert and keyring entry goes through Device policy (a card here), then is co-signed.
  const cards: string[] = [];
  A.guard.onCard = (c) => { cards.push(c.owner); A.guard.answer(c.id, 'allow'); };
  const del = await A.vault.sign(APP, { kind: 5, tags: [['e', signed.id], ['a', `30811:${A.g}:${vec.keyring.d}`], ['k', '4811'], ['k', '30811']], content: '' });
  assert.equal(del.kind, 5); assert.ok(verifyEvent(del)); assert.ok(kr);
  assert.deepEqual(cards, [`vault:${APP}`], 'the person saw the app\'s deletion');
});

test('invite: a 4812 rumor by the account, sealed by the account and wrapped by the device; never anything else', async () => {
  const acc = await create();
  const A = acc.A;
  A.vault.allow(APP);
  const reader = newKey();
  const content = JSON.stringify({ vault: 'b0'.repeat(32), name: 'Notes', keys: { ['aa'.repeat(16)]: 'bb'.repeat(32) } });
  const rumor = { pubkey: A.g, created_at: A.now, kind: 4812, tags: [], content };
  const wrap = await A.vault.invite(APP, rumor, reader.pub);
  assert.equal(wrap.kind, 1059); assert.ok(verifyEvent(wrap)); assert.deepEqual(wrap.tags, [['p', reader.pub]]);
  assert.notEqual(wrap.pubkey, A.g, 'a one-time key wraps it');
  const seal = sealOf(wrap, reader.sk);
  assert.equal(seal.kind, 13); assert.equal(seal.pubkey, A.g); assert.ok(verifyEvent(seal)); assert.deepEqual(seal.tags, []);
  assert.ok(seal.created_at <= A.now && seal.created_at > A.now - 2 * 86400);
  const r = JSON.parse(nip44Open(seal.content, nip44.v2.utils.getConversationKey(reader.sk, A.g)));
  assert.equal(r.kind, 4812); assert.equal(r.pubkey, A.g); assert.equal(r.id, eventId(r)); assert.equal(r.content, content); assert.equal(r.sig, undefined);
  await reject(A.vault.invite(APP, { ...rumor, kind: 14 }, reader.pub), 'declined');
  await reject(A.vault.invite(APP, { ...rumor, pubkey: reader.pub }, reader.pub), 'declined');
  await reject(A.vault.invite(APP, { ...rumor, sig: '00'.repeat(64) } as any, reader.pub), 'declined');
  await reject(A.vault.invite(APP, { ...rumor, id: '00'.repeat(32) }, reader.pub), 'malformed');
  await reject(A.vault.invite(APP, rumor, 'xyz'), 'malformed');
});

test('unwrap: a 4812 whose seal is the rumor\'s author, with the seal\'s pubkey; a forged seal or another kind is refused', async () => {
  const owner = await create(), reader = await create();
  owner.A.vault.allow(APP); reader.A.vault.allow(APP);
  const R = reader.A;
  const rumor = { pubkey: owner.A.g, created_at: owner.A.now, kind: 4812, tags: [], content: JSON.stringify({ vault: 'c0'.repeat(32), genesis: {} }) };
  const wrap = await owner.A.vault.invite(APP, rumor, R.g);
  const got = await R.vault.unwrap(APP, wrap);
  assert.equal(got.seal, owner.A.g); assert.equal(got.rumor.kind, 4812); assert.equal(got.rumor.content, rumor.content);
  // Hand-made wraps: a seal by someone else around the owner's rumor; a DM rumor from its true author.
  const mallory = newKey();
  const wrapOf = (sk: Uint8Array, r: any) => {
    const rr = { ...r, id: eventId(r) };
    const seal = finalizeEvent({ kind: 13, created_at: R.now, tags: [], content: nip44.v2.encrypt(JSON.stringify(rr), nip44.v2.utils.getConversationKey(sk, R.g)) }, sk);
    const eph = randomBytes(32);
    return finalizeEvent({ kind: 1059, created_at: R.now, tags: [['p', R.g]], content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(eph, R.g)) }, eph) as NostrEvent;
  };
  await reject(R.vault.unwrap(APP, wrapOf(mallory.sk, rumor)), 'declined');
  await reject(R.vault.unwrap(APP, wrapOf(mallory.sk, { ...rumor, pubkey: mallory.pub, kind: 14, content: 'a DM' })), 'declined');
  assert.equal((await R.vault.unwrap(APP, wrapOf(mallory.sk, { ...rumor, pubkey: mallory.pub }))).seal, mallory.pub, 'any author, checked by the reader against the genesis');
  await reject(R.vault.unwrap(APP, { ...wrap, content: wrap.content.slice(0, -4) + 'AAAA' }), 'declined');
});

test('decrypt: the vaults.json wrap to a reader opens; a DM, a rumor and junk don\'t', { skip: !vec && 'no vaults.json' }, async () => {
  const acc = await create({ nsec: vec.inputs.reader_npub_secret });
  const R = acc.A;
  assert.equal(R.g, vec.inputs.reader_npub);
  R.vault.allow(APP);
  const w = vec.wrap_to_reader.wrap;
  assert.equal(await R.vault.decrypt(APP, w.eph, w.ct), vec.wrap_to_reader.plaintext);
  const peer = newKey();
  const to = (text: string) => nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(peer.sk, R.g));
  await reject(R.vault.decrypt(APP, peer.pub, to('a private message')), 'declined');
  await reject(R.vault.decrypt(APP, peer.pub, to(JSON.stringify({ vault: 'x' }))), 'declined');
  await reject(R.vault.decrypt(APP, peer.pub, to(JSON.stringify({ kind: 4812, pubkey: peer.pub, created_at: 1, tags: [], content: JSON.stringify({ vault: 'x', keys: {} }) }))), 'declined');
  await reject(R.vault.decrypt(APP, peer.pub, 'AAAA'), 'declined');
  assert.equal(await R.vault.decrypt(APP, peer.pub, to(JSON.stringify({ vault: 'x', secret: 'y' }))), JSON.stringify({ vault: 'x', secret: 'y' }));
});
