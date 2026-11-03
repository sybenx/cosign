// Behaviour cases 10 (push and inbox) and 11 (transport).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wrap, unwrap, split, Reassembler, KIND_WRAP_LIVE, KIND_WRAP_STORED, PART_BYTES } from '../src/transport.ts';
import { pushPayload, readPush, Inbox, PushRegistry, PUSH_PLAIN, PER_PAIR, INBOX_ITEMS } from '../src/inbox.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

test('case 11: seal and wrap; the sender is the seal key', () => {
  const a = newKey(), b = newKey();
  const w = wrap(a.sk, b.pub, { v: 1, type: 'sign', id: '00'.repeat(16) });
  assert.equal(w.kind, KIND_WRAP_LIVE);
  const o = unwrap(b.sk, w);
  assert.equal(o.from, a.pub); assert.equal(o.body.type, 'sign');
  assert.equal(code(() => unwrap(newKey().sk, w)), 'undecryptable');
});

test('case 11: share-bearing messages are never sent as kind 1059', () => {
  const a = newKey(), b = newKey();
  for (const type of ['welcome', 'repair_sigma', 'delta', 'change', 'release_seed']) assert.equal(code(() => wrap(a.sk, b.pub, { type }, { stored: true })), 'never_stored');
  assert.equal(wrap(a.sk, b.pub, { type: 'notice' }, { stored: true, expiration: 1 }).kind, KIND_WRAP_STORED);
});

test('case 11: chunking and reassembly by sender; 513 KB refused; expired parts dropped', () => {
  const big = { v: 1, type: 'changes', cls: 'ask', data: bytesToHex(randomBytes(60_000)) };
  const parts = split(big);
  assert.ok(parts.length > 1 && parts.every((p) => JSON.stringify(p).length < PART_BYTES * 1.5));
  const R = new Reassembler();
  const t = 1000;
  // Interleave another sender's parts with the same `of`: reassembly is by (sender, of).
  const evil = parts.map((p) => ({ ...p, data: Buffer.from('x').toString('base64') }));
  let out = null;
  for (let k = 0; k < parts.length; k++) {
    try { R.take('mallory', evil[k], t); } catch { /* mallory's parts don't make a message */ }
    out = R.take('alice', parts[k], t) ?? out;
  }
  assert.deepEqual(out, big);
  assert.equal(code(() => split({ type: 'x', d: 'a'.repeat(513 * 1024) })), 'too_large');
  const R2 = new Reassembler();
  R2.take('alice', parts[0], t);
  R2.prune(t + 121 + 30);
  assert.equal(R2.pending, 0, 'an expired part is dropped');
});

test('case 10: push payload padding, size, signature', () => {
  const h = newKey(), other = newKey();
  const p1 = pushPayload(h, 'ask', 'aa'.repeat(16)), p2 = pushPayload(h, 'sign', 'bb'.repeat(16), { small: true });
  assert.equal(p1.length, PUSH_PLAIN); assert.equal(p2.length, PUSH_PLAIN);
  const big = pushPayload(h, 'ask', 'cc'.repeat(16), { blob: 'z'.repeat(5000) });
  assert.equal(readPush(big, new Set([h.pub])).wrap, undefined, 'wrap only if it fits');
  assert.equal(readPush(p2, new Set([h.pub])).wrap.small, true);
  assert.equal(code(() => readPush(p1, new Set([other.pub]))), 'unknown_server');
  const forged = new TextEncoder().encode(new TextDecoder().decode(p1).replace('"ask"', '"sig"'));
  assert.equal(code(() => readPush(forged, new Set([h.pub]))), 'bad_signature');
});

test('case 10: deliver, caps, p tag, removed senders', () => {
  const I = new Inbox(), a = newKey(), b = newKey(), bk = newKey();
  const members = new Set([a.pub, b.pub, bk.pub]), removed = new Set<string>();
  const ctx = { isMember: (k: string) => members.has(k), isRemoved: (k: string) => removed.has(k), isBackup: (k: string) => k === bk.pub };
  const w = wrap(a.sk, b.pub, { type: 'delta' });
  assert.equal(code(() => I.deliver({ from: a.pub, to: b.pub, wrap: wrap(a.sk, a.pub, { type: 'x' }), kind: 'delivery', cls: 'member', at: 0, ...ctx })), 'bad_p');
  assert.equal(code(() => I.deliver({ from: a.pub, to: bk.pub, wrap: wrap(a.sk, bk.pub, { type: 'x' }), kind: 'delivery', cls: 'member', at: 0, ...ctx })), 'backup_never_fetches');
  for (let k = 0; k < PER_PAIR; k++) I.deliver({ from: a.pub, to: b.pub, wrap: w, kind: 'delivery', cls: 'member', at: 0, ...ctx });
  assert.equal(code(() => I.deliver({ from: a.pub, to: b.pub, wrap: w, kind: 'delivery', cls: 'member', at: 0, ...ctx })), 'inbox_full');
  removed.add(a.pub);
  assert.equal(code(() => I.deliver({ from: a.pub, to: b.pub, wrap: w, kind: 'notice', cls: 'ask', at: 0, ...ctx })), 'removed');
  // Caps never drop deliveries or wait notices: flood notices from many senders.
  const J = new Inbox();
  J.deliver({ from: b.pub, to: a.pub, wrap: wrap(b.sk, a.pub, { type: 'delta' }), kind: 'delivery', cls: 'member', at: 0, isMember: () => true, isRemoved: () => false, isBackup: () => false });
  const nw = wrap(b.sk, a.pub, { type: 'notice' });
  for (let k = 0; k < INBOX_ITEMS + 20; k++) {
    J.deliver({ from: `sender${k}`, to: a.pub, wrap: nw, kind: 'notice', cls: 'ask', at: 1, isMember: () => true, isRemoved: () => false, isBackup: () => false });
  }
  assert.equal(J.items.length, INBOX_ITEMS);
  assert.ok(J.items.some((x) => x.kind === 'delivery'));
  // Ordinary items expire with their class; deliveries stay until acked.
  const got = J.get(a.pub, 10_000);
  assert.equal(got.length, 1);
  J.ack(a.pub, [got[0].iid]);
  assert.equal(J.get(a.pub, 10_000).length, 0);
});

test('case 10: one address per class, newest set wins, dropped on removal or 410', () => {
  const R = new PushRegistry();
  R.register('a', 10, { sign: 'https://p/1', ask: 'https://p/2', notice: 'https://p/3' });
  assert.equal(R.register('a', 5, { sign: 'old' }), false);
  R.dead('a', 'https://p/2');
  assert.deepEqual(R.get('a'), { sign: 'https://p/1', notice: 'https://p/3' });
  R.unregister('a');
  assert.equal(R.get('a'), null);
});
