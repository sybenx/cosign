// Device policy §1–§4, §6: the history, the records, the judge's rows, and the Guard through a NIP-46 site.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create } from '../sim/account.ts';
import { History, Ledger } from '../device/history.ts';
import { judge, itemsOf, itemKey, normValue, type JudgeCtx } from '../device/policy.ts';
import { Evidence } from '../device/grants.ts';
import { newKey, type NostrEvent } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const me = newKey(), g = me.pub, ck = nip44.v2.utils.getConversationKey(me.sk, g);
const NOW = 1_800_000_000;
const SITE = 'dev:site', OTHER = 'dev:other';
let t = NOW - 30 * 86400;
const ev = (kind: number, tags: string[][], content = '', at = ++t): NostrEvent => finalizeEvent({ kind, created_at: at, tags, content }, me.sk) as NostrEvent;
const follows = (n: number, from = 0) => Array.from({ length: n }, (_, k) => ['p', (k + from).toString(16).padStart(64, '0')]);
const priv = (tags: string[][]) => nip44.v2.encrypt(JSON.stringify(tags), ck);
const decrypt = async (c: string) => { try { return nip44.v2.decrypt(c, ck); } catch { return null; } };
function ctx(o: Partial<JudgeCtx> = {}): JudgeCtx {
  return { g, now: NOW, owner: SITE, scopes: ['post', 'lists'], history: new History(() => g), ledger: new Ledger(), decrypt, lookup: async () => [], ...o };
}
const unsigned = (e: NostrEvent) => ({ kind: e.kind, created_at: e.created_at, tags: e.tags, content: e.content, pubkey: e.pubkey });
const next = (kind: number, tags: string[][], content = '') => unsigned(ev(kind, tags, content, NOW));

test('§1 history: only the account\'s events whose signature verifies; the newest of each list; 25 versions kept', () => {
  const h = new History(() => g);
  const other = finalizeEvent({ kind: 3, created_at: NOW, tags: [], content: '' }, newKey().sk) as NostrEvent;
  assert.equal(h.take(other), false, 'another key');
  const forged = { ...ev(3, follows(2)), sig: '00'.repeat(64) };
  assert.equal(h.take(forged), false, 'a signature that fails');
  for (let k = 0; k < 30; k++) h.take(ev(3, follows(k + 1)));
  assert.equal(h.versions.get('3')!.length, 25);
  assert.equal(h.current('3')!.tags.length, 30);
  const set = ev(30000, [['d', 'friends'], ...follows(1)]);
  h.take(set); assert.equal(h.current('30000:friends')!.id, set.id);
});

test('§2 items: name and first value, relay URLs normalised, public and private apart; d/title are not items', async () => {
  assert.equal(normValue('wss://Relay.Example.com/'), 'wss://relay.example.com');
  const e = ev(10000, [['p', 'aa', 'wss://hint'], ['title', 'x'], ['r', 'WSS://R.example/']], priv([['p', 'bb']]));
  assert.deepEqual([...(await itemsOf(e, decrypt))!].sort(), [itemKey('priv', 'p', 'bb'), itemKey('pub', 'p', 'aa'), itemKey('pub', 'r', 'wss://r.example')].sort());
  // A kind with no private items is judged by its public tags alone; content that doesn't decrypt has none.
  assert.equal((await itemsOf(ev(3, [['p', 'aa']], '{"wss://x":{}}'), decrypt))!.size, 1);
  assert.equal((await itemsOf(ev(10000, [], 'junk'), decrypt))!.size, 0);
  assert.equal(await itemsOf(ev(10000, [], 'junk'), async () => undefined), undefined, 'no self key: unknown');
});

test('§2 follows: a site\'s net removals reach 10, or 20% and 5, before a card; small cuts are silent', async () => {
  const c = ctx(); c.history.take(ev(3, follows(100), '', NOW - 8 * 86400));
  assert.equal((await judge(next(3, follows(95, 5)), c)).level, 'silent', '5 of 100: 5%');
  assert.equal((await judge(next(3, follows(90, 10)), c)).level, 'confirm', '10 removed');
  const s = ctx(); s.history.take(ev(3, follows(20), '', NOW - 8 * 86400));
  assert.equal((await judge(next(3, follows(16, 4)), s)).level, 'silent', '4 of 20');
  assert.equal((await judge(next(3, follows(15, 5)), s)).level, 'confirm', '5 of 20 is 25%');
});

test('§2 removals add up within a week: many small cuts by one site, never the person\'s own edits', async () => {
  const c = ctx(); const week = ev(3, follows(100), '', NOW - 8 * 86400); c.history.take(week);
  // The site cut 4 three times; each step is a new current version, and its removals are in its log.
  let cur = 100;
  for (let k = 0; k < 2; k++) {
    const nv = ev(3, follows(cur - 4, 100 - cur + 4), '', NOW - 86400 + k);
    c.ledger.log('removed', SITE, '3', follows(4, 100 - cur).map((x) => itemKey('pub', 'p', x[1])), NOW - 86400);
    c.history.take(nv); cur -= 4;
  }
  assert.equal((await judge(next(3, follows(cur - 4, 100 - cur + 4)), c)).level, 'confirm', '12 net removals this week');
  const other = ctx({ owner: OTHER, history: c.history, ledger: c.ledger });
  assert.equal((await judge(next(3, follows(cur - 4, 100 - cur + 4)), other)).level, 'silent', 'another site\'s removals don\'t count against it');
});

test('§2 the pre-site version is the reference: a reconnect resets nothing, and no-op edits can\'t push it out', async () => {
  const c = ctx(); const pre = ev(10000, follows(50), '', NOW - 86400 * 3); c.history.take(pre);
  c.ledger.setPresite(SITE, '10000', pre.id); c.history.pin(pre);
  c.ledger.log('removed', SITE, '10000', follows(9).map((x) => itemKey('pub', 'p', x[1])), NOW - 86400 * 2);
  for (let k = 0; k < 30; k++) c.history.take(ev(10000, follows(41, 9), '', NOW - 86400 * 2 + k));   // 30 no-op edits
  assert.equal(c.history.versions.get('10000')!.some((x) => x.id === pre.id), false, 'pushed out of the 25, but pinned');
  assert.equal((await judge(next(10000, follows(40, 10)), c)).level, 'confirm', '10 net removals against the pre-site version');
});

test('§2 private items count, and moving a public item into the private part is a removal', async () => {
  const c = ctx(); c.history.take(ev(10000, follows(10), priv(follows(10, 50)), NOW - 8 * 86400));
  assert.equal((await judge(next(10000, follows(10), ''), c)).level, 'confirm', 'private content emptied: 10 removed');
  assert.equal((await judge(next(10000, [], priv([...follows(10, 50), ...follows(10)])), c)).level, 'confirm', 'public moved to private: removed');
  assert.equal((await judge(next(10000, follows(11), priv(follows(10, 50))), c)).level, 'silent', 'an addition');
  const nokey = ctx({ history: c.history, decrypt: async () => undefined });
  assert.equal((await judge(next(10000, follows(11), priv(follows(10, 50))), nokey)).level, 'confirm', 'no self key: Confirm');
});

test('§2 emptied: a list left with no items, or every item of the reference gone; a new empty set is no removal', async () => {
  const c = ctx(); c.history.take(ev(10001, follows(2), '', NOW - 8 * 86400));
  assert.equal((await judge(next(10001, [['p', 'new']]), c)).level, 'confirm', 'every item of the reference removed');
  // core §5.8: a list left with nothing at all is Held.
  assert.equal((await judge(next(10001, []), c)).level, 'held');
  assert.equal((await judge(next(30000, [['d', 'fresh'], ['title', 'x'], ['p', 'aa']]), c)).level, 'silent', 'a new named set');
});

test('§2 relay lists: any relay removed, or write switched to read, is Confirm; none left is Held', async () => {
  const c = ctx(); c.history.take(ev(10002, [['r', 'wss://a.example'], ['r', 'wss://b.example']]));
  assert.equal((await judge(next(10002, [['r', 'wss://a.example/'], ['r', 'wss://b.example'], ['r', 'wss://c.example']]), c)).level, 'silent', 'added, normalised');
  assert.equal((await judge(next(10002, [['r', 'wss://a.example']]), c)).level, 'confirm');
  assert.equal((await judge(next(10002, [['r', 'wss://a.example'], ['r', 'wss://b.example', 'read']]), c)).level, 'confirm');
  assert.equal((await judge(next(10002, []), c)).level, 'held');
});

test('§2 profile: two fields emptied, or a payment address changed, is Confirm; replacing name or picture is silent', async () => {
  const c = ctx(); c.history.take(ev(0, [], JSON.stringify({ name: 'a', about: 'b', picture: 'p', lud16: 'me@x' })));
  assert.equal((await judge(next(0, [], JSON.stringify({ name: 'junk', about: 'junk', picture: 'q', lud16: 'me@x' })), c)).level, 'silent');
  assert.equal((await judge(next(0, [], JSON.stringify({ name: 'a', about: ' ', picture: '', lud16: 'me@x' })), c)).level, 'confirm', 'two emptied');
  assert.equal((await judge(next(0, [], JSON.stringify({ name: 'a', about: 'b', picture: 'p', lud16: 'thief@x' })), c)).level, 'confirm');
  assert.equal((await judge(next(0, [], JSON.stringify({})), c)).level, 'held', 'core: emptied');
});

test('§2 expiring lists and lists dated ahead are declined; 7374 with an expiry is fine', async () => {
  const c = ctx({ scopes: ['post', 'lists', 'wallet'] });
  assert.equal((await judge(next(10000, [['p', 'a'], ['expiration', String(NOW + 60)]]), c)).level, 'declined');
  assert.equal((await judge({ ...next(10000, [['p', 'a']]), created_at: NOW + 301 }, c)).level, 'declined');
  assert.equal((await judge({ ...next(10000, [['p', 'a']]), created_at: NOW + 60 }, c)).level, 'silent', 'ordinary skew');
  assert.equal((await judge(next(7374, [['expiration', String(NOW + 60)]], 'x'), c)).level, 'silent');
});

test('§2 deletions: a site\'s own post within its budget waits 10 s; another\'s, 2–4, a list, or an unknown target is Confirm', async () => {
  const c = ctx();
  const mine = ev(1, [], 'mine'), theirs = ev(1, [], 'theirs'), list = ev(10000, follows(3));
  for (const x of [mine, theirs, list]) c.history.take(x);
  c.ledger.sign(mine.id, SITE); c.ledger.sign(theirs.id, OTHER);
  assert.equal((await judge(next(5, [['e', mine.id]]), c)).level, 'undo');
  assert.equal((await judge(next(5, [['e', theirs.id]]), c)).level, 'confirm');
  assert.equal((await judge(next(5, [['e', mine.id], ['e', theirs.id]]), c)).level, 'confirm');
  assert.equal((await judge(next(5, [['e', list.id]]), c)).row, 'delete-list');
  assert.equal((await judge(next(5, [['a', `10000:${g}:`]]), c)).row, 'delete-list');
  assert.equal((await judge(next(5, [['e', 'ee'.repeat(32)]]), c)).level, 'confirm', 'not found after the lookup');
  // An `e` and an `a` naming the same event are one target.
  const set = ev(30000, [['d', 's'], ['p', 'x']]); c.history.take(set);
  assert.equal((await judge(next(5, [['e', set.id], ['a', `30000:${g}:s`]]), c)).reason, 'Delete this list?');
  // A target signed by another key is ignored (relays ignore it too).
  const foreign = finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: '' }, newKey().sk) as NostrEvent;
  const l = ctx({ history: c.history, ledger: c.ledger, lookup: async () => [foreign] });
  assert.equal((await judge(next(5, [['e', foreign.id], ['e', mine.id]]), l)).level, 'undo');
  // The 21st single deletion in a day, counted across devices.
  for (let k = 0; k < 20; k++) c.ledger.del({ at: NOW - 3600, owner: SITE, n: 1, single: true, wallet: false, approved: false });
  assert.equal((await judge(next(5, [['e', mine.id]]), c)).row, 'delete-budget');
  // 5 or more targets, or a burst: core §5.8, Held.
  assert.equal((await judge(next(5, follows(5).map((x) => ['e', x[1]])), ctx())).level, 'held');
});

test('§2 wallet deletions: silent within 3, else a quiet try-later, never a card', async () => {
  const c = ctx({ scopes: ['wallet'] });
  const toks = [1, 2, 3, 4].map((k) => ev(7375, [], `t${k}`)); for (const x of toks) c.history.take(x);
  assert.equal((await judge(next(5, toks.slice(0, 3).map((x) => ['e', x.id])), c)).level, 'silent');
  assert.equal((await judge(next(5, toks.map((x) => ['e', x.id])), c)).level, 'try-later', '4 targets, and core would hold 5');
  for (let k = 0; k < 3; k++) c.ledger.del({ at: NOW - 60, owner: SITE, n: 1, single: true, wallet: true, approved: false });
  assert.equal((await judge(next(5, [['e', toks[0].id]]), c)).level, 'try-later', 'three in 10 minutes already');
  assert.equal((await judge(next(5, [['e', toks[0].id]]), ctx({ history: c.history })) ).level, 'confirm', 'no wallet scope: an ordinary deletion of another\'s event');
});

test('§2 wallet settings and payment keys changed by a site are Confirm; new tokens silent', async () => {
  const c = ctx({ scopes: ['wallet'] });
  c.history.take(ev(10019, [['pubkey', 'aa'], ['mint', 'https://m.example']]));
  assert.equal((await judge(next(10019, [['pubkey', 'bb'], ['mint', 'https://m.example']]), c)).level, 'confirm');
  assert.equal((await judge(next(10019, [['pubkey', 'aa'], ['mint', 'https://m.example'], ['relay', 'wss://x']]), c)).level, 'silent');
  c.history.take(ev(17375, [], 'w1'));
  assert.equal((await judge(next(17375, [], 'w2'), c)).level, 'confirm');
  assert.equal((await judge(next(7375, [], 'tok'), c)).level, 'silent');
});

test('§2 media deletes: Confirm naming files and servers; wide tokens declined; an Allow covers only what the card named', async () => {
  const x = (k: number) => ['x', String(k).repeat(64).slice(0, 64)];
  const tok = (tags: string[][]) => next(24242, [['t', 'delete'], ['expiration', String(NOW + 300)], ...tags]);
  const c = ctx();
  const one = await judge(tok([x(1), ['server', 'cdn.example']]), c);
  assert.equal(one.level, 'confirm'); assert.match(one.reason, /1 file from cdn\.example/);
  assert.match((await judge(tok([x(1)]), c)).reason, /every server/);
  assert.equal((await judge(tok([x(1), x(2), x(3), x(4), x(5)]), c)).level, 'declined', 'more than 4');
  assert.equal((await judge(tok([]), c)).level, 'declined', 'none named');
  assert.equal((await judge(next(24242, [['t', 'delete'], x(1)]), c)).level, 'declined', 'no expiry');
  const allowed = ctx({ allowed: (f, s) => f.every((h) => h === x(1)[1]) && s === 'cdn.example' });
  assert.equal((await judge(tok([x(1), ['server', 'cdn.example']]), allowed)).level, 'silent');
  assert.equal((await judge(tok([x(1), ['server', 'other.example']]), allowed)).level, 'confirm', 'another server');
  assert.equal((await judge(next(27235, [['u', 'https://h.example/api/thing'], ['method', 'DELETE']]), c)).level, 'confirm');
  assert.equal((await judge(next(27235, [['u', 'https://h.example/api/thing'], ['method', 'PUT']]), c)).level, 'silent');
});

test('§1 the records sync: one device\'s removals, grants and deletions count on another', async () => {
  const e = new Evidence();
  e.ledger.sign('aa'.repeat(32), 'dev1:g'); e.ledger.log('removed', 'dev1:g', '3', [itemKey('pub', 'p', 'x')], NOW);
  e.ledger.del({ at: NOW, owner: 'dev1:g', n: 2, single: false, wallet: false, approved: false });
  e.ledger.setPresite('dev1:g', '3', 'bb'.repeat(32)); e.ledger.approve('dev1:g', '3', 'cc'.repeat(32), NOW);
  const back = new Evidence(); back.load(e.dump());
  assert.equal(back.ledger.signed.get('aa'.repeat(32)), 'dev1:g');
  assert.ok(back.ledger.removals('dev1:g', '3').has(itemKey('pub', 'p', 'x')));
  assert.equal(back.ledger.burst(NOW + 1), 2);
  assert.equal(back.ledger.presiteOf('dev1:g', '3'), 'bb'.repeat(32));
  // Only the maker's owners count (review 17 L5).
  const l = new Ledger(); l.take(e.ledger.data(), (o) => o === 'member' || String(o).startsWith('dev2:'));
  assert.equal(l.signed.size + l.dels.length + l.removed.size, 0);
});

// --- through a NIP-46 site, on a simulated account ----------------------------------------------------
async function site() {
  const acc = await create();
  const A = acc.A, bus = acc.bus;
  A.guard.undoMs = 50; A.guard.quietMs = 10;
  const key = newKey();
  const call = async (signer: string, method: string, params: string[] = []) => {
    const id = bytesToHex(randomBytes(8)), ck2 = nip44.v2.utils.getConversationKey(key.sk, signer);
    const reply = new Promise<any>((res) => { const w = bus.events.watch({ kinds: [24133], authors: [signer], '#p': [key.pub] }, (r: any) => { const x = JSON.parse(nip44.v2.decrypt(r.content, ck2)); if (x.id === id) { w.close(); res(x); } }); });
    await bus.events.publishEvent(finalizeEvent({ kind: 24133, created_at: bus.now, tags: [['p', signer]], content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck2) }, key.sk));
    return reply;
  };
  const u = new URL(A.nip46.mintBunker(['ws://relay.test'], 'coracle')); const signer = u.hostname;
  assert.equal((await call(signer, 'connect', [signer, u.searchParams.get('secret')!])).result, 'ack');
  A.nip46.allowScope(signer, 'lists');
  const owner = `${A.kp.pub}:${A.nip46.grants.get(signer)!.entry}`;
  const sign = (e: object) => call(signer, 'sign_event', [JSON.stringify({ created_at: bus.now, content: '', tags: [], ...e })]);
  return { acc, A, bus, signer, sign, owner };
}

test('through NIP-46: a big cut shows a card; Allow signs it, Decline answers declined; three declines decline that row for an hour', async () => {
  const { A, bus, sign, owner } = await site();
  const mine = await A.sign({ kind: 3, tags: follows(40), content: '' });   // the member app's follows
  await bus.events.publishEvent(mine);
  bus.advance(8 * 86400);
  const cards: number[] = [];
  A.guard.onCard = (c) => { cards.push(c.id); A.guard.answer(c.id, cards.length === 1 ? 'allow' : 'decline'); };
  const r1 = await sign({ kind: 3, tags: follows(25) });
  assert.ok(r1.result, 'allowed'); assert.equal(cards.length, 1);
  assert.equal(A.meta.evidence().ledger.approvedOf(owner, '3')?.[0], JSON.parse(r1.result).id, 'the last-approved reference');
  assert.equal(A.meta.evidence().ledger.removals(owner, '3').size, 15, 'its removals logged');
  bus.advance(1);
  for (let k = 0; k < 3; k++) { bus.advance(1); assert.match((await sign({ kind: 3, tags: follows(10 - k) })).error, /^declined: you declined it/); }
  bus.advance(1);
  assert.match((await sign({ kind: 3, tags: follows(5) })).error, /^declined: you declined this site's requests/, 'auto-declined: no card');
  assert.equal(cards.length, 4);
  assert.ok((await sign({ kind: 1, content: 'still posts' })).result, 'other rows go on');
});

test('through NIP-46: a site deleting its own post waits for the Undo; Undo stops it and counts as a decline', async () => {
  const { A, bus, sign } = await site();
  const post = JSON.parse((await sign({ kind: 1, content: 'oops' })).result);
  bus.advance(1);
  const del = await sign({ kind: 5, tags: [['e', post.id]] });
  assert.ok(del.result, 'signed after the wait');
  const post2 = JSON.parse((await sign({ kind: 1, content: 'oops 2' })).result);
  bus.advance(1);
  const p = sign({ kind: 5, tags: [['e', post2.id]] });
  await new Promise((r) => setTimeout(r, 30));
  const [w] = A.guard.pendingUndos(); assert.ok(w);
  assert.ok(A.guard.undoPending(w.id));
  assert.match((await p).error, /^declined: undone/);
  // A post this site didn't make: Confirm.
  const memberPost = await A.sign({ kind: 1, content: 'mine' });
  A.guard.onCard = (c) => A.guard.answer(c.id, 'decline');
  assert.match((await sign({ kind: 5, tags: [['e', memberPost.id]] })).error, /^declined/);
});

test('through NIP-46: an emptied follow list is Held, answered held: at once', async () => {
  const { A, bus, sign } = await site();
  await bus.events.publishEvent(await A.sign({ kind: 3, tags: follows(3), content: '' }));
  bus.advance(1);
  assert.match((await sign({ kind: 3, tags: [] })).error, /^held:/);
  assert.equal(A.nip46.held.size, 1);
});

test('§3 Undo: an earlier version signed again, dated after the newest; restoring a smaller one asks first', async () => {
  const { A, bus } = await site();
  const v1 = await A.sign({ kind: 10000, tags: follows(5), content: '' }); bus.advance(1);
  const v2 = await A.sign({ kind: 10000, tags: follows(3), content: '' }); bus.advance(1);
  const back = await A.undoTo(v1.id) as NostrEvent;
  assert.equal(back.tags.length, 5); assert.ok(back.created_at > v2.created_at);
  bus.advance(1);
  const ask = await A.undoTo(v2.id);
  assert.equal((ask as any).needs, 'confirm');
  const done = await A.undoTo(v2.id, { confirmed: true }) as NostrEvent;
  assert.equal(done.tags.length, 3);
});

test('§3 Undo everything a site did: its removals re-added and its additions removed, others\' edits kept', async () => {
  const { A, bus, sign, owner } = await site();
  await bus.events.publishEvent(await A.sign({ kind: 10000, tags: follows(6), content: '' })); bus.advance(1);
  assert.ok((await sign({ kind: 10000, tags: [...follows(4), ['p', 'ff'.repeat(32)]] })).result, '2 removed, 1 added: silent');
  bus.advance(1);
  const mine = await A.sign({ kind: 10000, tags: [...follows(4), ['p', 'ff'.repeat(32)], ['p', 'ee'.repeat(32)]], content: '' }); // the person adds one
  bus.advance(1);
  // Removing the site's addition is a removal: Confirm first (§3: judged like any change).
  assert.equal(((await A.undoSite(owner)).lists[0] as any).needs, 'confirm');
  const r = await A.undoSite(owner, { confirmed: true });
  const out = r.lists[0] as NostrEvent;
  const ps = new Set(out.tags.map((x) => x[1]));
  assert.ok(ps.has(follows(6)[5][1]) && ps.has(follows(6)[4][1]), 'removals back');
  assert.ok(!ps.has('ff'.repeat(32)), 'its addition gone'); assert.ok(ps.has('ee'.repeat(32)), 'the person\'s kept');
  assert.ok(out.created_at > mine.created_at);
});

test('§4 a held change is dropped once the list changed since', async () => {
  const { A, bus, sign } = await site();
  await bus.events.publishEvent(await A.sign({ kind: 3, tags: follows(3), content: '' })); bus.advance(1);
  await sign({ kind: 3, tags: [] });
  const [h] = [...A.nip46.held.values()];
  bus.advance(1); await A.sign({ kind: 3, tags: follows(4), content: '' });
  await assert.rejects(A.nip46.approveHeld(h.id), /superseded|changed since/);
});
