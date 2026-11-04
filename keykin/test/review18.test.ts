// Review 18's findings (Device policy judging), as regression tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { create } from '../sim/account.ts';
import { History, Ledger } from '../device/history.ts';
import { Guard, judge, itemKey, distinctTargets, type JudgeCtx, type GuardHost } from '../device/policy.ts';
import { Evidence } from '../device/grants.ts';
import { newKey, type NostrEvent } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const me = newKey(), g = me.pub, ck = nip44.v2.utils.getConversationKey(me.sk, g);
const NOW = 1_800_000_000, SITE = 'dev:site';
let t = NOW - 30 * 86400;
const ev = (kind: number, tags: string[][], content = '', at = ++t): NostrEvent => finalizeEvent({ kind, created_at: at, tags, content }, me.sk) as NostrEvent;
const follows = (n: number, from = 0) => Array.from({ length: n }, (_, k) => ['p', (k + from).toString(16).padStart(64, '0')]);
const decrypt = async (c: string) => { try { return nip44.v2.decrypt(c, ck); } catch { return null; } };
const next = (kind: number, tags: string[][], content = '', at = NOW) => ({ kind, created_at: at, tags, content, pubkey: g });
const ctx = (o: Partial<JudgeCtx> = {}): JudgeCtx => ({ g, now: NOW, owner: SITE, scopes: ['post', 'lists'], history: new History(() => g), ledger: new Ledger(), decrypt, lookup: async () => [], ...o });
function fakeGuard(o: Partial<GuardHost> = {}) {
  const history = new History(() => g), ledger = new Ledger();
  const h: GuardHost = { g, now: NOW, history, ledger: () => ledger, record: (f) => f(ledger), decrypt, lookup: async () => [], refresh: async () => ({ answered: 1, asked: 1 }), refreshRecords: async () => {}, persist: () => {}, ...o };
  return { guard: new Guard(h), history, ledger };
}

test('H1: trimming a month never sheds removal logs or recent deletions; a site can\'t flush its log with additions', async () => {
  const l = new Ledger();
  l.log('removed', SITE, '3', follows(7).map((x) => itemKey('pub', 'p', x[1])), NOW);
  l.del({ at: NOW - 60, owner: SITE, n: 1, single: true, wallet: false, approved: false });
  for (let k = 0; k < 24; k++) l.log('added', SITE, `30000:s${k}`, follows(300, k * 300).map((x) => itemKey('pub', 'p', x[1])), NOW);
  assert.equal(l.logCount('added', SITE), Ledger.LOG_PER_OWNER, 'additions capped per site across its lists');
  l.trim(l.size(), NOW);
  assert.equal(l.removals(SITE, '3').size, 7); assert.equal(l.dels.length, 1);
  // A full removal log: every further removal by that site asks.
  const full = new Ledger();
  for (let k = 0; k < 10; k++) full.log('removed', SITE, `30000:x${k}`, follows(200, k * 200).map((x) => itemKey('pub', 'p', x[1])), NOW);
  const c = ctx({ ledger: full }); c.history.take(ev(3, follows(100), '', NOW - 86400));
  assert.equal((await judge(next(3, follows(99, 1)), c)).level, 'confirm');
  // A month too big to publish keeps the site's removals.
  const acc = await create(); const A = acc.A; await A.fetch();
  A.meta.record((led) => { led.log('removed', SITE, '3', ['["pub","p","x"]'], A.now); for (let k = 0; k < 6000; k++) led.sign(bytesToHex(randomBytes(32)), `${A.kp.pub}:flood`); });
  for (let k = 0; k < 6000; k++) A.meta.encrypted(nip44.v2.encrypt('x', ck), `${A.kp.pub}:flood`);
  await A.meta.publish();
  assert.equal(A.meta.evidence().ledger.removals(SITE, '3').size, 1);
});

test('M1: a site\'s concurrent deletions are judged one after another: the budget holds', async () => {
  const { guard, history, ledger } = fakeGuard();
  guard.undoMs = 20; guard.cardWaitMs = 200;
  const posts = [1, 2, 3].map((k) => ev(1, [], `p${k}`)); for (const p of posts) { history.take(p); ledger.sign(p.id, SITE); }
  for (let k = 0; k < 19; k++) ledger.del({ at: NOW - 3600, owner: SITE, n: 1, single: true, wallet: false, approved: false });
  guard.onCard = (c) => guard.answer(c.id, 'decline');
  const sign = (e: any) => async () => { const s = { ...e, id: bytesToHex(randomBytes(32)), sig: '' } as NostrEvent; await guard.signed(s, SITE); return s; };
  const rs = await Promise.all(posts.map((p) => { const e = next(5, [['e', p.id]]); return guard.serve(e, SITE, ['post'], sign(e)); }));
  assert.equal(rs.filter((r) => 'signed' in r).length, 1, 'only the 20th is silent');
});

test('M2/L3: one Undo tap cancels every waiting twin from that site, and counts as a decline', async () => {
  const { guard, history, ledger } = fakeGuard();
  guard.undoMs = 300;
  const post = ev(1, [], 'p'); history.take(post); ledger.sign(post.id, SITE);
  const a = guard.gate(next(5, [['e', post.id]]), SITE, ['post']), b = guard.gate(next(5, [['e', post.id]], '', NOW + 1), SITE, ['post']);
  await new Promise((r) => setTimeout(r, 30));
  const w = guard.pendingUndos(); assert.equal(w.length, 2); assert.equal(w[0].owner, SITE);
  assert.ok(guard.undoPending(w[0].id));
  for (const r of await Promise.all([a, b])) assert.match((r as any).error, /undone/);
  assert.equal(guard.declines.get(SITE)?.length, 1);
});

test('M3: a deletion naming nothing of the account\'s is declined, so it can\'t fill the burst', async () => {
  const other = newKey().pub;
  assert.equal((await judge(next(5, [['a', `30023:${other}:x`]]), ctx())).row, 'delete-none');
  assert.equal((await judge(next(5, [['e', 'not-hex']]), ctx())).level, 'declined');
});

test('M4: a judged list whose current version the device can\'t see is try-later; a pre-site version is never the site\'s own', async () => {
  const { guard } = fakeGuard({ refresh: async () => ({ answered: 0, asked: 2 }) });
  assert.equal((await guard.judge(next(10002, [['r', 'wss://evil']]), SITE, ['lists'])).level, 'try-later');
  const ok = fakeGuard();
  assert.equal((await ok.guard.judge(next(10002, [['r', 'wss://mine']]), SITE, ['lists'])).level, 'silent', 'every relay said there is none: a first list');
  const s1 = ev(10002, [['r', 'wss://mine']]); await ok.guard.signed(s1, SITE);
  await ok.guard.signed(ev(10002, [['r', 'wss://mine'], ['r', 'wss://b']]), SITE);
  assert.equal(ok.ledger.presiteOf(SITE, '10002'), null, 'its own version is no pre-site reference');
});

test('M5: a one-element e tag never breaks the bookkeeping of a signed deletion', async () => {
  const { guard, history, ledger } = fakeGuard();
  const post = ev(1, [], 'p'); history.take(post);
  await guard.signed(ev(5, [['e'], ['e', post.id]]), SITE);
  assert.equal(ledger.dels.length, 1);
  assert.equal(history.get(undefined as any), null);
});

test('M6: at most 4 open cards per site; more are try-later without a card', async () => {
  const { guard } = fakeGuard();
  guard.cardWaitMs = 100;
  const del = (k: number) => next(27235, [['u', `https://h.example/api/${k}`], ['method', 'DELETE']]);
  const rs = await Promise.all([1, 2, 3, 4, 5].map((k) => guard.gate(del(k), SITE, ['post'])));
  assert.equal(rs.filter((r) => /too many requests/.test((r as any).error ?? '')).length, 1);
});

test('M7: a legacy NIP-04 private list is read with the self key; an unreadable current version asks', async () => {
  const acc = await create(); const A = acc.A; await A.fetch();
  const legacy = await A.nip04(A.g, JSON.stringify([['p', 'aa']]), true);
  assert.equal(await A.decryptSelf(legacy), JSON.stringify([['p', 'aa']]));
  const c = ctx(); c.history.take(ev(10000, [], 'unreadable?iv=xx', NOW - 86400));
  assert.equal((await judge(next(10000, []), c)).level, 'held', 'core: emptied');
  assert.equal((await judge(next(10000, [['p', 'aa']]), c)).level, 'confirm', 'what left the private part is unknown');
  assert.equal((await judge(next(10000, [['p', 'aa']], 'unreadable?iv=xx'), c)).level, 'silent', 'private part kept as it was');
});

test('M8: an Undo that needs the person stays in the outbox until it is signed', async () => {
  const acc = await create(); const A = acc.A; await A.fetch();
  const v1 = await A.sign({ kind: 10000, tags: follows(3), content: '' }); acc.bus.advance(1);
  await A.sign({ kind: 10000, tags: follows(5), content: '' }); acc.bus.advance(1);
  assert.equal(((await A.undoTo(v1.id)) as any).needs, 'confirm');
  assert.equal(A.undoOutbox.length, 1); await A.flushUndos(); assert.equal(A.undoOutbox.length, 1, 'kept');
  await A.undoTo(v1.id, { confirmed: true });
  assert.equal(A.undoOutbox.length, 0);
});

test('L1: wallet settings re-saved unchanged (a fresh nonce) are silent; changed ones ask', async () => {
  const c = ctx({ scopes: ['wallet'] }); c.history.take(ev(17375, [], nip44.v2.encrypt('[["mint","m"]]', ck)));
  assert.equal((await judge(next(17375, [], nip44.v2.encrypt('[["mint","m"]]', ck)), c)).level, 'silent');
  assert.equal((await judge(next(17375, [], nip44.v2.encrypt('[["mint","x"]]', ck)), c)).level, 'confirm');
});

test('L2: an e and an a naming one event are one target for the budget', () => {
  const h = new History(() => g), s = ev(30023, [['d', 'art']]); h.take(s);
  assert.equal(distinctTargets({ tags: [['e', s.id], ['a', `30023:${g}:art`]] }, h, g), 1);
});

test('L4: an a target of a kind with no address is never looked up, and asks', async () => {
  let looked = 0;
  const c = ctx({ lookup: async () => { looked++; return []; } });
  assert.equal((await judge(next(5, [['a', `1:${g}:`]]), c)).level, 'confirm');
  assert.equal(looked, 0);
  assert.equal((await judge(next(5, follows(6).map((x) => ['e', x[1]])), c)).level, 'held');
  assert.equal(looked, 0, 'no lookup for what core already holds');
});

test('L7: an item the person re-added and later removed no longer counts against the site', async () => {
  const c = ctx();
  const items = follows(20);
  c.history.take(ev(3, items, '', NOW - 8 * 86400));
  c.ledger.log('removed', SITE, '3', items.slice(0, 4).map((x) => itemKey('pub', 'p', x[1])), NOW - 5 * 86400);
  c.history.take(ev(3, items.slice(4), '', NOW - 5 * 86400));
  c.history.take(ev(3, items, '', NOW - 4 * 86400));               // the person re-adds them
  c.history.take(ev(3, items.slice(4), '', NOW - 3 * 86400));      // and later removes them again
  assert.equal((await judge(next(3, items.slice(5)), c)).level, 'silent', '1 of 20 by the site');
});

test('records sync with the new limits: an Evidence round trip keeps the policy records', () => {
  const e = new Evidence(); e.ledger.log('removed', SITE, '3', [itemKey('pub', 'p', 'x')], NOW);
  const b = new Evidence(); b.load(e.dump());
  assert.ok(b.ledger.removals(SITE, '3').has(itemKey('pub', 'p', 'x')));
});
