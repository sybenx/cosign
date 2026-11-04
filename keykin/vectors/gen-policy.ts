// Device policy §2's verdicts for every port: each case has the device's history (signed events), the synced records
// (a Ledger's published form), the event a site asks for, who asks and with which scopes, what a relay lookup returns,
// and the level and row the TS reference decides. Private items decrypt with `ck`, the self conversation key (test
// material only). Run: node vectors/gen-policy.ts > vectors/policy.json
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { History, Ledger } from '../device/history.ts';
import { judge, itemKey, normValue } from '../device/policy.ts';
import { newKey, type NostrEvent } from '../src/event.ts';
import { bytesToHex } from '../src/bytes.ts';

const me = newKey(), g = me.pub, ck = nip44.v2.utils.getConversationKey(me.sk, g);
const NOW = 1_800_000_000, SITE = 'dev:site', OTHER = 'dev:other';
let t = NOW - 30 * 86400;
const ev = (kind: number, tags: string[][], content = '', at = ++t): NostrEvent => finalizeEvent({ kind, created_at: at, tags, content }, me.sk) as NostrEvent;
const follows = (n: number, from = 0) => Array.from({ length: n }, (_, k) => ['p', (k + from).toString(16).padStart(64, '0')]);
const priv = (tags: string[][]) => nip44.v2.encrypt(JSON.stringify(tags), ck);
const next = (kind: number, tags: string[][], content = '', at = NOW) => ({ kind, created_at: at, tags, content, pubkey: g });
const decrypt = async (c: string) => { try { return nip44.v2.decrypt(c, ck); } catch { return null; } };

interface Case { name: string; history: NostrEvent[]; ledger?: (l: Ledger) => void; event: any; owner?: string; scopes?: string[]; lookup?: NostrEvent[] }
const week = NOW - 8 * 86400;
const f100 = ev(3, follows(100), '', week), f20 = ev(3, follows(20), '', week);
const pl = ev(10000, follows(10), priv(follows(10, 50)), week);
const relays = ev(10002, [['r', 'wss://a.example'], ['r', 'wss://b.example']]);
const prof = ev(0, [], JSON.stringify({ name: 'a', about: 'b', picture: 'p', lud16: 'me@x' }));
const mine = ev(1, [], 'mine'), theirs = ev(1, [], 'theirs'), list = ev(10000, follows(3)), set = ev(30000, [['d', 's'], ['p', 'x']]);
const toks = [1, 2, 3, 4].map((k) => ev(7375, [], `t${k}`));
const foreign = finalizeEvent({ kind: 1, created_at: NOW, tags: [], content: '' }, newKey().sk) as NostrEvent;
const w10019 = ev(10019, [['pubkey', 'aa'], ['mint', 'https://m.example']]), w17375 = ev(17375, [], 'w1');
const x = (k: number) => ['x', String(k).repeat(64).slice(0, 64)];
const tok = (tags: string[][]) => next(24242, [['t', 'delete'], ['expiration', String(NOW + 300)], ...tags]);
const ownSigned = (l: Ledger) => { l.sign(mine.id, SITE); l.sign(theirs.id, OTHER); };
const cases: Case[] = [
  { name: '5 of 100 follows', history: [f100], event: next(3, follows(95, 5)) },
  { name: '10 of 100 follows', history: [f100], event: next(3, follows(90, 10)) },
  { name: '4 of 20', history: [f20], event: next(3, follows(16, 4)) },
  { name: '5 of 20', history: [f20], event: next(3, follows(15, 5)) },
  { name: 'log adds up', history: [f100, ev(3, follows(92, 8), '', NOW - 86400)], ledger: (l) => l.log('removed', SITE, '3', follows(8).map((y) => itemKey('pub', 'p', y[1])), NOW - 86400), event: next(3, follows(88, 12)) },
  { name: 'another site\'s log', history: [f100, ev(3, follows(92, 8), '', NOW - 86400)], ledger: (l) => l.log('removed', OTHER, '3', follows(8).map((y) => itemKey('pub', 'p', y[1])), NOW - 86400), event: next(3, follows(88, 12)) },
  { name: 'private emptied', history: [pl], event: next(10000, follows(10), '') },
  { name: 'public to private', history: [pl], event: next(10000, [], priv([...follows(10, 50), ...follows(10)])) },
  { name: 'private addition', history: [pl], event: next(10000, follows(11), priv(follows(10, 50))) },
  { name: 'reference emptied', history: [ev(10001, follows(2), '', week)], event: next(10001, [['p', 'new']]) },
  { name: 'list left empty (core)', history: [ev(10001, follows(2), '', week)], event: next(10001, []) },
  { name: 'new named set', history: [], event: next(30000, [['d', 'fresh'], ['title', 'x'], ['p', 'aa']]) },
  { name: 'relay added, normalised', history: [relays], event: next(10002, [['r', 'WSS://A.example/'], ['r', 'wss://b.example'], ['r', 'wss://c.example']]) },
  { name: 'relay removed', history: [relays], event: next(10002, [['r', 'wss://a.example']]) },
  { name: 'relay read-only', history: [relays], event: next(10002, [['r', 'wss://a.example'], ['r', 'wss://b.example', 'read']]) },
  { name: 'no relays (core)', history: [relays], event: next(10002, []) },
  { name: 'profile junk', history: [prof], event: next(0, [], JSON.stringify({ name: 'junk', about: 'junk', picture: 'q', lud16: 'me@x' })) },
  { name: 'profile two emptied', history: [prof], event: next(0, [], JSON.stringify({ name: 'a', about: ' ', picture: '', lud16: 'me@x' })) },
  { name: 'profile lud16', history: [prof], event: next(0, [], JSON.stringify({ name: 'a', about: 'b', picture: 'p', lud16: 'thief@x' })) },
  { name: 'profile emptied (core)', history: [prof], event: next(0, [], '{}') },
  { name: 'expiring list', history: [], event: next(10000, [['p', 'a'], ['expiration', String(NOW + 60)]]) },
  { name: 'list dated ahead', history: [], event: next(10000, [['p', 'a']], '', NOW + 301) },
  { name: 'ordinary skew', history: [], event: next(10000, [['p', 'a']], '', NOW + 60) },
  { name: 'quote with expiry', history: [], event: next(7374, [['expiration', String(NOW + 60)]], 'x'), scopes: ['wallet'] },
  { name: 'own post deleted', history: [mine, theirs], ledger: ownSigned, event: next(5, [['e', mine.id]]) },
  { name: 'another\'s post deleted', history: [mine, theirs], ledger: ownSigned, event: next(5, [['e', theirs.id]]) },
  { name: 'two deleted', history: [mine, theirs], ledger: ownSigned, event: next(5, [['e', mine.id], ['e', theirs.id]]) },
  { name: 'list deleted by e', history: [list], event: next(5, [['e', list.id]]) },
  { name: 'list deleted by a', history: [list], event: next(5, [['a', `10000:${g}:`]]) },
  { name: 'unknown target', history: [], event: next(5, [['e', 'ee'.repeat(32)]]) },
  { name: 'e and a one target', history: [set], event: next(5, [['e', set.id], ['a', `30000:${g}:s`]]) },
  { name: 'foreign target ignored', history: [mine], ledger: ownSigned, lookup: [foreign], event: next(5, [['e', foreign.id], ['e', mine.id]]) },
  { name: 'budget spent', history: [mine], ledger: (l) => { ownSigned(l); for (let k = 0; k < 20; k++) l.del({ at: NOW - 3600, owner: SITE, n: 1, single: true, wallet: false, approved: false }); }, event: next(5, [['e', mine.id]]) },
  { name: 'five targets (core)', history: [], event: next(5, follows(5).map((y) => ['e', y[1]])) },
  { name: 'burst (core)', history: [mine], ledger: (l) => { ownSigned(l); l.del({ at: NOW - 60, owner: OTHER, n: 5, single: false, wallet: false, approved: false }); }, event: next(5, [['e', mine.id]]) },
  { name: 'wallet three', history: toks, scopes: ['wallet'], event: next(5, toks.slice(0, 3).map((y) => ['e', y.id])) },
  { name: 'wallet four', history: toks, scopes: ['wallet'], event: next(5, toks.map((y) => ['e', y.id])) },
  { name: 'wallet recent', history: toks, scopes: ['wallet'], ledger: (l) => { for (let k = 0; k < 3; k++) l.del({ at: NOW - 60, owner: SITE, n: 1, single: true, wallet: true, approved: false }); }, event: next(5, [['e', toks[0].id]]) },
  { name: '10019 pubkey', history: [w10019], scopes: ['wallet'], event: next(10019, [['pubkey', 'bb'], ['mint', 'https://m.example']]) },
  { name: '10019 relay only', history: [w10019], scopes: ['wallet'], event: next(10019, [['pubkey', 'aa'], ['mint', 'https://m.example'], ['relay', 'wss://x']]) },
  { name: '17375 changed', history: [w17375], scopes: ['wallet'], event: next(17375, [], 'w2') },
  { name: 'new token', history: [], scopes: ['wallet'], event: next(7375, [], 'tok') },
  { name: 'blossom one', history: [], event: tok([x(1), ['server', 'cdn.example']]) },
  { name: 'blossom any server', history: [], event: tok([x(1)]) },
  { name: 'blossom five', history: [], event: tok([x(1), x(2), x(3), x(4), x(5)]) },
  { name: 'blossom none', history: [], event: tok([]) },
  { name: 'blossom no expiry', history: [], event: next(24242, [['t', 'delete'], x(1)]) },
  { name: 'nip98 delete', history: [], event: next(27235, [['u', 'https://h.example/api/thing'], ['method', 'DELETE']]) },
  { name: 'nip98 put', history: [], event: next(27235, [['u', 'https://h.example/api/thing'], ['method', 'PUT']]) },
  { name: 'malformed tags', history: [list], event: next(10000, [['p'], [], ['p', 'aa', 'x', 'y'], ['', '']]) },
  { name: 'pre-site reference', history: [ev(10000, follows(50), '', NOW - 3 * 86400), ...Array.from({ length: 3 }, (_, k) => ev(10000, follows(41, 9), '', NOW - 2 * 86400 + k))],
    ledger: (l) => { l.log('removed', SITE, '10000', follows(9).map((y) => itemKey('pub', 'p', y[1])), NOW - 2 * 86400); }, event: next(10000, follows(40, 10)) },
  // Review 18.
  { name: 'nothing to delete', history: [], event: next(5, [['a', `30023:${newKey().pub}:x`]]) },
  { name: 'a with no address', history: [], event: next(5, [['a', `1:${g}:`]]) },
  { name: 'one-element e', history: [mine], ledger: ownSigned, event: next(5, [['e'], ['e', mine.id]]) },
  { name: 'wallet re-saved', history: [ev(37375, [['d', 'w']], nip44.v2.encrypt('[["mint","m"]]', ck))], scopes: ['wallet'], event: next(37375, [['d', 'w']], nip44.v2.encrypt('[["mint","m"]]', ck)) },
  { name: 'wallet plaintext changed', history: [ev(37375, [['d', 'w']], nip44.v2.encrypt('[["mint","m"]]', ck))], scopes: ['wallet'], event: next(37375, [['d', 'w']], nip44.v2.encrypt('[["mint","x"]]', ck)) },
  { name: 're-added since', history: [ev(3, follows(20), '', NOW - 8 * 86400), ev(3, follows(16, 4), '', NOW - 5 * 86400), ev(3, follows(20), '', NOW - 4 * 86400), ev(3, follows(16, 4), '', NOW - 3 * 86400)],
    ledger: (l) => l.log('removed', SITE, '3', follows(4).map((y) => itemKey('pub', 'p', y[1])), NOW - 5 * 86400), event: next(3, follows(15, 5)) },
  { name: 'removal log full', history: [f100], ledger: (l) => { for (let k = 0; k < 10; k++) l.log('removed', SITE, `30000:x${k}`, follows(200, k * 200).map((y) => itemKey('pub', 'p', y[1])), NOW); }, event: next(3, follows(99, 1)) },
  { name: 'unreadable current', history: [ev(10000, [], 'unreadable?iv=xx', NOW - 86400)], event: next(10000, [['p', 'aa']]) },
  { name: 'unreadable kept', history: [ev(10000, [], 'unreadable?iv=xx', NOW - 86400)], event: next(10000, [['p', 'aa']], 'unreadable?iv=xx') },
];
const out = [];
for (const c of cases) {
  const history = new History(() => g); for (const e of c.history) history.take(e);
  const ledger = new Ledger(); c.ledger?.(ledger);
  // The pre-site case names its first version as the site's pre-site version.
  if (c.name === 'pre-site reference') ledger.setPresite(SITE, '10000', c.history[0].id);
  const owner = c.owner ?? SITE, scopes = (c.scopes ?? ['post', 'lists']) as any;
  const v = await judge(c.event, { g, now: NOW, owner, scopes, history, ledger, decrypt, lookup: async () => c.lookup ?? [] });
  out.push({ name: c.name, history: c.history, ledger: ledger.data(), owner, scopes, lookup: c.lookup ?? [], event: c.event, level: v.level, row: v.row });
}
const urls = ['wss://Relay.Example.com/', 'WSS://a.b/x//', 'wss://h/p?q=1/', 'ws://H:80/', 'https://x/', 'wss://h#f/'].map((u) => [u, normValue(u)]);
console.log(JSON.stringify({ note: 'judge(event, ctx) as the TS reference decides it; private items decrypt with ck', g, now: NOW, ck: bytesToHex(ck), urls, cases: out }, null, 1));
