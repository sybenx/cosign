// Cases for the phone's copy of the policy (android core/Policy.kt), judged here by
// server/policy.ts, so the two can't drift apart.
//
//   node test/policy-vectors.ts

import { writeFileSync } from 'node:fs';
import { assess, type Ev } from '../policy.ts';

const pk = (i: number) => i.toString(16).padStart(64, '0');
const NOW = 1_800_000_000;
const ev = (kind: number, tags: string[][] = [], content = '', created_at = NOW): Ev => ({ kind, tags, content, created_at });
const follows = (n: number, from = 0) => Array.from({ length: n }, (_, i) => ['p', pk(from + i)]);
const relays = (...urls: string[]) => urls.map(u => ['r', u]);

const cases: [string, Ev, Ev | undefined][] = [
  ['note', ev(1, [], 'gm'), undefined],
  ['vanish', ev(62), undefined],
  ['delete 4', ev(5, follows(4).map(t => ['e', t[1]])), undefined],
  ['delete 5', ev(5, follows(5).map(t => ['e', t[1]])), undefined],
  ['delete follow list', ev(5, [['a', `3:${pk(9)}:`]]), undefined],
  ['delete by k', ev(5, [['e', pk(1)], ['k', '10002']]), undefined],
  ['first follow list', ev(3, follows(30)), undefined],
  ['follow one more', ev(3, follows(31)), ev(3, follows(30))],
  ['unfollow 5 of 30', ev(3, follows(25)), ev(3, follows(30))],
  ['unfollow 10 of 30', ev(3, follows(20)), ev(3, follows(30))],
  ['unfollow 10 of 100', ev(3, follows(90)), ev(3, follows(100))],
  ['replace all 30', ev(3, follows(30, 100)), ev(3, follows(30))],
  ['empty from 3', ev(3, []), ev(3, follows(3))],
  ['empty from 2', ev(3, []), ev(3, follows(2))],
  ['relays drop 2 of 3', ev(10002, relays('wss://a')), ev(10002, relays('wss://a', 'wss://b/', 'wss://c'))],
  ['relays drop 1 of 3', ev(10002, relays('wss://a', 'wss://b')), ev(10002, relays('wss://a', 'wss://b/', 'wss://c'))],
  ['relays trailing slash', ev(10002, relays('wss://a/', 'wss://b')), ev(10002, relays('wss://a', 'wss://b/'))],
  ['bookmarks emptied', ev(10003, []), ev(10003, follows(4).map(t => ['e', t[1]]))],
  ['set emptied', ev(30000, [['d', 'friends']]), ev(30000, [['d', 'friends'], ...follows(5)])],
  ['profile name change', ev(0, [], JSON.stringify({ name: 'b', about: 'x' })), ev(0, [], JSON.stringify({ name: 'a', about: 'x' }))],
  ['profile wipe 2', ev(0, [], JSON.stringify({ name: 'a' })), ev(0, [], JSON.stringify({ name: 'a', about: 'x', picture: 'p' }))],
  ['profile emptied', ev(0, [], '{}'), ev(0, [], JSON.stringify({ name: 'a' }))],
  ['first profile', ev(0, [], JSON.stringify({ name: 'a' })), undefined],
  ['profile dated 2099', ev(0, [], JSON.stringify({ name: 'a' }), 4_070_908_800), undefined],
  ['follows 20 minutes ahead', ev(3, follows(3), '', NOW + 1200), ev(3, follows(3))],
  ['follows 5 minutes ahead (a fast clock)', ev(3, follows(4), '', NOW + 300), ev(3, follows(3))],
  ['relay list dated 2099', ev(10002, relays('wss://a'), '', 4_070_908_800), undefined],
  ['set dated 2099', ev(30000, [['d', 'x'], ...follows(2)], '', 4_070_908_800), undefined],
  ['note dated 2099 (scheduled?)', ev(1, [], 'hi', 4_070_908_800), undefined],
  ['deletion by a, dated 2099', ev(5, [['a', `3:${pk(9)}:`]], '', 4_070_908_800), undefined],
  ['deletion by e, dated 2099', ev(5, [['e', pk(1)]], '', 4_070_908_800), undefined],
];

const out = cases.map(([label, e, prev]) => { const a = assess(e, prev, NOW); return { label, now: NOW, event: e, prev: prev ?? null, hold: a.hold ?? null, refuse: a.refuse ?? null }; });
writeFileSync(new URL('../../android/app/src/test/resources/policy.json', import.meta.url), JSON.stringify(out, null, 2));
console.log(`wrote ${out.length} policy cases, ${out.filter(c => c.hold).length} held, ${out.filter(c => c.refuse).length} refused`);
