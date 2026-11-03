// Core §9.5, the JSON profile: what both implementations refuse, and how they write.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { parseJson, strictJson, utf8Strict, fromB64u, fromB64, jcs, randomBytes, utf8ToBytes, bytesToHex } from '../src/bytes.ts';
import { eventId, eventShape, siteEvent, newKey } from '../src/event.ts';
import { destructive, profileObject, deletionTargets } from '../src/destructive.ts';
import { placeholderList, changeKey } from '../src/approval.ts';
import { nip44Bytes, nip44Open } from '../src/nip44.ts';

const refused = (text: string, why?: RegExp) => assert.throws(() => strictJson(text), (e: any) => e.code === 'malformed' && (!why || why.test(e.message)), text);

test('§9.5 RFC 8259 exactly, and no key twice at any depth', () => {
  for (const t of ['﻿{}', '{"a":1,}', "{'a':1}", '[NaN]', '{"a":1} x', '/*c*/{}', '{"a":1} ', '[1,]', '', ' ', 'tru', '"\t"', '{"a" 1}'])
    refused(t);
  refused('{"a":1,"a":2}', /twice/);
  refused('{"x":{"b":[{"c":1,"c":1}]}}', /twice/);
  refused('{"a":1,"\\u0061":2}', /twice/);
  assert.deepEqual(strictJson(' \t\n\r{"a":[true,false,null,"x\\/y"]}\r\n'), { a: [true, false, null, 'x/y'] });
  const p = strictJson('{"__proto__":1}');
  assert.deepEqual(Object.keys(p), ['__proto__']);
  assert.equal(jcs(p), '{"__proto__":1}');
});

test('§9.5 integers only, spelled one way, at most 2^53 - 1', () => {
  for (const t of ['1.0', '1e0', '1E2', '-0', '0.5', '01', '+1', '9007199254740992', '-9007199254740992', '1e-400', '1.0000000000000001']) refused(t);
  assert.equal(strictJson('9007199254740991'), 9007199254740991);
  assert.equal(strictJson('-9007199254740991'), -9007199254740991);
  assert.equal(strictJson('0'), 0);
  // Kind 0's content: the grammar only, never refused for form or size.
  assert.deepEqual(parseJson('{"n":1e999,"m":-0,"f":1.5}', { numbers: 'grammar' }) !== null, true);
  assert.throws(() => parseJson('{"n":01}', { numbers: 'grammar' }));
});

test('§9.5 no lone surrogates, no control characters but five, raw or escaped', () => {
  refused('"\\ud800"', /surrogate/);
  refused('"\\udc00x"', /surrogate/);
  refused('"\ud800"', /surrogate/);
  refused('{"\\ud800":1}', /surrogate/);
  refused('"\\u0001"', /U\+0001/);
  refused('"\\u000b"', /U\+000B/);
  refused('"\\u0000"', /U\+0000/);
  assert.equal(strictJson('"\\b\\t\\n\\f\\r"'), '\b\t\n\f\r');
  assert.equal(strictJson('"\\ud83d\\ude00"'), '😀');
  assert.equal(strictJson('" \u007f"'), ' \u007f');
});

test('§9.5 depth: the outermost value is 1, depth 33 is malformed; each text on its own', () => {
  assert.doesNotThrow(() => strictJson('['.repeat(32) + ']'.repeat(32)));
  refused('['.repeat(33) + ']'.repeat(33), /deeper/);
  assert.doesNotThrow(() => strictJson('['.repeat(31) + '1' + ']'.repeat(31)));
  refused('['.repeat(32) + '1' + ']'.repeat(32), /deeper/);
  refused('{"a":'.repeat(33) + '1' + '}'.repeat(33), /deeper/);
  // A text inside a string is a string at its own depth.
  assert.doesNotThrow(() => strictJson('['.repeat(31) + JSON.stringify('['.repeat(32) + ']'.repeat(32)) + ']'.repeat(31)));
  assert.throws(() => jcs(JSON.parse('['.repeat(33) + ']'.repeat(33))), /deeper/);
});

test('§9.5 fatal UTF-8', () => {
  for (const b of [[0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xff], [0xe2, 0x82]])
    assert.throws(() => utf8Strict(Uint8Array.from(b)), /UTF-8/, bytesToHex(Uint8Array.from(b)));
  assert.equal(utf8Strict(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), '﻿{}', 'a BOM is kept, so the reader refuses it');
  refused(utf8Strict(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])));
});

test('§9.5 base64url and base64: one spelling each, zero unused bits', () => {
  assert.equal(fromB64u('AA').length, 1);
  for (const s of ['AB', 'A', 'AA==', 'A A', 'AA\n', '+/', 'AAA=', 'AAB']) assert.throws(() => fromB64u(s), /base64url/, s);
  assert.equal(fromB64u('AAA').length, 2);
  assert.equal(fromB64('AA==').length, 1);
  for (const s of ['AB==', 'AA', 'A===', 'AA=A', '-_==', 'AAB=', ' AA==']) assert.throws(() => fromB64(s), /base64/, s);
});

test('§9.5 JCS: keys by UTF-16 code units, the five escapes, everything else raw; nothing outside the profile', () => {
  assert.equal(jcs({ 9: 1, 10: 2, b: 3, a: 4 }), '{"10":2,"9":1,"a":4,"b":3}');
  assert.equal(jcs({ '\uffff': 3, '\ud83d\ude00': 2, '\u20ac': 1 }), '{"\u20ac":1,"\ud83d\ude00":2,"\uffff":3}', 'UTF-16 code units: 20AC, D83D DE00, FFFF (by code point U+1F600 would come last)');
  assert.equal(jcs('<&\u007f  😀/'), '"<&\u007f  😀/"');
  assert.equal(jcs('"\\\b\t\n\f\r'), '"\\"\\\\\\b\\t\\n\\f\\r"');
  for (const v of ['\u000b', '\ud800', 1.5, -0, 2 ** 53, { k: '\u0001' }, { '\udfff': 1 }]) assert.throws(() => jcs(v), /malformed/);
});

test('§9.5 event shape: exactly the NIP-01 fields, typed, lowercase hex', () => {
  const k = newKey();
  const r = { pubkey: k.pub, created_at: 1, kind: 1, tags: [['p', 'x']], content: 'hi' };
  const ok = { ...r, id: eventId(r) };
  assert.doesNotThrow(() => eventShape(ok, 'rumor'));
  assert.throws(() => eventShape({ ...ok, sig: 'a'.repeat(128) }, 'rumor'), /field "sig"/);
  assert.throws(() => eventShape(ok, 'signed'), /no "sig"/);
  assert.throws(() => eventShape({ ...ok, extra: 1 }, 'cosign'), /field "extra"/);
  assert.throws(() => eventShape({ ...ok, id: ok.id.toUpperCase() }, 'rumor'), /lowercase/);
  assert.throws(() => eventShape({ ...ok, kind: 65536 }, 'rumor'), /kind/);
  assert.throws(() => eventShape({ ...ok, created_at: -1 }, 'rumor'), /created_at/);
  assert.throws(() => eventShape({ ...ok, tags: [['p', 1]] }, 'rumor'), /tags/);
  assert.throws(() => eventShape({ ...ok, content: 'a\u000bb' }, 'rumor'), /U\+000B/);
  // NIP-01 ids are refused, not escaped, for what §9.5 refuses (Nostr libraries disagree on them).
  assert.throws(() => eventId({ ...r, content: 'line\u000bbreak' }), /U\+000B/);
  assert.equal(eventId({ ...r, content: 'a b' }), bytesToHex(new Uint8Array(Buffer.from(require_sha(`[0,"${k.pub}",1,1,[["p","x"]],"a b"]`)))));
});
const require_sha = (s: string) => { const { sha256 } = require_noble; return sha256(utf8ToBytes(s)); };
import * as require_noble from '@noble/hashes/sha2.js';

test("§9.5 a site's event: absent fields filled, its id, sig and extras dropped, causes named", () => {
  const g = newKey().pub;
  const e = siteEvent({ kind: 1, created_at: 5, id: 'f'.repeat(64), sig: 'nonsense', pubkey: '', relays: ['x'] }, g);
  assert.deepEqual(Object.keys(e).sort(), ['content', 'created_at', 'id', 'kind', 'pubkey', 'tags']);
  assert.deepEqual([e.pubkey, e.tags, e.content], [g, [], '']);
  assert.equal(e.id, eventId(e));
  assert.equal(siteEvent({ kind: 1, created_at: 5, pubkey: null, id: null, sig: null }, g).pubkey, g);
  assert.throws(() => siteEvent({ kind: 1, created_at: 5, pubkey: newKey().pub }, g), /another pubkey/);
  assert.throws(() => siteEvent({ kind: 1, created_at: 5, content: 'Word\u000bbreak' }, g), /contains control character U\+000B/);
  assert.throws(() => siteEvent({ kind: 1, created_at: 1.5 }, g), /created_at/);
  assert.throws(() => siteEvent({ created_at: 1 }, g), /kind/);
});

test('§5.8 with §9.5: tags counted from two elements, distinct targets, empty content, case-sensitive wss', () => {
  const ev = (kind: number, tags: string[][], content = '') => ({ kind, created_at: 0, tags, content });
  assert.equal(destructive(ev(3, [['p']])), true, '["p"] is no tag');
  assert.equal(destructive(ev(3, [[]])), true, '[] is no tag');
  assert.equal(destructive(ev(3, [['p', '']])), false, '["p",""] counts');
  assert.equal(destructive(ev(3, [['d', 'x']])), true);
  assert.equal(destructive(ev(3, [], ' ')), false, 'whitespace is not empty');
  assert.equal(destructive(ev(3, [], '{}')), false, '{} is not empty');
  const x = 'a'.repeat(64);
  assert.equal(deletionTargets(ev(5, Array.from({ length: 6 }, () => ['e', x]))), 1, 'the same target six times is one');
  assert.equal(deletionTargets(ev(5, [['e', x], ['a', x], ['e'], ['p', x]])), 2);
  assert.equal(destructive(ev(5, Array.from({ length: 6 }, () => ['e', x]))), false);
  assert.equal(destructive(ev(10002, [['r', 'WSS://relay.example']])), true, 'case-sensitive');
  assert.equal(destructive(ev(10002, [['r', 'ws://relay.example']])), false);
  assert.equal(destructive(ev(10002, [['r']])), true);
  // Kind 0: the first five rules only; the whitespace set written out.
  assert.equal(destructive(ev(0, [], '{"name":"x","n":1e999,"f":1.5}')), false, 'numbers are never refused');
  assert.equal(destructive(ev(0, [], '﻿{"name":"x"}')), true, 'a BOM counts as empty');
  assert.equal(destructive(ev(0, [], '{"name":"x","name":"y"}')), true, 'a repeated key counts as empty');
  assert.equal(destructive(ev(0, [], '{"name":"\\u0001x"}')), true, 'a stray control character counts as empty');
  assert.equal(destructive(ev(0, [], '{"name":"　 ﻿ "}')), true, 'only whitespace');
  assert.equal(destructive(ev(0, [], '{"name":"​"}')), false, 'U+200B is not in the set');
  assert.equal(destructive(ev(0, [], '{"name":"ㅤ"}')), false);
  assert.equal(destructive(ev(0, [], '{"name":"."}')), false);
  assert.equal(destructive(ev(0, [], '{"about":1}')), true, 'not a string');
  assert.equal(profileObject('[]'), null);
});

test('§6.7.2: the paper placeholder keeps every field but inner and state; §9.5 change comparison', () => {
  const c = { paper: { key: 'k', replaces: 'r', inner: 'i', state: ['s'], holders: ['h'], heir: 'e', module_field: { x: 1 } } } as any;
  assert.deepEqual(placeholderList([c])[0], { paper: { key: 'k', replaces: 'r', holders: ['h'], heir: 'e', module_field: { x: 1 } } });
  assert.equal(changeKey({ add: { key: 'k', kind: 'device', salt: 1 } } as any), changeKey({ add: { key: 'k', kind: 'device', salt: 1, lock: null } } as any));
  assert.notEqual(changeKey({ add: { key: 'k', kind: 'device', salt: 1, x: 1 } } as any), changeKey({ add: { key: 'k', kind: 'device', salt: 1 } } as any));
});

test('§9.5 NIP-44: our decryption matches nostr-tools, refuses loose base64 and invalid UTF-8', () => {
  const a = newKey(), b = newKey();
  const ck = nip44.v2.utils.getConversationKey(a.sk, b.pub);
  for (const m of ['x', 'é😀', 'a'.repeat(1000), 'b'.repeat(40000)]) assert.equal(nip44Open(nip44.v2.encrypt(m, ck), ck), m);
  const p = nip44.v2.encrypt('a'.repeat(40), ck);
  assert.ok(p.endsWith('='), 'this length needs padding');
  assert.throws(() => nip44Bytes(p.replace(/=+$/, ''), ck), /undecryptable/);
  assert.throws(() => nip44Bytes(p.slice(0, -4) + '!!!!', ck), /undecryptable/);
  const flipped = Buffer.from(p, 'base64'); flipped[40] ^= 1;
  assert.throws(() => nip44Bytes(flipped.toString('base64'), ck), /mac/);
  void randomBytes;
});
