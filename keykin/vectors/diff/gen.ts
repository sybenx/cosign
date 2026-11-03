// Differential probes for the Kotlin port (review 6). Writes probes.json: each probe has an
// area, a name, its input and the TypeScript reference's result ("ts"). kprobe/ runs the same
// inputs through the Kotlin and compare.ts prints the disagreements.
// Run: node gen.ts > probes.json   (from this directory)
const K = new URL('../..', import.meta.url).pathname.replace(/\/$/, '');
const { fixture } = await import(`${K}/test/helpers.ts`);
const { eventId, eventShape, schnorrVerify, newKey } = await import(`${K}/src/event.ts`);
const { jcs, KeykinError, sha, bytesToHex, hexToBytes, concatBytes, utf8ToBytes, strictJson, utf8Strict, fromB64u, fromB64 } = await import(`${K}/src/bytes.ts`);
const { checkAssertion, softLock } = await import(`${K}/src/lock.ts`);
const { lockChallenge } = await import(`${K}/src/codes.ts`);
const { destructive } = await import(`${K}/src/destructive.ts`);
const { checkLifetime } = await import(`${K}/src/lifetimes.ts`);
const { checkEpochRecord } = await import(`${K}/src/record.ts`);
const { computeMembership } = await import(`${K}/src/membership.ts`);
const { approveLock, approvePair } = await import(`${K}/src/approval.ts`);
const { deal: dealRedeal } = await import(`${K}/src/redeal.ts`);
const { p256 } = await import(`${K}/node_modules/@noble/curves/nist.js`);
const { secp256k1 } = await import(`${K}/node_modules/@noble/curves/secp256k1.js`);
const { sha256 } = await import(`${K}/node_modules/@noble/hashes/sha2.js`);

const out: any[] = [];
const res = (f: () => unknown) => { try { const v = f(); return v === undefined ? 'ok' : v; } catch (e: any) { return e instanceof KeykinError ? `refuse:${e.code}` : `THROW:${e?.message ?? e}`; } };
const P = (area: string, name: string, input: any, ts: unknown) => out.push({ area, name, input, ts });

// ---------------- NIP-01 event ids ----------------
const base = { pubkey: 'ab'.repeat(32), created_at: 1_800_000_000, kind: 1, tags: [['p', 'x']] as any, content: '' };
const contents: Record<string, string> = {
  ascii: 'hello', controls: '\u0000\u0001\u001f\u007f\b\f\n\r\t', quote_bs: '"\\/', u2028: '  ', emoji: '😀',
  lone_high: 'a\ud800b', lone_low: '\udc00', nonchar: '￿﻿', c1: '\u0085\u009f', en_dash: '– €',
};
// §9.5: the text through the profile, the rumor shape, then the id.
const EID = (name: string, text: string) => P('event_id', name, text, res(() => { const o = strictJson(text); eventShape({ ...o, id: '0'.repeat(64) }, 'rumor'); return eventId(o); }));
for (const [n, c] of Object.entries(contents)) EID(`content ${n}`, JSON.stringify({ ...base, content: c }));
EID('tag lone surrogate', JSON.stringify({ ...base, tags: [['p', '\ud800']] }));
EID('created_at 1.5', JSON.stringify({ ...base, created_at: 1.5 }));
EID('created_at as a string', JSON.stringify({ ...base, created_at: '1800000000' }));
EID('created_at 2^53+2', JSON.stringify({ ...base, created_at: 2 ** 53 + 2 }));
EID('kind 1.0', JSON.stringify(base).replace('"kind":1', '"kind":1.0'));
EID('content U+000B (Word line break)', JSON.stringify({ ...base, content: 'a\u000bb' }));
EID('content escaped U+0001', JSON.stringify(base).replace('"content":""', '"content":"\\u0001"'));
EID('content U+2028 in a note', JSON.stringify({ ...base, content: 'a\u2028b' }));
EID('kind 65536', JSON.stringify({ ...base, kind: 65536 }));
EID('created_at -1', JSON.stringify({ ...base, created_at: -1 }));
EID('uppercase pubkey', JSON.stringify({ ...base, pubkey: 'AB'.repeat(32) }));
EID('an extra field', JSON.stringify({ ...base, relays: [] }));
EID('tags with a number', JSON.stringify({ ...base, tags: [['p', 1]] }));
EID('content twice', JSON.stringify(base).replace('"content":""', '"content":"","content":"x"'));
EID('pubkey missing', JSON.stringify({ ...base, pubkey: undefined }));

// §9.5's reader on its own: every text both sides must decide alike.
const RD = (name: string, text: string) => P('jcs', `read: ${name}`, text, res(() => jcs(strictJson(text))));
for (const [n, t] of Object.entries({
  bom: '\ufeff[]', trailing_comma: '[1,]', single_quote: "['a']", nan: '[NaN]', comment: '/*x*/[]', nbsp_around: '\u00a0[]', tab_around: '\t[]\r\n',
  raw_tab_in_string: '["a\tb"]', escaped_tab: '["a\\tb"]', escaped_u000b: '["\\u000b"]', escaped_u0000: '["\\u0000"]', escaped_lone_low: '["\\udc00"]',
  escaped_pair: '["\\ud83d\\ude00"]', escaped_slash: '["a\\/b"]', dup_escaped: '{"a":1,"\\u0061":2}', dup_deep: '[{"x":{"y":1,"y":1}}]',
  int_max: '[9007199254740991]', int_min: '[-9007199254740991]', int_over: '[9007199254740992]', leading_zero: '[01]', plus: '[+1]', e0: '[1e0]', minus_zero: '[-0]',
  tiny: '[1e-400]', near_one: '[1.0000000000000001]', depth_32: '['.repeat(32) + ']'.repeat(32), depth_33: '['.repeat(33) + ']'.repeat(33),
  depth_33_scalar: '['.repeat(32) + '1' + ']'.repeat(32), proto_key: '{"__proto__":{"x":1}}', int_keys: '{"10":1,"9":2,"1":3}',
  empty_key: '{"":1}', u007f_u2029: '["\u007f\u2029"]', two_values: '[] []', bare_string: '"x"', bare_int: '7', empty: '', ws_only: ' ',
})) RD(n, t);

// §9.5 fatal UTF-8 (hex bytes in, then the reader).
for (const [n, h] of Object.entries({ ok: '5b2278225d', overlong_slash: '5b22c0af225d', surrogate: '5b22eda080225d', beyond: '5b22f4908080225d', truncated: '5b22e282225d',
  bom: 'efbbbf5b5d', lone_ff: '5bff5d', nul_escape: '5b225c7530303030225d' }))
  P('utf8', n, h, res(() => jcs(strictJson(utf8Strict(hexToBytes(h))))));

// §9.5 base64url and standard base64.
for (const s of ['', 'AA', 'AB', 'A', 'AAA', 'AAB', 'AA==', 'A A', 'AA\n', '+/', '_-', 'AAAA', '____', '___'])
  P('b64u', JSON.stringify(s), s, res(() => bytesToHex(fromB64u(s))));
for (const s of ['', 'AA==', 'AB==', 'AA', 'AAA=', 'AAB=', 'A===', 'AA=A', '-_==', '+/+/', 'AAAA', ' AA==', 'AA==\n'])
  P('b64', JSON.stringify(s), s, res(() => bytesToHex(fromB64(s))));

// ---------------- JCS ----------------
const jcsIn: Record<string, string> = {
  en_dash: '["Ann’s phone – €"]', zwsp: '["a​b"]', c1: '["\u0085"]', backslash_slash: '["a\\\\/b"]', lt_slash: '["</x>"]',
  lone: '["\\ud800"]', float: '[1.5]', exp: '[1e21]', big: '[12345678901234567890]', neg0: '[-0]', one_point_0: '[1.0]',
  keys_utf16: '{"\\ud83d\\ude00":1,"\\uffff":2,"a":3,"B":4}', nested: '{"b":{"d":1,"c":[true,null]},"a":"x"}',
};
for (const [n, t] of Object.entries(jcsIn)) P('jcs', n, t, res(() => jcs(strictJson(t))));

// ---------------- BIP-340 ----------------
const Pt = secp256k1.Point, N = Pt.Fn.ORDER;
const modn = (a: bigint) => ((a % N) + N) % N;
const th = (tag: string, ...parts: Uint8Array[]) => { const t = sha256(utf8ToBytes(tag)); return sha256(concatBytes(t, t, ...parts)); };
const big = (b: Uint8Array) => BigInt('0x' + (bytesToHex(b) || '0'));
const b32 = (x: bigint) => hexToBytes(x.toString(16).padStart(64, '0'));
/** BIP-340 signing with the challenge over arbitrary public-key bytes (so a non-32-byte encoding can be "valid"). */
function signWithPubBytes(d0: bigint, msg: Uint8Array, pubBytes: Uint8Array) {
  const Pp = Pt.BASE.multiply(d0); const d = Pp.y % 2n === 0n ? d0 : N - d0;
  let k0 = modn(big(sha256(concatBytes(b32(d), msg)))); const R = Pt.BASE.multiply(k0); const k = R.y % 2n === 0n ? k0 : N - k0;
  const e = modn(big(th('BIP0340/challenge', b32(R.x), pubBytes, msg)));
  return bytesToHex(concatBytes(b32(R.x), b32(modn(k + e * d))));
}
{
  const d = 0x1234567890abcdefn; const x = Pt.BASE.multiply(d).x; const xh = x.toString(16).padStart(64, '0'); const msg = sha256(utf8ToBytes('m'));
  const good = signWithPubBytes(d, msg, hexToBytes(xh));
  const add = (name: string, sig: string, pub: string) => P('schnorr', name, { sig, msg: bytesToHex(msg), pub }, schnorrVerify(sig, msg, pub));
  add('valid', good, xh);
  add('sig uppercase', good.toUpperCase(), xh);
  add('pub uppercase', good, xh.toUpperCase());
  // "+d" parses as 0x0d with Kotlin's String.toInt(16).
  const plus = good.slice(0, 2).startsWith('0') ? '+' + good.slice(1) : null;
  { let s = good, i = s.search(/0[0-9a-f]/); s = s.slice(0, i) + '+' + s.slice(i + 1); add(`sig with "+" for a leading 0 nibble (pos ${i})`, s, xh); }
  add('pub as 33 bytes 00||x, challenge over the 33 bytes', signWithPubBytes(d, msg, hexToBytes('00' + xh)), '00' + xh);
  add('sig 63 bytes', good.slice(0, 126), xh);
  add('s = n', good.slice(0, 64) + N.toString(16), xh);
  void plus;
}

// ---------------- WebAuthn lock assertions ----------------
{
  const g = 'cd'.repeat(32), w = utf8ToBytes('sign-what');
  const sk = p256.utils.randomSecretKey(); const pubB = p256.getPublicKey(sk, false); const pub = bytesToHex(pubB); const rp = bytesToHex(sha256(utf8ToBytes('keykin.test')));
  const auth = new Uint8Array(37); auth.set(hexToBytes(rp), 0); auth[32] = 5; auth[36] = 1;
  const cdOf = (s: string) => utf8ToBytes(s);
  const cdGood = JSON.stringify({ type: 'webauthn.get', challenge: lockChallenge(g, w), origin: 'keykin:app' });
  const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const msgOf = (cd: Uint8Array) => concatBytes(auth, sha256(cd));
  const der = (r: Uint8Array, s: Uint8Array) => { const i = (x: Uint8Array) => concatBytes(new Uint8Array([2, x.length]), x); const body = concatBytes(i(r), i(s)); return concatBytes(new Uint8Array([0x30, body.length]), body); };
  const strip = (x: bigint) => { let h = x.toString(16); if (h.length % 2) h = '0' + h; return hexToBytes(h); };
  const canon = (x: bigint) => { const b = strip(x); return b[0] & 0x80 ? concatBytes(new Uint8Array([0]), b) : b; };
  const sigRS = (cd: Uint8Array) => { const c = p256.sign(msgOf(cd), sk, { format: 'compact', lowS: false, extraEntropy: true }); return { r: big(c.slice(0, 32)), s: big(c.slice(32)) }; };
  const A = (name: string, lockPub: string, lockRp: string, a: any) => P('lock', name, { g, what: bytesToHex(w), pub: lockPub, rp: lockRp, assertion: a }, checkAssertion(g, { pub: lockPub, rp: lockRp }, w, a));
  const mk = (cdStr: string, sigBytes?: Uint8Array, authB64?: string, cdB64?: string) => {
    const cd = cdOf(cdStr); const { r, s } = sigRS(cd);
    return { authData: authB64 ?? b64(auth), clientData: cdB64 ?? b64(cd), sig: b64(sigBytes ?? der(canon(r), canon(s))) };
  };
  A('valid', pub, rp, mk(cdGood));
  { const cd = cdOf(cdGood); const { r, s } = sigRS(cd); const n = p256.Point.Fn.ORDER; A('high-S', pub, rp, mk(cdGood, der(canon(r), canon(n - s)))); }
  // DER INTEGER with the high bit set and no 0x00 pad: a negative number in DER.
  { const cd = cdOf(cdGood); let r = 0n, s = 0n; for (;;) { ({ r, s } = sigRS(cd)); if (r >> 255n) break; } A('r high bit, no 0x00 pad (negative DER integer)', pub, rp, { authData: b64(auth), clientData: b64(cd), sig: b64(der(strip(r), canon(s))) }); }
  { const cd = cdOf(cdGood); let r = 0n, s = 0n; for (;;) { ({ r, s } = sigRS(cd)); if (!(r >> 255n)) break; } A('r with a redundant 0x00', pub, rp, { authData: b64(auth), clientData: b64(cd), sig: b64(der(concatBytes(new Uint8Array([0]), canon(r)), canon(s))) }); }
  { const cd = cdOf(cdGood); const { r, s } = sigRS(cd); const d = der(canon(r), canon(s)); const ber = concatBytes(new Uint8Array([0x30, 0x81, d[1]]), d.slice(2)); A('BER long-form length', pub, rp, { authData: b64(auth), clientData: b64(cd), sig: b64(ber) }); }
  { const cd = cdOf(cdGood); const { r, s } = sigRS(cd); A('trailing byte after DER', pub, rp, { authData: b64(auth), clientData: b64(cd), sig: b64(concatBytes(der(canon(r), canon(s)), new Uint8Array([0]))) }); }
  { const y = big(pubB.slice(33)); const off = '04' + bytesToHex(pubB.slice(1, 33)) + ((y + 1n) % (2n ** 256n)).toString(16).padStart(64, '0'); A('public key off the curve', off, rp, mk(cdGood)); }
  A('public key all zero', '04' + '00'.repeat(64), rp, mk(cdGood));
  A('malformed lock pub, wrong clientData type (which check first)', 'zz', rp, mk(cdGood.replace('webauthn.get', 'webauthn.create')));
  A('lock pub uppercase hex', pub.toUpperCase(), rp, mk(cdGood));
  A('rp uppercase hex', pub, rp.toUpperCase(), mk(cdGood));
  A('rp wrong length, otherwise valid', pub, rp + '00', mk(cdGood));
  A('clientData with a duplicate key (create then get)', pub, rp, mk('{"type":"webauthn.create","type":"webauthn.get","challenge":"' + lockChallenge(g, w) + '"}'));
  A('clientData in single quotes / unquoted keys', pub, rp, mk("{type:'webauthn.get',challenge:'" + lockChallenge(g, w) + "'}"));
  A('clientData with trailing garbage', pub, rp, mk(cdGood + 'xyz'));
  A('clientData with a trailing comma', pub, rp, mk(cdGood.slice(0, -1) + ',}'));
  A('clientData with a UTF-8 BOM', pub, rp, mk('﻿' + cdGood));
  A('clientData is an array', pub, rp, mk('[]'));
  { const a = mk(cdGood); A('authData in the standard base64 alphabet with padding', pub, rp, { ...a, authData: Buffer.from(auth).toString('base64') }); }
  { const a = mk(cdGood); A('sig base64 with a space in it', pub, rp, { ...a, sig: a.sig.slice(0, 10) + ' ' + a.sig.slice(10) }); }
  { const a = mk(cdGood); A('authData with trailing "=" padding (base64url)', pub, rp, { ...a, authData: a.authData + '=' }); }
}

// ---------------- destructive ----------------
const D = (name: string, kind: number, content: string, tags: string[][] = [], recent = 0) => P('destructive', name, { kind, content, tags, recent }, res(() => destructive({ kind, created_at: 0, tags, content }, recent)));
D('kind 0 nested duplicate key', 0, '{"name":"x","a":{"b":1,"b":2}}');
D('kind 0 duplicate key in an array of objects', 0, '{"name":"x","a":[{"b":1,"b":2}]}');
D('kind 0 duplicate top-level name', 0, '{"name":"x","name":""}');
D('kind 0 escaped duplicate key', 0, '{"name":"x","\\u006eame":"y"}');
D('kind 0 trailing comma', 0, '{"name":"x",}');
D('kind 0 single quotes', 0, "{'name':'x'}");
D('kind 0 unquoted value', 0, '{"name":x}');
D('kind 0 trailing garbage', 0, '{"name":"x"} y');
D('kind 0 leading \\u0001', 0, '\u0001{"name":"x"}');
D('kind 0 raw tab inside a string', 0, '{"name":"a\tb"}');
D('kind 0 name is U+FEFF', 0, '{"name":"\\ufeff"}');
D('kind 0 name is U+001C', 0, '{"name":"\\u001c"}');
D('kind 0 name is U+00A0', 0, '{"name":"\\u00a0"}');
D('kind 0 name is U+180E', 0, '{"name":"\\u180e"}');
D('kind 0 name is U+0085', 0, '{"name":"\\u0085"}');
D('kind 0 JSON with a comment', 0, '{"name":"x" /* c */}');
D('kind 0 "null" value then name', 0, '{"a":null,"a":1,"name":"x"}');
D('kind 3 empty tag', 3, '', [[]]);
D('kind 5 empty tag', 5, '', [[]]);
D('kind 10002 empty tag', 10002, '', [[]]);
D('kind 10002 "r" without a URL', 10002, '', [['r']]);
// §5.8 with §9.5 (14.15): counting, targets, empty content, the whitespace set, kind 0 numbers.
{
  const t = 'a'.repeat(64);
  D('kind 3 ["p"] is no tag', 3, '', [['p']]);
  D('kind 3 ["p",""] counts', 3, '', [['p', '']]);
  D('kind 3 content " "', 3, ' ');
  D('kind 3 content "{}"', 3, '{}');
  D('kind 30000 only d', 30000, '', [['d', 'x']]);
  D('kind 5 one target six times', 5, '', Array.from({ length: 6 }, () => ['e', t]));
  D('kind 5 e and a same value', 5, '', [['e', t], ['a', t], ['e', t], ['a', t], ['e', 'b'.repeat(64)]]);
  D('kind 5 five distinct', 5, '', Array.from({ length: 5 }, (_, k) => ['e', String(k)]));
  D('kind 5 one-element e tags', 5, '', Array.from({ length: 6 }, () => ['e']));
  D('kind 5 burst with duplicates', 5, '', [['e', t], ['e', t]], 4);
  D('kind 10002 WSS:// upper case', 10002, '', [['r', 'WSS://relay.example']]);
  D('kind 10002 ws://', 10002, '', [['r', 'ws://relay.example']]);
  for (const [n, c] of Object.entries({
    'numbers by grammar only': '{"name":"x","n":1e999,"m":-0,"f":1.5,"b":123456789012345678901234567890}',
    'bad number grammar': '{"name":"x","n":01}',
    'escaped control character': '{"name":"\\u0001x"}',
    'escaped lone surrogate elsewhere': '{"name":"x","about":"\\ud800"}',
    'depth 33 elsewhere': '{"name":"x","deep":' + '['.repeat(32) + ']'.repeat(32) + '}',
    'depth 32 elsewhere': '{"name":"x","deep":' + '['.repeat(31) + ']'.repeat(31) + '}',
    'name of U+3000 U+00A0 U+FEFF U+2028': '{"name":"　 ﻿ "}',
    'name of U+000B (escaped)': '{"name":"\\u000b"}',
    'name of U+200B': '{"name":"​"}',
    'name of U+3164': '{"name":"ㅤ"}',
    'name of U+180E': '{"name":"᠎"}',
    'name of U+0085': '{"name":"\u0085"}',
    'name "."': '{"name":"."}',
    'BOM before': '﻿{"name":"x"}',
    'an array': '[{"name":"x"}]',
  })) D(`kind 0 ${n}`, 0, c);
}

// ---------------- lifetimes ----------------
for (const t of ['delta', 'paper_ck', 'dk_seed', 'release_seed', 'paper_item', 'welcome', 'repair_sigma', 'change', 'ack', 'pair_request', 'cancel', 'unknown_x'])
  for (const c of ['member', 'ask']) P('lifetime', `${t}/${c}`, { type: t, cls: c, age: 10 }, checkLifetime(t, c, 1000, 1010));
P('lifetime', 'proto/ask', { type: '__proto__', cls: 'ask', age: 10 }, checkLifetime('__proto__', 'ask', 1000, 1010));

// ---------------- epoch records ----------------
const R = (name: string, F: any, ev: any) => P('record', name, { g: F.g, event: ev }, res(() => { checkEpochRecord(ev, { g: F.g }); }));
{ const F = fixture(); R('valid', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { delete c.prev; } }); R('prev missing', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.t = '4'; } }); R('t as the string "4"', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.epoch.n = '1'; } }); R('epoch.n as the string "1"', F, F.recEv); }
{ const F = fixture(); R('epoch.n written 1.0', F, F.sign(30242, F.recEv.content.replace('"n":1,', '"n":1.0,'), [['d', 'keykin'], ['v', '1'], ['epoch', '1']])); }
{ const F = fixture(); R('v written 1.0', F, F.sign(30242, F.recEv.content.replace('"v":1,', '"v":1.0,'), [['d', 'keykin'], ['v', '1'], ['epoch', '1']])); }
{ const F = fixture({ mutate: (c: any) => { c.members[1].host = ''; } }); R('server host ""', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.members[1].host = 5; } }); R('server host a number', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.members[0].shares = ['1', 2, 3]; } }); R('device share "1" (string)', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.members[0].shares = [1.5, 2, 3]; } }); R('device share 1.5', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.removed = ['zz']; } }); R('removed holds a non-key', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.commitment = c.commitment.map((h: string) => h.toUpperCase()); } }); R('commitment in uppercase hex', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { c.commitment[1] = '02' + 'ff'.repeat(32); } }); R('commitment point off the curve', F, F.recEv); }
{ const F = fixture(); R('content with a duplicate key', F, F.sign(30242, F.recEv.content.replace('"v":1,', '"v":1,"v":1,'), [['d', 'keykin'], ['v', '1'], ['epoch', '1']])); }
{ const F = fixture({ mutate: (c: any) => { c.members.push({ key: 'ee'.repeat(32), kind: 'observer', shares: [] }); } }); R('unknown-kind member with no shares', F, F.recEv); }
{ const F = fixture({ mutate: (c: any) => { delete c.members[0].kind; } }); R('member without a kind', F, F.recEv); }

// ---------------- membership ----------------
const EXP = 1_900_000_000;
const F = fixture(); const A0 = F.devices[0];
const B = newKey(), C = newKey();
const view = (evs: any[]) => res(() => {
  const m = computeMembership(F.rec, evs);
  return { devices: [...m.devices].sort(), removed: [...m.removed].sort(), seats: Object.fromEntries([...m.seats].map(([k, s]: any) => [k, s.holder?.key ?? null])),
    backup: m.backupKey, refused: m.refused.map((x: any) => x.code).sort(), invariant: m.invariantError !== null,
    locks: Object.fromEntries([...m.locks].map(([k, l]: any) => [k, l?.pub ?? null])) };
});
const M = (name: string, evs: any[]) => P('membership', name, { record: F.recEv, changes: evs }, view(evs));
const lockAp = (l: any[], exp = EXP) => { try { return approveLock(F.g, F.epochId, l, exp, A0.kp.pub, A0.lock!); } catch { return { expiry: exp, lock: { member: A0.kp.pub, assertion: { authData: "", clientData: "", sig: "" } } }; } };
const addCh = (a: any) => { const l = [{ add: a }]; return F.change(l[0], l, lockAp(l)); };
const listEvs = (list: any[], ap: any, d = dealRedeal(F.g, A0.kp, [], new Map(), F.backup.kp.pub, [5, 6])) => list.map((c) => F.change('redeal' in c ? { redeal: d.redeal } : c, list, ap));
const addB = addCh({ key: B.pub, kind: 'device', lock: null, salt: 0 });
M('add (baseline)', [addB]);
M('add whose lock is missing (not null)', [addCh({ key: B.pub, kind: 'device', salt: 0 })]);
M('add whose lock is malformed', [addCh({ key: B.pub, kind: 'device', lock: { pub: 'zz', rp: 'zz' }, salt: 0 })]);
M('add with salt 1.5', [addCh({ key: B.pub, kind: 'device', lock: null, salt: 1.5 })]);
M('add with salt "0"', [addCh({ key: B.pub, kind: 'device', lock: null, salt: '0' })]);
M('add with salt 2^32 (u32 overflow)', [addCh({ key: B.pub, kind: 'device', lock: null, salt: 2 ** 32 })]);
M('add with a curly apostrophe in an extra field', [addCh({ key: B.pub, kind: 'device', lock: null, salt: 0, label: 'Ann’s phone' })]);
M('add with "\\/" in an extra field', [addCh({ key: B.pub, kind: 'device', lock: null, salt: 0, label: 'a\\/b' })]);
M('add with an en dash in an extra field', [addCh({ key: B.pub, kind: 'device', lock: null, salt: 0, label: 'x–y' })]);
{ const l = [{ add: { key: B.pub, kind: 'device', lock: null, salt: 0 } }]; const ap = lockAp(l);
  M('change content with "v":1.0', [F.sign(24302, JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: l[0], list: l, approval: ap }).replace('"v":1,', '"v":1.0,'), [['v', '1'], ['epoch', F.epochId]])]);
  M('change content with a duplicate key', [F.sign(24302, JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: l[0], list: l, approval: ap }).replace('"v":1,', '"v":1,"v":1,'), [['v', '1'], ['epoch', F.epochId]])]);
  M('change content without "list"', [addB, F.sign(24302, JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: l[0], approval: ap }), [['v', '1'], ['epoch', F.epochId]])]);
  M('change content without "approval"', [addB, F.sign(24302, JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: l[0], list: l }), [['v', '1'], ['epoch', F.epochId]])]);
  M('change: null', [addB, F.sign(24302, JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: null, list: l, approval: ap }), [['v', '1'], ['epoch', F.epochId]])]);
  M('lock approval without an assertion', [addB, F.change(l[0], l, { expiry: EXP, lock: { member: A0.kp.pub } })]);
  M('approval with a negative expiry', [addB, F.change(l[0], l, { ...ap, expiry: -1 })]);
  M('approval with expiry "1900000000" (string)', [addB, F.change(l[0], l, { ...ap, expiry: String(EXP) })]);
}
{ const l = [{ x: 1, add: { key: C.pub, kind: 'device', lock: null, salt: 0 } }]; M('change with an extra key before its type', [F.change(l[0], l, lockAp(l))]); }
{ const l = [{ add: { key: C.pub, kind: 'device', lock: null, salt: 0 }, zz: 1 }]; M('change with an extra key after its type', [F.change(l[0], l, lockAp(l))]); }
// Remove with a redeal whose dealer signature is bad.
{ const l = [{ remove: B.pub }, { redeal: { dealer: A0.kp.pub } }]; const d = dealRedeal(F.g, A0.kp, [], new Map(), F.backup.kp.pub, [5, 6]);
  d.redeal.sig = d.redeal.sig.slice(0, -2) + (d.redeal.sig.endsWith('00') ? '01' : '00');
  M('[remove, redeal] whose redeal has a bad dealer signature', [addB, ...listEvs(l, lockAp(l), d)]); }
{ const l = [{ remove: B.pub }, { redeal: { dealer: A0.kp.pub } }]; const d = dealRedeal(F.g, A0.kp, [], new Map(), F.backup.kp.pub, [5, 6]); (d.redeal as any).D = ['02' + 'ff'.repeat(32), d.redeal.D[1], d.redeal.D[2]];
  M('[remove, redeal] whose redeal D1 is off the curve', [addB, ...listEvs(l, lockAp(l), d)]); }
{ const l = [{ remove: B.pub, to: 'zz' }, { redeal: { dealer: A0.kp.pub } }]; M('remove with a malformed "to"', [addB, ...listEvs(l, lockAp(l))]); }
// Abandoning a remove list's redeal.
{ const l = [{ remove: B.pub }, { redeal: { dealer: A0.kp.pub } }]; const d1 = dealRedeal(F.g, A0.kp, [], new Map(), F.backup.kp.pub, [5, 6]); const rmEvs = listEvs(l, lockAp(l), d1);
  const l2 = [{ redeal: { dealer: A0.kp.pub } }]; const d2 = dealRedeal(F.g, A0.kp, [], new Map(), F.backup.kp.pub, [5, 6], [d1.redeal.id]);
  M('a bare redeal that abandons a remove list\'s redeal', [addB, ...rmEvs, ...listEvs(l2, lockAp(l2), d2)]); }
// Lock changes.
{ const lk = (nw: any, replaces: any) => { const l = [{ lock: { member: A0.kp.pub, replaces, new: nw } }]; return F.change(l[0], l, approvePair(F.g, F.epochId, l, EXP, A0.kp, B, 'ee'.repeat(16))); };
  M('lock change with a malformed new lock', [addB, lk({ pub: 'zz', rp: 'zz' }, A0.lock!.pub.pub)]);
  { const l = [{ lock: { member: A0.kp.pub, new: softLock().pub } }]; M('lock change without "replaces"', [addB, F.change(l[0], l, approvePair(F.g, F.epochId, l, EXP, A0.kp, B, 'ee'.repeat(16)))]); }
  M('lock change with replaces 5', [addB, lk(softLock().pub, 5)]);
  M('pair approval without "r"', [addB, (() => { const l = [{ lock: { member: A0.kp.pub, replaces: A0.lock!.pub.pub, new: softLock().pub } }]; const ap: any = approvePair(F.g, F.epochId, l, EXP, A0.kp, B, 'ee'.repeat(16)); delete ap.pair[0].r; return F.change(l[0], l, ap); })()]);
}
// Seats.
const seatEvs = (idx: string, replaces: any, entry: any, exp = EXP) => { const l = [{ seat: { seat: idx, new: entry, replaces } }, { redeal: { dealer: A0.kp.pub } }]; return listEvs(l, lockAp(l, exp)); };
const srvEntry = (i: number, host: any = newKey().pub) => ({ key: newKey().pub, kind: 'server', shares: [i], host });
M('seat server:+8', seatEvs('server:+8', F.servers[2].kp.pub, srvEntry(8)));
M('seat change whose new entry is a helper on a server seat', seatEvs('server:8', F.servers[2].kp.pub, { key: newKey().pub, kind: 'helper', shares: [8] }));
M('seat change whose new key is not hex', seatEvs('server:8', F.servers[2].kp.pub, { key: 'zz', kind: 'server', shares: [8], host: newKey().pub }));
M('seat change without "replaces"', (() => { const l = [{ seat: { seat: 'server:8', new: srvEntry(8) } }, { redeal: { dealer: A0.kp.pub } }]; return listEvs(l, lockAp(l)); })());
M('two server seats with host "" within 24 h', [...seatEvs('server:4', F.servers[0].kp.pub, srvEntry(4, '')), ...seatEvs('server:7', F.servers[1].kp.pub, srvEntry(7, ''))]);
M('server seat host "" and a helper seat, within 24 h', [...seatEvs('server:4', F.servers[0].kp.pub, srvEntry(4, '')), ...seatEvs('helper', null, { key: newKey().pub, kind: 'helper', shares: F.rec.seats.helper })]);
M('one server seat with host ""', seatEvs('server:4', F.servers[0].kp.pub, srvEntry(4, '')));
// Papers.
{ const K2 = newKey(); const l: any[] = [{ paper: { key: K2.pub, replaces: F.backup.kp.pub, holders: null } }, { redeal: { dealer: A0.kp.pub } }]; const a = lockAp(l); const d = dealRedeal(F.g, A0.kp, [], new Map(), K2.pub, [5, 6]);
  M('paper with holders: null', [F.change({ paper: { key: K2.pub, replaces: F.backup.kp.pub, holders: null, inner: 'aa'.repeat(32), state: [] } }, l, a), F.change({ redeal: d.redeal }, l, a)]); }
{ const K2 = newKey(); const l: any[] = [{ paper: { key: K2.pub, replaces: F.backup.kp.pub } }, { redeal: { dealer: A0.kp.pub } }]; const a = lockAp(l); const d = dealRedeal(F.g, A0.kp, [], new Map(), K2.pub, [5, 6]);
  M('paper with state "x" (not an array)', [F.change({ paper: { key: K2.pub, replaces: F.backup.kp.pub, inner: 'aa'.repeat(32), state: 'x' } }, l, a), F.change({ redeal: d.redeal }, l, a)]); }
{ const K2 = newKey(); const l: any[] = [{ paper: { key: K2.pub, replaces: F.backup.kp.pub, heir: 'Zoë – Ann' } }, { redeal: { dealer: A0.kp.pub } }]; const a = lockAp(l); const d = dealRedeal(F.g, A0.kp, [], new Map(), K2.pub, [5, 6]);
  M('paper with an heir name holding an en dash', [F.change({ paper: { key: K2.pub, replaces: F.backup.kp.pub, heir: 'Zoë – Ann', inner: 'aa'.repeat(32), state: [] } }, l, a), F.change({ redeal: d.redeal }, l, a)]); }

// Recovery approvals (adds approved by the paper after a wait).
{ const { approveRecovery, signWaited } = await import(`${K}/src/approval.ts`); const { recoveryWaitId } = await import(`${K}/src/codes.ts`);
  const l = [{ add: { key: C.pub, kind: 'device', lock: null, salt: 0 } }];
  const rec = (r: any, waited?: any[]) => { const r0 = typeof r === 'string' && r.length === 32 ? r : 'ab'.repeat(16); const wait = recoveryWaitId(F.backup.kp.pub, F.epochId, r0);
    const ws = waited ?? [0, 1].map((k) => signWaited(F.g, F.servers[k].host, 'recovery', wait, 1_800_000_000, 1_800_000_000 + 3 * 86400));
    const ap: any = approveRecovery(F.g, l, F.backup.kp, { r }, ws); if (waited === null) delete ap.recovery.waited; return F.change(l[0], l, ap); };
  M('recovery (baseline)', [rec('ab'.repeat(16))]);
  M('recovery with release_request.r a number', [rec(5)]);
  M('recovery with release_request.r ""', [rec('')]);
  M('recovery without "waited"', [rec('ab'.repeat(16), null as any)]);
}
{ const l = [{ add: { key: C.pub, kind: 'device', lock: null, salt: 0 } }]; const ap = lockAp(l);
  const txt = JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: l[0], list: l, approval: ap }).replace('"v":1,', "'v':1,");
  M('change content with a single-quoted key', [F.sign(24302, txt, [['v', '1'], ['epoch', F.epochId]])]);
  M('change content with trailing text', [F.sign(24302, JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: l[0], list: l, approval: ap }) + ' x', [['v', '1'], ['epoch', F.epochId]])]);
}

// SLIP-39 (Backup §3): TS-made shares Kotlin must combine, and corruptions both must refuse alike.
{
  const { generate, combine, recoverBackup } = await import(`${K}/src/slip39.ts`);
  const hx = (b: Uint8Array) => Buffer.from(b).toString('hex');
  const S = (name: string, mnemonics: string[], passphrase = '') => P('slip39', name, { mnemonics, passphrase }, res(() => hx(combine(mnemonics, passphrase))));
  const secret = new Uint8Array(32).map((_, i) => i * 7 + 1);
  const p: string[] = generate(1, [[2, 3]], secret, '', 1, (n: number) => new Uint8Array(n).map((_, i) => (i * 31 + n) & 0xff))[0];
  const g2 = generate(2, [[2, 3], [1, 1], [3, 4]], secret.slice(0, 16), 'TREZOR', 0, (n: number) => new Uint8Array(n).map((_, i) => (i * 13 + 5) & 0xff));
  S('2 of 3, pieces 0 and 2', [p[0], p[2]]);
  S('2 of 3, pieces 2 and 1 (order)', [p[2], p[1]]);
  S('one piece alone', [p[0]]);
  S('the same piece twice', [p[0], p[0]]);
  S('all three pieces', p);
  const w = p[0].split(' ');
  S('one word swapped for another', [[...w.slice(0, 5), w[5] === 'academic' ? 'acid' : 'academic', ...w.slice(6)].join(' '), p[1]]);
  S('upper case words', [p[0].toUpperCase(), p[1]]);
  S('extra spaces and a newline', ['  ' + p[0].replace(/ /g, '  ') + '\n', p[1]]);
  S('an unknown word', [[...w.slice(0, 3), 'zzzz', ...w.slice(4)].join(' '), p[1]]);
  S('one word missing', [w.slice(0, -1).join(' '), p[1]]);
  S('two groups, 2 + 1 members', [g2[0][1], g2[0][0], g2[1][0]], 'TREZOR');
  S('two groups, wrong passphrase', [g2[0][1], g2[0][0], g2[1][0]], 'trezor');
  S('two groups, one group short a member', [g2[0][1], g2[1][0]], 'TREZOR');
  S('mixing two sets', [p[0], g2[0][0]]);
  // Review 7: one separator set (space, tab, LF, CR) on both sides.
  for (const [n, sep] of [['NBSP', '\u00a0'], ['U+2003', '\u2003'], ['U+3000', '\u3000'], ['U+2028', '\u2028'], ['U+FEFF', '\ufeff'], ['U+001C', '\u001c'], ['U+000B', '\u000b'], ['U+0085', '\u0085']])
    S(`words separated by ${n}`, [p[0].replace(' ', sep), p[1]]);
  S('a leading BOM', ['\ufeff' + p[0], p[1]]);
  S('a leading U+001C', ['\u001c' + p[0], p[1]]);
  S('tabs and CRLF', ['\t' + p[0].replace(/ /g, '\r\n'), p[1]]);
  // The Backup §3 profile, checked before any PBKDF2 runs.
  const B = (name: string, mnemonics: string[]) => P('slip39', name, { mnemonics, passphrase: '', backup: true }, res(() => hx(recoverBackup(mnemonics))));
  const det = (n: number) => new Uint8Array(n).map((_, i) => (i * 29 + 3) & 0xff);
  B('backup: two pieces', [p[1], p[2]]);
  const e6 = generate(1, [[2, 3]], secret, '', 6, det)[0];
  B('backup: pieces with e = 6', [e6[0], e6[1]]);
  B('backup: two groups', generate(1, [[2, 2], [2, 2]], secret, '', 1, det)[0]);
  const s16 = generate(1, [[2, 3]], secret.slice(0, 16), '', 1, det)[0];
  B('backup: a 16-byte value', [s16[0], s16[1]]);
  const t3 = generate(1, [[3, 3]], secret, '', 1, det)[0];
  B('backup: 3 of 3', t3);
}

console.log(JSON.stringify(out, null, 1));
