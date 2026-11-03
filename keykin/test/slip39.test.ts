// SLIP-0039 against Trezor's official vectors (keykin/vectors/slip39), plus round trips and Backup §3.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { combine, recoverBackup, generate, backupPieces, decodeShare, encodeShare, rs1024Verify, rs1024Create, splitSecret, recoverSecret } from '../src/slip39.ts';
import { WORDS } from '../src/slip39-words.ts';
import { sha, bytesToHex, randomBytes } from '../src/bytes.ts';

const dir = new URL('../vectors/slip39/', import.meta.url);
const vectors: [string, string[], string, string][] = JSON.parse(readFileSync(new URL('vectors.json', dir), 'utf8'));

test('the wordlist is the mandated one', () => {
  assert.equal(WORDS.length, 1024);
  assert.equal(bytesToHex(sha(WORDS.join('\n') + '\n')), 'bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3');
});

for (const [name, mnemonics, secret] of vectors) {
  test(`vector ${name}`, () => {
    if (secret) assert.equal(bytesToHex(combine(mnemonics, 'TREZOR')), secret);
    else assert.throws(() => combine(mnemonics, 'TREZOR'));
  });
}

test('round trips: one level, two levels, 128 and 256 bits; every encoded share decodes back', () => {
  for (const len of [16, 32]) {
    const ms = randomBytes(len);
    const g = generate(2, [[2, 3], [3, 5], [1, 1]], ms, 'TREZOR', 0);
    assert.equal(bytesToHex(combine([g[0][0], g[0][2], g[2][0]], 'TREZOR')), bytesToHex(ms));
    assert.equal(bytesToHex(combine([g[1][4], g[1][0], g[1][2], g[0][1], g[0][0]], 'TREZOR')), bytesToHex(ms));
    assert.notEqual(bytesToHex(combine([g[0][0], g[0][2], g[2][0]], 'other')), bytesToHex(ms), 'a wrong passphrase gives another secret');
    for (const s of g.flat()) assert.equal(encodeShare(decodeShare(s)), s);
  }
});

test('RS1024: any change of one word is detected', () => {
  const data = Array.from({ length: 30 }, (_, k) => (k * 37) % 1024);
  const full = [...data, ...rs1024Create(true, data)];
  assert.ok(rs1024Verify(true, full));
  assert.ok(!rs1024Verify(false, full), 'the customization string matters');
  for (let k = 0; k < full.length; k++) { const bad = [...full]; bad[k] ^= 1 + (k % 1023); assert.ok(!rs1024Verify(true, bad), `word ${k}`); }
});

test('share counts: T = N = 16 works, 17 shares and a 1-of-N group are refused; too few shares fail the digest', () => {
  const s = randomBytes(16);
  const sh = splitSecret(16, 16, s);
  assert.equal(bytesToHex(recoverSecret(16, sh.map((v, i) => [i, v] as [number, Uint8Array]))), bytesToHex(s));
  assert.throws(() => splitSecret(2, 17, s));
  assert.throws(() => generate(1, [[1, 3]], s));
  const three = splitSecret(3, 5, s);
  assert.throws(() => recoverSecret(3, [[0, three[0]], [1, three[1]]]), /digest/);
});

test('Backup §3: three pieces, any two recover the backup secret; one alone does not', () => {
  const secret = randomBytes(32);
  const p = backupPieces(secret);
  assert.equal(p.length, 3);
  assert.equal(p[0].split(' ').length, 33);
  for (const pair of [[0, 1], [0, 2], [1, 2]]) assert.equal(bytesToHex(combine(pair.map((i) => p[i]))), bytesToHex(secret));
  assert.throws(() => combine([p[0]]));
  assert.ok(decodeShare(p[0]).ext && decodeShare(p[0]).e === 1, 'extendable, iteration exponent 1');
});

test('review 7: one separator set, positions not words in refusals, e range, the backup profile', () => {
  const secret = randomBytes(32);
  const p = backupPieces(secret);
  // Space, tab, line feed and carriage return separate words; nothing else does.
  assert.equal(bytesToHex(combine([' \t' + p[0].replaceAll(' ', '\r\n') + '\n', p[1]])), bytesToHex(secret));
  for (const sep of [' ', ' ', '　', ' ', '﻿', '\u001c'])
    assert.throws(() => combine([p[0].replace(' ', sep), p[1]]), /slip39/, `U+${sep.codePointAt(0)!.toString(16)}`);
  assert.throws(() => combine(['﻿' + p[0], p[1]]));
  // The refusal says where, never the piece's words.
  try { combine([p[0].replaceAll(' ', ' '), p[1]]); assert.fail('accepted'); } catch (e) { assert.match(String(e), /word 1 is not/); assert.ok(!String(e).includes(p[0].split(' ')[1])); }
  for (const e of [-1, 16, 20, 1.5]) assert.throws(() => generate(1, [[2, 3]], secret, '', e), /iteration exponent/);
  // Untrusted pieces must fit the Backup §3 profile before PBKDF2 runs.
  assert.equal(bytesToHex(recoverBackup([p[0], p[1]])), bytesToHex(secret));
  const e6 = generate(1, [[2, 3]], secret, '', 6)[0];
  assert.throws(() => recoverBackup([e6[0], e6[1]]), /not a Keykin backup piece/);
  assert.throws(() => recoverBackup(generate(1, [[2, 2], [2, 2]], secret)[0]), /not a Keykin backup piece/);
  const short = generate(1, [[2, 3]], randomBytes(16))[0];
  assert.throws(() => recoverBackup([short[0], short[1]]), /not a Keykin backup piece/);
});
