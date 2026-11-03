// Backup module: §2 (QR, 24 words), §3 (holder inbox, piece ack), §4.1 (the heir's envelope).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { backupQR, readBackupQR, accountCard, backupWords, readBackupWords, holderInboxKey, makeHeir, openHeir, checkHeirPiece, heirWaitId } from '../src/backup.ts';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { newKey, pubOf } from '../src/event.ts';
import { sha, bytesToHex, randomBytes } from '../src/bytes.ts';
import { mod } from '../src/curve.ts';

const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };
const card = () => ({ g: pubOf(sha('g')), epoch: '11'.repeat(16), servers: [{ host: newKey().pub, https: 'https://s1.test', relays: ['wss://r.test'] }], holderInbox: newKey().pub });

test('§2 the QR: kkbak1 bech32, upper case, round trip; the card has no secret', () => {
  const k = newKey(), c = card();
  const qr = backupQR(k.sk, c);
  assert.ok(qr.startsWith('KKBAK1') && qr === qr.toUpperCase());
  const r = readBackupQR(qr);
  assert.equal(bytesToHex(r.sk!), bytesToHex(k.sk)); assert.deepEqual(r.card, c);
  const cc = readBackupQR(accountCard(c));
  assert.equal(cc.sk, null); assert.deepEqual(cc.card, c);
  assert.equal(code(() => backupQR(new Uint8Array(32), c)), 'bad_backup', 'zero is not a secret');
});

test('§2 the 24 words: Keykin checksum, not BIP-39; a wallet seed is recognised', () => {
  const k = newKey();
  const w = backupWords(k.sk);
  assert.equal(w.length, 24);
  assert.equal(bytesToHex(readBackupWords(w)), bytesToHex(k.sk));
  const bad = [...w]; bad[3] = bad[3] === 'abandon' ? 'ability' : 'abandon';
  assert.match(String(code(() => readBackupWords(bad))), /bad_backup|wallet_seed/);
  // A real BIP-39 seed fails Keykin's checksum 255 times in 256 and is named as a wallet seed.
  let named = 0;
  for (let k2 = 0; k2 < 8; k2++) if (code(() => readBackupWords(generateMnemonic(wordlist, 256).split(' '))) === 'wallet_seed') named++;
  assert.ok(named >= 6);
});

test('§4.1 the heir envelope: pieces at the seats check against C0 and C1; any two open it with the heir key', () => {
  const heir = newKey(), secret = newKey().sk, setId = newKey().pub, g = pubOf(sha('g'));
  const h = makeHeir({ g, setId, heirKey: heir.pub, secret, card: 'kkbakcard1…', seats: [4, 7, 8] });
  for (const [x, p] of h.pieces) assert.ok(checkHeirPiece(h.record, x, p));
  assert.ok(!checkHeirPiece(h.record, 4, mod(h.pieces.get(4)! + 1n)));
  const opened = openHeir(h.record, g, heir.sk, [[7, h.pieces.get(7)!], [8, h.pieces.get(8)!]]);
  assert.equal(opened.secret, bytesToHex(secret));
  assert.throws(() => openHeir(h.record, g, newKey().sk, [[4, h.pieces.get(4)!], [8, h.pieces.get(8)!]]), 'only the heir');
  assert.equal(code(() => openHeir(h.record, g, heir.sk, [[4, h.pieces.get(4)!]])), 'bad_heir', 'one server alone opens nothing');
  assert.equal(code(() => makeHeir({ g, setId, heirKey: heir.pub, secret, card: '', seats: [4, 7, 8], waitDays: 7 })), 'bad_heir');
  assert.equal(heirWaitId(heir.pub, setId, '22'.repeat(16)).length, 64);
  assert.equal(holderInboxKey(bytesToHex(randomBytes(32))).length, 32);
});
