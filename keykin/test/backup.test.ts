// Backup module: §2 (QR, 24 words), §3 (holder inbox, piece ack), §4.1 (the heir's envelope).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { backupQR, readBackupQR, accountCard, backupWords, readBackupWords, holderInboxKey, makeHeir, openHeir, checkHeirPiece, heirWaitId } from '../src/backup.ts';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { newKey, pubOf, verifyEvent } from '../src/event.ts';
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
  // Long relay lists fit: TLV lengths are 2 bytes (Backup §2, spec item 38).
  const long = { ...c, servers: [{ host: newKey().pub, https: 'https://s1.test', relays: Array.from({ length: 12 }, (_, k) => `wss://relay-${k}.example.org`) }] };
  assert.deepEqual(readBackupQR(backupQR(k.sk, long)).card, long);
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

test('§4.3 the heir: pinned by F7, waits 180 days, any device stops it without a lock, then two servers release', async () => {
  const { create } = await import('../sim/account.ts');
  const { msg } = await import('../sim/nodes.ts');
  const acc = await create();
  const heir = newKey();
  const K = await acc.A.newPaper((l) => acc.A.approveLock(l), { heir: heir.pub });
  for (const s of acc.servers) assert.ok(s.co!.heirs.has(K.pub), 'every server took its piece');
  const ask = async (s: any) => {
    const ch = await acc.bus.send(heir, s.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
    return acc.bus.send(heir, s.kp.pub, msg('heir_request', acc.g, acc.epochId, 'member', { set: K.pub, request: bytesToHex(randomBytes(16)), challenge: ch.challenge }));
  };
  const n = await ask(acc.servers[0]);
  assert.equal(n.kind, 'heir');
  // The owner opens the app: a lockless cancel ends it (only heir waits may be cancelled without a lock).
  assert.equal((await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, msg('cancel', acc.g, acc.epochId, 'member', { wait: n.wait }))).kind, 'cancelled');
  assert.equal((await ask(acc.servers[0])).code, 'heir_cooldown', '30 days before a new request');
  // A real absence: new request after the cooldown at two servers; 180 days later, two pieces open the envelope.
  acc.bus.advance(31 * 86400);
  for (const s of acc.servers.slice(0, 2)) assert.equal((await ask(s)).kind, 'heir');
  assert.equal((await acc.bus.send(heir, acc.servers[1].kp.pub, msg('heir_get', acc.g, acc.epochId, 'ask', { set: K.pub }))).code, 'heir_wait_not_passed');
  acc.bus.advance(181 * 86400);
  const pieces: [number, bigint][] = [];
  let record: any;
  for (const s of acc.servers.slice(0, 2)) {
    const a = await acc.bus.send(heir, s.kp.pub, msg('heir_get', acc.g, acc.epochId, 'ask', { set: K.pub }));
    assert.equal(a.type, 'heir_piece', JSON.stringify(a));
    pieces.push([a.x, BigInt('0x' + a.piece)]); record = a.record;
  }
  assert.equal(openHeir(record, acc.g, heir.sk, pieces).secret, bytesToHex(K.sk), 'the heir has the backup key: next, the paper recovery with its 3-day wait');
});

test('§3 recovery contacts: F7 hands out 2-of-3 SLIP-39 pieces; two friends recover the backup key; then the paper recovery', async () => {
  const { create, recover } = await import('../sim/account.ts');
  const { FriendNode } = await import('../sim/nodes.ts');
  const { recoverBackup } = await import('../src/slip39.ts');
  const { unwrap } = await import('../src/transport.ts');
  const acc = await create();
  const friends = [0, 1, 2].map(() => acc.bus.add(new FriendNode(acc.bus)) as InstanceType<typeof FriendNode>);
  const K = await acc.A.newPaper((l) => acc.A.approveLock(l), { holders: friends });
  const pc = acc.A.m!.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === K.pub)!;
  assert.equal((pc.c.change as any).paper.holders.length, 3, 'the holder keys are pinned in the paper change');
  assert.ok(friends.every((f) => f.pieces.has(K.pub)));
  // The phone is lost. The new device shows a fresh key; Ana and Carl, in person, seal their pieces to it.
  acc.bus.kill(acc.A.kp.pub);
  const fresh = newKey();
  const got: string[] = [];
  for (const f of [friends[0], friends[2]]) got.push(unwrap(fresh.sk, await f.giveTo(fresh, K.pub)).body.piece);
  const sk = recoverBackup(got);
  assert.equal(bytesToHex(sk), bytesToHex(K.sk), 'two pieces give the backup key');
  // One friend alone gets nothing.
  assert.throws(() => recoverBackup([got[0]]));
  const { D } = await recover(acc, [acc.A], { sk, pub: K.pub });
  assert.ok(verifyEvent(await D.sign({ content: 'recovered through two friends' })));
});

test('core 14.24: the heir key asks seated? itself, and the answer names hosts but no member keys', async () => {
  const { create } = await import('../sim/account.ts');
  const { msg } = await import('../sim/nodes.ts');
  const { seatedAskDigest } = await import('../src/codes.ts');
  const { schnorrSign } = await import('../src/event.ts');
  const nip44 = await import('nostr-tools/nip44');
  const acc = await create();
  const heir = newKey();
  await acc.A.newPaper((l) => acc.A.approveLock(l), { heir: heir.pub });
  const s = acc.servers[0];
  const h = bytesToHex(sha(Uint8Array.from(Buffer.from(heir.pub, 'hex'))));
  const ch = await acc.bus.send(heir, s.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask'));
  const r = await acc.bus.send(heir, s.kp.pub, { type: 'seated?', h, challenge: ch.challenge, sig: schnorrSign(seatedAskDigest(h, ch.challenge), heir.sk) });
  assert.equal(r.type, 'seated', JSON.stringify(r));
  const [entry] = JSON.parse(nip44.v2.decrypt(r.ct, nip44.v2.utils.getConversationKey(heir.sk, r.host)));
  assert.equal(entry.g, acc.g);
  assert.ok(entry.servers.length >= 2 && entry.servers.every((x: any) => x.host && !('key' in x)), 'hosts, no member keys');
});
