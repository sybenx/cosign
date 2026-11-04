// Member-key signing for other protocols, and the account's devices with onMemberRemoved.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { create, invite } from '../sim/account.ts';
import { memberSign, memberVerify, memberDigest, registerDomain, domainFault } from '../device/index.ts';
import { detachedDigest } from '../src/codes.ts';
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.ts';
import { schnorr } from '@noble/curves/secp256k1.js';
import type { Change } from '../src/types.ts';

const V = JSON.parse(readFileSync(new URL('../vectors/membersig.json', import.meta.url), 'utf8'));

test('the vectors: digests reproduce, signatures verify, refused domains are refused', () => {
  for (const v of V.valid) {
    assert.equal(bytesToHex(memberDigest(v.domain, hexToBytes(v.message))), v.digest);
    assert.ok(memberVerify(v.sig, v.domain, hexToBytes(v.message), V.member_key));
    assert.equal(bytesToHex(schnorr.sign(hexToBytes(v.digest), hexToBytes(V.member_sk), new Uint8Array(32))), v.sig, 'BIP-340 with zero aux is fixed');
  }
  for (const r of V.refused_domains) { assert.ok(domainFault(r.domain), r.domain); assert.throws(() => registerDomain(r.domain), /bad_domain/); }
});

test('a device signs under a registered domain with its member key; anything else fails to verify', async () => {
  const acc = await create();
  const root = randomBytes(32);
  const { sig, key } = acc.A.signAsMember('nostr-vault/ksig/1', root);
  assert.equal(key, acc.A.kp.pub);
  assert.ok(memberVerify(sig, 'nostr-vault/ksig/1', root, key));
  assert.ok(!memberVerify(sig, 'nostr-vault/ksig/1', randomBytes(32), key), 'another message');
  assert.ok(!memberVerify(sig, 'nostr-vault/ksig/1', root, acc.g), 'the account key is not the member key');
  assert.throws(() => acc.A.signAsMember('nostr-vault/other/1', root), /not registered/);
  registerDomain('nostr-vault/other/1');
  assert.ok(memberVerify(acc.A.signAsMember('nostr-vault/other/1', root).sig, 'nostr-vault/other/1', root, key));
  assert.ok(!memberVerify(sig, 'nostr-vault/other/1', root, key), 'a signature for one domain is not one for another');
});

test('no domain reaches a core message: keykin and cosign are refused, and the 0x00 ends the domain', () => {
  // A core detached digest is SHA-256("keykin-pair/1" ‖ g ‖ JCS); the domain that would rebuild it is refused.
  assert.throws(() => memberDigest('keykin-pair/1', hexToBytes('ab'.repeat(32))), /bad_domain/);
  assert.throws(() => memberSign(randomBytes(32), 'keykin-pair/1', new Uint8Array(0)), /bad_domain/);
  // An event id's preimage begins with "[": no domain can.
  assert.ok(domainFault('[0,"ab"]/1'));
  // Two registered domains where one is the other plus bytes still give different digests.
  registerDomain('nostr-vault/ksig/12');
  assert.notEqual(bytesToHex(memberDigest('nostr-vault/ksig/1', new TextEncoder().encode('2xyz'))), bytesToHex(memberDigest('nostr-vault/ksig/12', new TextEncoder().encode('xyz'))));
  void detachedDigest;
});

test('memberKeys is the current devices; onMemberRemoved fires after the redeal, with its state hash', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.deepEqual(acc.A.memberKeys(), [acc.A.kp.pub, B.kp.pub, C.kp.pub].sort());
  const seenA: any[] = [], seenB: any[] = [];
  acc.A.onMemberRemoved((x) => seenA.push(x));
  B.onMemberRemoved((x) => seenB.push(x));
  const lost: Change[] = [{ remove: C.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(lost, acc.A.approveLock(lost));
  await B.fetch();
  const state = acc.A.dataKeys.current().state;
  assert.deepEqual(seenA, [{ removed: [C.kp.pub], state }], 'once, on the dealer, with the new state');
  assert.deepEqual(seenB, [{ removed: [C.kp.pub], state }], 'and on another device');
  assert.deepEqual(acc.A.memberKeys(), [acc.A.kp.pub, B.kp.pub].sort());
});
