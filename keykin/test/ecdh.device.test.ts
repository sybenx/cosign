// Core §5.5 on the device: the account's own NIP-44 and NIP-04, by ECDH with a co-signer. A peer with
// an ordinary key (nostr-tools) reads what the account wrote, and the account reads what it wrote back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { create } from '../sim/account.ts';
import { newKey } from '../src/event.ts';

test('the account encrypts and decrypts with NIP-44 and NIP-04 without ever holding its key whole', async () => {
  const acc = await create();
  const peer = newKey();
  const ck = nip44.v2.utils.getConversationKey(peer.sk, acc.g);
  assert.equal(nip44.v2.decrypt(await acc.A.nip44(peer.pub, 'hello from the account', true), ck), 'hello from the account');
  assert.equal(await acc.A.nip44(peer.pub, nip44.v2.encrypt('hello back', ck), false), 'hello back');
  assert.equal(await nip04.decrypt(peer.sk, acc.g, await acc.A.nip04(peer.pub, 'nip04 hi', true)), 'nip04 hi');
  assert.equal(await acc.A.nip04(peer.pub, await nip04.encrypt(peer.sk, acc.g, 'nip04 back'), false), 'nip04 back');
});
