// Review 22: the vault-app device calls' fixes (TS; Kotlin's in VaultTest.kt and the Kotlin e2e).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nip44 from 'nostr-tools/nip44';
import { create } from '../sim/account.ts';
import { DeviceNode } from '../device/node.ts';
import { vaultPayload } from '../device/doors.ts';
import { VAULT_OPENS_PER_HOUR } from '../device/vaultcalls.ts';
import { newKey } from '../src/event.ts';

const APP = 'org.example.notes@' + 'ab'.repeat(16);
const reject = (p: Promise<unknown>, code: string) => assert.rejects(p, (e: any) => e.code === code);

test('L1: an event or rumor with vault fields added is no vault payload', () => {
  assert.ok(vaultPayload(JSON.stringify({ vault: 'v', keys: {} })));
  assert.ok(!vaultPayload(JSON.stringify({ kind: 4812, content: '{}', vault: 'v', keys: {} })));
  assert.ok(!vaultPayload(JSON.stringify({ kind: 13, content: 'x', sig: 'y', vault: 'v', secret: 'z' })));
});

test('M2: decrypts and unwraps are capped per app and hour', async () => {
  const { A } = await create();
  A.vault.allow(APP);
  const peer = newKey();
  const ct = nip44.v2.encrypt('a private message', nip44.v2.utils.getConversationKey(peer.sk, A.g));
  for (let k = 0; k < VAULT_OPENS_PER_HOUR; k++) await reject(A.vault.decrypt(APP, peer.pub, ct), 'declined');
  await reject(A.vault.decrypt(APP, peer.pub, ct), 'try-later');
  A.bus.now += 3601;
  await reject(A.vault.decrypt(APP, peer.pub, ct), 'declined');
});

test('L2, L7: the grant and "Don\'t allow" survive a restart in Kotlin\'s shape; revoking lets the app ask again', async () => {
  const { A } = await create();
  A.vault.allow(APP); A.vault.decline('org.other@' + 'cd'.repeat(16));
  assert.deepEqual(A.vault.dump(), { apps: [APP], declined: ['org.other@' + 'cd'.repeat(16)] });
  const saved: Record<string, string> = {}; A.attach({ save: (k, t) => { saved[k] = t; } });
  const B = DeviceNode.restore(A.bus, Object.values(saved)[0]);
  assert.ok(!B.vault.mayAsk('org.other@' + 'cd'.repeat(16)), 'declined, remembered');
  B.vault.revoke('org.other@' + 'cd'.repeat(16));
  assert.ok(B.vault.mayAsk('org.other@' + 'cd'.repeat(16)));
  B.vault.load([APP]); assert.deepEqual(B.vault.allowed(), [APP], 'the earlier array form still loads');
});

test('L7: kind 5 addresses and ids are read strictly; an invitation\'s rumor has every field', async () => {
  const { A } = await create();
  A.vault.allow(APP);
  for (const a of [`30811:${A.g}`, ` 30811:${A.g}:d`, `30811:${A.g.toUpperCase()}:d`, `030811:${A.g}:d`])
    await reject(A.vault.sign(APP, { kind: 5, tags: [['a', a]], content: '' }), 'declined');
  await reject(A.vault.sign(APP, { kind: 5, tags: [['e', 'AB'.repeat(32)]], content: '' }), 'declined');
  await reject(A.vault.invite(APP, { pubkey: A.g, created_at: A.now, kind: 4812, content: '{}' } as any, newKey().pub), 'malformed');
});
