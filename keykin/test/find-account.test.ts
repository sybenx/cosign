// device/recover.ts `findAccount` (core 14.23, red team 23b): `seated?` at the hosts, hints believed only when two
// distinct seated servers agree; route 3 per signer, so a stranger's signpost can't hide the account's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Bus } from '../sim/bus.ts';
import { createByDkg } from '../sim/account.ts';
import { Host } from '../server/host.ts';
import { FileStore, KeyRing } from '../runtime/store.ts';
import { newKey } from '../src/event.ts';
import { finalizeEvent } from 'nostr-tools/pure';
import { signpostD } from '../src/codes.ts';
import { signpostContent } from '../src/upkeep.ts';
import { KIND_SIGNPOST } from '../src/types.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { findAccount, findAccounts } from '../device/recover.ts';

async function setup() {
  const bus = new Bus();
  const hosts = [0, 1, 2].map((k) => {
    const d = mkdtempSync(join(tmpdir(), 'kk-find-'));
    return new Host({ net: bus, hosting: bus, store: new FileStore(join(d, 'data'), new KeyRing(join(d, 'keys'))), profile: { https: `https://h${k}.test`, relays: ['ws://127.0.0.1:1'], operator: newKey().pub, name: `H${k}` } }).start();
  });
  const acc = await createByDkg({ net: bus as any, hosts });
  return { bus, hosts, acc };
}

test('route 1: a listed host finds the account, its servers from the agreed change set', async () => {
  const { bus, hosts, acc } = await setup();
  const f = await findAccount(bus as any, acc.paper, [hosts[0].key.pub]);
  assert.equal(f.g, acc.g);
  assert.equal(f.epochId, acc.epochId);
  assert.deepEqual(f.servers.map((s) => s.key).sort(), acc.A.servers().map((s) => s.key).sort());
});

test('route 3: a stranger\'s signposts (a huge n, a junk n) don\'t hide the account\'s own', async () => {
  const { bus, acc } = await setup();
  for (const n of ['999999', 'x']) {
    const fake = newKey();
    const content = signpostContent(acc.paper.pub, bytesToHex(randomBytes(32)), [{ host: newKey().pub }]);
    await bus.events.publishEvent(finalizeEvent({ kind: KIND_SIGNPOST, created_at: bus.now, tags: [['d', signpostD(acc.paper.pub)], ['n', n], ['h', '00'.repeat(32)]], content }, fake.sk));
  }
  const r = await findAccounts(bus as any, acc.paper, []);
  assert.deepEqual(r.found.map((x) => x.g), [acc.g]);
  assert.equal(r.unreachable, true, 'the strangers\' servers didn\'t answer: said, not hidden');
  assert.equal((await findAccount(bus as any, acc.paper, [])).g, acc.g);
});

test('a hint naming one server twice is not two servers', async () => {
  const { bus, acc } = await setup();
  // A host that lies: the account and epoch are real, but it lists only one seat, twice.
  const evil = newKey();
  const one = acc.A.servers()[0].key;
  const nip44 = await import('nostr-tools/nip44');
  const { seatedDigest } = await import('../src/codes.ts');
  const { schnorrSign } = await import('../src/event.ts');
  const { hexToBytes } = await import('../src/bytes.ts');
  bus.add({ kp: evil, handle: async (_f: string, b: any) => {
    if (b?.type === 'challenge') return { type: 'challenge', challenge: bytesToHex(randomBytes(16)) };
    if (b?.type !== 'seated?') return null;
    const ct = nip44.v2.encrypt(JSON.stringify([{ g: acc.g, epoch: acc.epochId, servers: [{ key: one }, { key: one }] }]), nip44.v2.utils.getConversationKey(evil.sk, acc.paper.pub));
    return { type: 'seated', ct, host: evil.pub, sig: schnorrSign(seatedDigest(b.h, hexToBytes(b.challenge), new TextEncoder().encode(ct)), evil.sk) };
  } });
  // Signposts out of the way: only route 1, through the lying host.
  bus.published.length = 0;
  assert.deepEqual((await findAccounts(bus as any, acc.paper, [evil.pub])).found, []);
});
