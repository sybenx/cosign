// Account admin module: creation by DKG (§1.1), import's `refused: exists` (§1.2), deleting (§3).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createByDkg, create, invite } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';
import { msg } from '../sim/nodes.ts';

test('§1.1 creation by DKG: three servers, provisional until confirmed, then everyday use', async () => {
  const acc = await createByDkg();
  assert.ok(acc.servers.every((s) => !s.provisional && s.co!.state.shares.size === 1));
  assert.equal(acc.A.rec!.origin, 'dkg');
  assert.ok(verifyEvent(await acc.A.sign({ content: 'born by DKG' })));
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  assert.ok(verifyEvent(await B.sign({ content: 'and growing' })));
  // The DKG's throwaway keys and secret packages are gone.
  assert.ok(acc.servers.every((s) => s.dkg === null));
});

test('§1.1 a provisional account unconfirmed for an hour is dropped, keeping no record', async () => {
  const { ServerNode } = await import('../sim/nodes.ts');
  void ServerNode;
  const acc = await createByDkg();
  // Simulate a server that never got the confirmation: put it back to provisional and wait.
  const s = acc.servers[0];
  s.provisional = true; s.welcomedAt = acc.bus.now;
  acc.bus.advance(3601);
  assert.equal((await acc.bus.send(acc.A.kp, s.kp.pub, msg('state_get', acc.g, acc.epochId, 'ask'))).code, 'unknown_account');
});

test('§1.2: a second epoch record for a g a server already serves is refused: exists', async () => {
  const acc = await create();
  const w = { recEv: acc.A.recEv, changes: [], state: [], seeds: [], items: [], base: acc.A.base };
  assert.equal((await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, { type: 'seat_welcome', w })).code, 'exists');
});

test('§3 Destroy my key: lock-approved, every server keeps only a tombstone and answers deleted for ever', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  // A request without an approval is refused: there is no hold path.
  const bare = msg('account_delete', acc.g, acc.epochId, 'member', {});
  assert.equal((await acc.bus.send(B.kp, acc.servers[0].kp.pub, bare)).code, 'needs_approval');
  const n = await acc.A.deleteAccount();
  assert.equal(n, 3);
  assert.ok(acc.A.wiped);
  for (const s of acc.servers) { assert.ok(s.tombstone); assert.equal(s.co!.state.shares.size, 0); assert.equal(s.seeds.size, 0); }
  const later = await acc.bus.send(B.kp, acc.servers[1].kp.pub, msg('state_get', acc.g, acc.epochId, 'ask'));
  assert.equal(later.type, 'deleted');
  await assert.rejects(B.sign({ content: 'after the end' }));
});

test('§3 a peer\'s deleted, host-signed by a current seat holder, reaches a server that missed the request', async () => {
  const acc = await create();
  acc.bus.kill(acc.servers[2].kp.pub);
  await acc.A.deleteAccount();
  assert.ok(!acc.servers[2].tombstone);
  acc.bus.revive(acc.servers[2].kp.pub);
  const ans = await acc.bus.send(acc.servers[0].kp, acc.servers[2].kp.pub, { ...(acc.servers[0].deletedAnswer()) });
  assert.equal(ans.type, 'deleted');
  assert.ok(acc.servers[2].tombstone && acc.servers[2].co!.state.shares.size === 0);
});
