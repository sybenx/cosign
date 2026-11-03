// Regression tests for independent review 5 (keykin-impl-review-5.md).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, createByDkg, replaceServer } from '../sim/account.ts';
import { msg, ServerNode } from '../sim/nodes.ts';
import { newKey, verifyEvent, schnorrSign } from '../src/event.ts';
import { sha, hexToBytes, jcsBytes, bytesToHex, randomBytes } from '../src/bytes.ts';
import { what } from '../src/codes.ts';

test('B1: a peer\'s deleted is accepted only with a request whose approval checks here', async () => {
  const acc = await create();
  const [S1, S2] = acc.servers;
  // S1 forges a request with no valid approval and host-signs a `deleted` for it.
  const forged = { ...msg('account_delete', acc.g, acc.epochId, 'member', {}), approval: { lock: { member: acc.A.kp.pub, assertion: { authData: '', clientData: '', sig: '' } } } };
  const host_sig = schnorrSign(sha('keykin-deleted/1', hexToBytes(acc.g), jcsBytes(forged)), S1.host.sk);
  const a = await acc.bus.send(S1.kp, S2.kp.pub, { type: 'deleted', request: forged, changes: [], host: S1.host.pub, host_sig });
  assert.notEqual(a.type, 'deleted');
  assert.ok(!S2.tombstone && S2.co!.state.shares.size === 1, 'S2 kept its share');
  assert.ok(verifyEvent(await acc.A.sign({ content: 'still alive' })));
});

test('B2/B3: enroll and DKG messages never re-key or wipe a live seat', async () => {
  const acc = await create();
  const stranger = newKey();
  assert.equal((await acc.bus.send(stranger, acc.servers[0].kp.pub, { type: 'enroll', g: acc.g })).code, 'already_seated');
  assert.equal((await acc.bus.send(stranger, acc.servers[0].kp.pub, { type: 'create' })).code, 'already_seated');
  assert.equal((await acc.bus.send(stranger, acc.servers[1].kp.pub, { type: 'dkg_1', index: 4, max: 8 })).code, 'no_dkg');
  assert.ok(verifyEvent(await acc.A.sign({ content: 'unharmed' })));
});

test('B6: a provisional account is replaced only by a newer record for the same key', async () => {
  const acc = await createByDkg();
  const s = acc.servers[0];
  s.provisional = true;
  const other = await create();
  const w = { recEv: other.A.recEv, changes: [], state: [], seeds: [], items: [], base: other.A.base };
  // Even a record that seats this very server key is refused while another g is provisional here.
  const a = await s.handle(other.A.kp.pub, { type: 'seat_welcome', w }, acc.bus.now);
  assert.match(a.code, /not_seated|provisional_other/);
  assert.equal(s.rec!.g, acc.g);
});

test('B5/B7: a helper stop survives a server replacement; the helper keeps up with redeals', async () => {
  const acc = await create();
  const { addHelper } = await import('../sim/account.ts');
  const H = await addHelper(acc, acc.A, (l) => acc.A.approveLock(l));
  const stop = bytesToHex(randomBytes(16));
  await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, msg('helper_stop', acc.g, acc.epochId, 'member', { stop, by: acc.A.kp.pub }));
  assert.ok(acc.servers.every((x) => x.co!.stops.has(stop)), 'the stop reached every peer');
  acc.bus.kill(acc.servers[2].kp.pub);
  const Y = await replaceServer(acc, acc.A, 8, (l) => acc.A.approveLock(l));
  assert.ok(Y.co!.stops.has(stop), 'and the new seat holder');
  await H.fetch();
  assert.deepEqual([...H.state!.ids], [...acc.A.state!.ids], 'the helper applied the redeal');
  await assert.rejects(H.sign({ content: 'still stopped' }), /helper_stopped/);
  void ServerNode; void what;
});
