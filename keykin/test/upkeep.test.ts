// Upkeep pieces outside the flows: redeal apply refusals, uploads, the material pin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.ts';
import { deal, applyRedeal, sealItem, itemHash } from '../src/redeal.ts';
import { acceptUpload, baseItem, openMaterial, materialInner } from '../src/upkeep.ts';
import { computeMembership } from '../src/membership.ts';
import { approveLock } from '../src/approval.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { mod } from '../src/curve.ts';
import type { Change } from '../src/types.ts';

const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

test('a redeal delta that misses its commitment is refused; a good one applies and rebuilds C_S', () => {
  const F = fixture(); const A = F.devices[0];
  const d = deal(F.g, A.kp, [], new Map([[A.kp.pub, [1, 2, 3]]]), F.backup.kp.pub, [5, 6]);
  const s0 = { ids: new Set<string>(), C: F.commitment, shares: A.shares };
  const mine = d.deltas.get(A.kp.pub)!;
  const bad = new Map(mine); bad.set(1, mod(mine.get(1)! + 1n));
  assert.equal(code(() => applyRedeal(F.g, s0, d.redeal, bad, true, [5, 6])), 'bad_delta');
  const r = applyRedeal(F.g, s0, d.redeal, mine, true, [5, 6]);
  assert.equal(r.state.ids.size, 1);
  assert.deepEqual(r.paperValues, d.paperValues.values, 'a device works out δ(b1), δ(b2) from its own three');
  assert.equal(code(() => applyRedeal(F.g, r.state, d.redeal, mine, true, [5, 6])), 'cannot_apply', 'never twice');
  assert.equal(code(() => applyRedeal(F.g, s0, d.redeal, mine, true, [5, 6], new Set([d.redeal.id]))), 'cannot_apply', 'never an abandoned one');
});

test('an upload without a valid approval is refused', () => {
  const F = fixture(); const A = F.devices[0];
  const m = computeMembership(F.rec, []);
  const list: Change[] = [{ remove: A.kp.pub }, { redeal: { dealer: A.kp.pub } }];
  const now = Math.floor(Date.now() / 1000);
  assert.equal(code(() => acceptUpload(m, A.kp.pub, { list, approval: {}, items: [] }, now)), 'bad_approval');
  const ap = approveLock(F.g, F.epochId, list, now + 3600, A.kp.pub, A.lock!);
  assert.equal(code(() => acceptUpload(m, A.kp.pub, { list, approval: ap, items: [] }, now)), 'ok');
  assert.equal(code(() => acceptUpload(m, A.kp.pub, { list, approval: ap, items: [] }, now + 7200)), 'approval_expired');
  // Review 1 #6: only the list's dealer uploads, once.
  assert.equal(code(() => acceptUpload(m, F.servers[0].kp.pub, { list, approval: ap, items: [] }, now)), 'not_dealer');
  const held = acceptUpload(m, A.kp.pub, { list, approval: ap, items: [], redeal: 'ab'.repeat(16) }, now);
  assert.equal(code(() => acceptUpload(m, A.kp.pub, { list, approval: ap, items: [], redeal: 'ab'.repeat(16) }, now, held)), 'upload_held');
});

test('backup material: the base must match its pin and the sum must land on P_b', () => {
  const F = fixture();
  const seed = bytesToHex(randomBytes(32));
  const base = baseItem(F.backup.kp, seed, F.backup.shares, bytesToHex(randomBytes(32)), []);
  const args = { g: F.g, backup: F.backup.kp, pin: materialInner(base, []), base, baseSeed: seed, items: [], seeds: new Map(), C0: F.commitment, redeals: [], state: new Set<string>() };
  assert.equal(code(() => openMaterial(args)), 'ok');
  assert.equal(code(() => openMaterial({ ...args, pin: '00'.repeat(32) })), 'bad_material');
  const wrong = baseItem(F.backup.kp, seed, new Map([[5, 1n], [6, 2n]]), '00'.repeat(32), []);
  assert.equal(code(() => openMaterial({ ...args, base: wrong, pin: itemHash(wrong) })), 'bad_material');
  void sealItem;
});
