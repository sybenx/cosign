// Key families module §2: the settling procedure, rule by rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeEvent } from 'nostr-tools/pure';
import { settle, parseFamily, WINDOW, GRACE, KIND_ACCEPT, KIND_FAMILY } from '../src/families.ts';
import { destructive } from '../src/destructive.ts';
import { newKey } from '../src/event.ts';

const C = 'cc'.repeat(32), M1 = '11'.repeat(32), M2 = '22'.repeat(32);
const fam = (id: string, master: string, height: number) => ({ v: { id, master, child: C }, height });
const rel = (family: string, master: string, height: number) => ({ v: { family, master }, height });
const T = 1_000_000;

test('§1 a family carries both signatures; the accept must name this master', () => {
  const m = newKey(), c = newKey();
  const accept = finalizeEvent({ kind: KIND_ACCEPT, created_at: 1, tags: [['p', m.pub]], content: '' }, c.sk);
  const f = finalizeEvent({ kind: KIND_FAMILY, created_at: 1, tags: [['p', c.pub]], content: JSON.stringify(accept) }, m.sk) as any;
  assert.deepEqual(parseFamily(f), { id: f.id, master: m.pub, child: c.pub });
  const other = newKey();
  const wrong = finalizeEvent({ kind: KIND_FAMILY, created_at: 1, tags: [['p', c.pub]], content: JSON.stringify(accept) }, other.sk) as any;
  assert.equal(parseFamily(wrong), null);
  assert.equal(destructive({ kind: KIND_FAMILY, created_at: 0, tags: [], content: '' }), true, 'all four kinds are Held (§4)');
});

test('§2 settling: pending, settled after window + grace, same-master retries are one', () => {
  assert.equal(settle(C, [fam('a', M1, T)], [], T + 10).kind, 'pending');
  assert.deepEqual(settle(C, [fam('a', M1, T), fam('b', M1, T + 5)], [], T + WINDOW + GRACE), { kind: 'settled', family: 'a', master: M1 });
});

test('§2 a different master within the window: disputed for good', () => {
  const s = settle(C, [fam('a', M1, T), fam('b', M2, T + WINDOW)], [], T + 10 * WINDOW);
  assert.equal(s.kind, 'disputed');
  // Releasing never helps in a dispute.
  assert.equal(settle(C, [fam('a', M1, T), fam('b', M2, T + 100)], [rel('a', M1, T + 200)], T + 10 * WINDOW).kind, 'disputed');
});

test('§2 no claims on a settled child; a dead pair stays dead; changing master by release first', () => {
  // A thief's claim anchored after M1's family settled is dead.
  assert.deepEqual(settle(C, [fam('a', M1, T), fam('b', M2, T + WINDOW + 1)], [], T + 5 * WINDOW), { kind: 'settled', family: 'a', master: M1 });
  // M1 releases (anchored), then M2 claims after the release: M2's family decides.
  const s = settle(C, [fam('a', M1, T), fam('b', M2, T + 3 * WINDOW)], [rel('a', M1, T + 2 * WINDOW)], T + 6 * WINDOW);
  assert.deepEqual(s, { kind: 'settled', family: 'b', master: M2 });
  // An old accept replayed by M1 after its release is dead for good (dead pair).
  assert.deepEqual(settle(C, [fam('a', M1, T), fam('b', M2, T + 3 * WINDOW), fam('c', M1, T + 5 * WINDOW)], [rel('a', M1, T + 2 * WINDOW)], T + 9 * WINDOW),
    { kind: 'settled', family: 'b', master: M2 });
});
