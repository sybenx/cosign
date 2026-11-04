import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import { scopeForDecrypt } from '../device/grants.ts';
import { monthOf } from '../device/metadata.ts';

async function three() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  for (const d of [B]) await d.fetch();
  return { acc, A: acc.A, B };
}
const isMeta = (e: any) => e.tags.some((t: string[]) => t[0] === 'd' && t[1].startsWith('keykin-meta:'));

test.skip('P1 too_large after N local encrypts; sticks', async () => {
  const { A } = await three();
  let n = 0, err: any = null;
  for (; n < 9000; n++) { await A.nip44(A.g, `x${n}`, true, { owner: 'a'.repeat(64) + ':' + 'b'.repeat(32) }); if (n % 500 === 0 && n > 4000) { try { await A.meta.publish(); } catch (e) { err = e; break; } } }
  console.log('P1 threw at', n, err?.code);
  // a new record later still fails
  await assert.rejects(() => A.meta.publish());
});

test('P2 part 0 newer than part 1 (between publishes): month dropped, not kept', async () => {
  const { acc, A, B } = await three();
  const list = JSON.stringify([['p', 'ab'.repeat(32)]]);
  const ct = await A.nip44(A.g, list, true); await A.sign({ kind: 10000, content: ct, tags: [] });
  for (let k = 0; k < 300; k++) await A.nip44(A.g, `n${k}`, true, { owner: 'c'.repeat(64) + ':' + 'd'.repeat(32) });
  const first = await A.meta.publish();
  console.log('P2 parts', first.filter(isMeta).length);
  await B.meta.fetch();
  const judge = () => scopeForDecrypt(B.g, B.g, list, { payload: ct, evidence: B.evidence });
  console.log('P2 before', judge());
  // A adds one record at the very start (sorted), all parts change; a reader sees new part0 + index? simulate: only new part 0 has arrived
  for (let k = 0; k < 50; k++) await A.nip44(A.g, `m${k}`, true, { owner: '0'.repeat(64) + ':' + '0'.repeat(32) });
  acc.bus.advance(700);
  const second = await A.meta.publish();
  const p0 = second.find(isMeta)!;   // first published is part 0
  const idx = second.filter((e) => e.tags.some((t: string[]) => t[1].startsWith('keykin-meta-index:')));
  // relay state: new part 0 and new index arrived; new part 1.. not yet (or withheld)
  const keep = acc.bus.published.filter((e) => !second.includes(e) || e === p0);
  acc.bus.published.splice(0, acc.bus.published.length, ...keep);
  await B.meta.fetch();
  console.log('P2 after (index + part0 new, later parts old)', judge(), 'others months', B.meta.others.get(A.kp.pub)?.size);
  // without the index too:
  acc.bus.published.splice(0, acc.bus.published.length, ...keep.filter((e) => !idx.includes(e)));
});

test('P3 a failed publish leaves later parts never sent', async () => {
  const { acc, A, B } = await three();
  for (let k = 0; k < 300; k++) await A.nip44(A.g, `n${k}`, true, { owner: 'c'.repeat(64) + ':' + 'd'.repeat(32) });
  const realPub = A.meta.h.publish; let fail = true;
  (A.meta.h as any).publish = async (e: any) => { if (fail) throw new Error('offline'); return realPub(e); };
  await A.meta.publish().catch((e) => console.log('P3 first publish', e.message));
  fail = false;
  // one more record whose hash sorts last: only the last part changes
  let ct = ''; for (let i = 0; ; i++) { ct = await A.nip44(A.g, `z${i}`, true, { owner: 'f'.repeat(64) + ':' + 'f'.repeat(32) }); break; }
  acc.bus.advance(700);
  const out = await A.meta.publish();
  console.log('P3 second publish sent', out.length, 'events');
  await B.meta.fetch();
  console.log('P3 B has months of A:', B.meta.others.get(A.kp.pub)?.size, 'owners', B.evidence.owners.size);
});

test('P4 months kept', () => {
  for (const d of ['2026-03-31', '2026-05-31', '2026-07-31', '2026-10-31', '2026-12-31']) {
    const now = Date.parse(d + 'T12:00:00Z') / 1000;
    const keep = new Set(Array.from({ length: 13 }, (_, k) => monthOf(now - k * 30 * 86400)));
    console.log('P4', d, [...keep].join(' '));
  }
});
