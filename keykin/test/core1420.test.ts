// Core 14.20 (review 13 M4 and its red team): a paper item checked from its own ephemeral secret, never a
// key the dealer sends; re-issued items checked through `reissue_eph` before anyone destroys a value; blame
// only on proof.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite, recover } from '../sim/account.ts';
import { wrap, unwrap } from '../src/transport.ts';
import { sealItem, itemHash, redealDigest, type Dealt } from '../src/redeal.ts';
import { schnorrSign, newKey, verifyEvent, type NostrEvent } from '../src/event.ts';
import { scalarHex } from '../src/curve.ts';
import { msg } from '../src/msg.ts';
import type { Change } from '../src/types.ts';
import type { DeviceNode } from '../device/node.ts';

const R = (dealer: DeviceNode): Change[] => [{ redeal: { dealer: dealer.kp.pub } }];
async function three() {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l), { lock: true });
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  await B.fetch(); await C.fetch();
  return { acc, A: acc.A, B, C };
}
/** Rewrite the dealer's sealed delivery to `to` (the test holds every device's key). */
function rewrite(items: { to: string; wrap: NostrEvent }[], to: DeviceNode, dealer: DeviceNode, f: (body: any) => void) {
  const it = items.find((x) => x.to === to.kp.pub)!;
  const body = unwrap(to.kp.sk, it.wrap).body; f(body);
  it.wrap = wrap(dealer.kp.sk, to.kp.pub, body);
}
const notices = (d: DeviceNode) => d.notices.filter((n) => n.kind === 'bad_backup_piece');
const reissues = (acc: any, by: DeviceNode, id: string) => acc.servers[0].items.filter((x: any) => x.kind === 'reissue' && x.redeal === id && x.by === by.kp.pub);

test('an honest redeal: every device opens the paper item from its eph and destroys its values; nothing is re-issued', async () => {
  const { acc, A, B, C } = await three();
  await A.submit(R(A), A.approveLock(R(A)));
  for (const d of [A, B, C]) { await d.fetch(); assert.equal(d.kept.size, 0, d.name); assert.equal(notices(d).length, 0); }
  assert.equal(acc.servers[0].items.filter((x: any) => x.kind === 'reissue').length, 0);
});

test('a dealer\'s bound item with wrong contents: proof against it; values kept, re-issued, checked by the others; recovery works', async () => {
  const { acc, A, B, C } = await three();
  const tamper = (dl: Dealt, items: any[]) => {
    const bad = sealItem('paper', dl.redeal.id, dl.redeal.paper_to, dl.releaseSeed, { redeal: dl.redeal.id, d: dl.paperValues.values.map((x) => scalarHex(x + 1n)), b: dl.paperValues.b, dk_seed: dl.dkSeed });
    dl.paperItem = bad.item; dl.paperEph = bad.eph;
    dl.redeal.paper_item = itemHash(bad.item); dl.redeal.sig = schnorrSign(redealDigest(acc.g, dl.redeal), A.kp.sk);
    for (const x of [B, C]) rewrite(items, x, A, (b) => { b.paper_item = bad.item; b.paper_eph = { redeal: dl.redeal.id, item: itemHash(bad.item), eph: bad.eph }; });
  };
  const id = JSON.parse((await A.submit(R(A), A.approveLock(R(A)), { tamper }))[0].content).change.redeal.id;
  assert.deepEqual(notices(B).map((n) => [n.member, n.redeal]), [[A.kp.pub, id]], 'a dismissable line naming the dealer');
  assert.ok(B.kept.has(id), 'the values kept');
  await B.fetch();                                           // B re-issues
  assert.equal(reissues(acc, B, id).length, 1);
  assert.equal(B.kept.size, 0, 'confirmed by two servers');
  await C.fetch(); await A.fetch();
  assert.equal(C.kept.size, 0, 'C opened B\'s item and destroyed its values');
  assert.equal(reissues(acc, C, id).length, 0, 'and re-issued none of its own');
  // The paper holder skips the dealer's bad item and sums the re-issued one.
  acc.bus.kill(A.kp.pub); acc.bus.kill(B.kp.pub); acc.bus.kill(C.kp.pub);
  const { D } = await recover(acc, [A, B, C]);
  assert.ok(verifyEvent(await D.sign({ content: 'recovered past a bad paper item' })));
});

test('a missing, unbound or replayed paper_eph proves nothing: no line, the device re-issues', async () => {
  const { acc, A, B, C } = await three();
  let old: any;
  await A.submit(R(A), A.approveLock(R(A)), { tamper: (_dl, items) => rewrite(items, B, A, (b) => { old = b.paper_eph; }) });
  const id2 = JSON.parse((await A.submit(R(A), A.approveLock(R(A)), { tamper: (_dl, items) => {
    rewrite(items, B, A, (b) => { b.paper_eph = old; });     // a replayed eph from the earlier redeal
    rewrite(items, C, A, (b) => { delete b.paper_eph; });    // and none at all
  } }))[0].content).change.redeal.id;
  for (const d of [B, C]) assert.equal(notices(d).length, 0, `${d.name}: no blame without proof`);
  assert.ok(B.kept.has(id2) && C.kept.has(id2));
  await B.fetch();
  assert.equal(reissues(acc, B, id2).length, 1, 'B re-issued');
  await C.fetch();
  assert.equal(C.kept.size, 0, 'C checked B\'s item instead of re-issuing');
  assert.equal(reissues(acc, C, id2).length, 0);
});

test('an equivocating re-issuer: its eph doesn\'t open its item; proof, a line naming it, an own re-issue, its later eph ignored', async () => {
  const { acc, A, B, C } = await three();
  const id = JSON.parse((await A.submit(R(A), A.approveLock(R(A)), { tamper: (_dl, items) => { for (const x of [B, C]) rewrite(items, x, A, (b) => { delete b.paper_eph; }); } }))[0].content).change.redeal.id;
  const r = A.m!.redeals.get(id)!.r, K = A.m!.backupKey!, v = C.kept.get(id)!;
  // B seals its re-issue under one eph and names another in the item.
  const { reissueItem } = await import('../src/redeal.ts');
  const { item } = reissueItem(acc.g, r, K, v.release, B.kept.get(id)!, B.kp);
  const e2 = newKey();
  const forged = { ...item, eph: e2.pub, sig: '' };
  const { sig: _s, ...unsigned } = forged;
  forged.sig = schnorrSign((await import('../src/codes.ts')).detachedDigest('paper-reissue', acc.g, unsigned), B.kp.sk);
  for (const s of acc.servers) await acc.bus.send(B.kp, s.kp.pub, msg('paper_reissue', acc.g, acc.epochId, 'member', { item: forged }));
  C.takeDelivery(wrap(B.kp.sk, C.kp.pub, { type: 'reissue_eph', redeal: id, K, item: itemHash(forged), eph: e2.sk && Buffer.from(e2.sk).toString('hex') }));
  await C.fetch();
  assert.deepEqual(notices(C).map((n) => n.member), [B.kp.pub], 'the line names the re-issuer, on proof');
  assert.equal(reissues(acc, C, id).length, 1, 'C re-issued its own');
  // A later reissue_eph from B for that redeal and K is ignored.
  assert.equal(C.takeDelivery(wrap(B.kp.sk, C.kp.pub, { type: 'reissue_eph', redeal: id, K, item: itemHash(forged), eph: '11'.repeat(32) })), 'junk');
});

test('fewer than two servers hold a re-issued item: others wait, keep their values, and after 7 days re-issue their own', async () => {
  const { acc, A, B, C } = await three();
  const id = JSON.parse((await A.submit(R(A), A.approveLock(R(A)), { tamper: (_dl, items) => { for (const x of [B, C]) rewrite(items, x, A, (b) => { delete b.paper_eph; }); } }))[0].content).change.redeal.id;
  acc.bus.kill(acc.servers[1].kp.pub); acc.bus.kill(acc.servers[2].kp.pub);
  await B.fetch();                                           // one live server holds B's item
  await C.fetch();
  assert.ok(C.kept.has(id), 'C keeps its values');
  assert.equal(notices(C).length, 0);
  acc.bus.revive(acc.servers[1].kp.pub); acc.bus.revive(acc.servers[2].kp.pub);
  acc.bus.advance(7 * 86400 + 1);
  await C.fetch(); await C.fetch();
  assert.equal(reissues(acc, C, id).length, 1, 'C re-issued its own');
});

test('a device re-issues at most once per redeal and K; servers keep the first item', async () => {
  const { acc, A, B, C } = await three();
  const id = JSON.parse((await A.submit(R(A), A.approveLock(R(A)), { tamper: (_dl, items) => rewrite(items, B, A, (b) => { delete b.paper_eph; }) }))[0].content).change.redeal.id;
  B.kept.set(id, B.kept.get(id)!);
  await B.reissueMissing();
  const first = itemHash(reissues(acc, B, id)[0]);
  B.paperVerified.delete(`${A.m!.backupKey}:${id}`); B.kept.set(id, { b: [5, 6], d: [1n, 2n], dk: '00'.repeat(32), release: B.seeds.get(id)! } as any);
  await B.reissueMissing();
  assert.equal(reissues(acc, B, id).length, 1);
  assert.equal(itemHash(reissues(acc, B, id)[0]), first);
  void C;
});

test('the co-signer wants a paper_eph and a dk_seed for every post-list device', async () => {
  const { A } = await three();
  await assert.rejects(A.submit(R(A), A.approveLock(R(A)), { tamper: (_dl, items) => { for (const it of items) delete it.paper_eph; } }), /missing/);
});
