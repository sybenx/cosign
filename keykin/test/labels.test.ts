// Device names (Account admin §2, device/labels.ts): a device names itself; every device reads the names, only a name
// signed by the device it names, flags two with the same name; relays see neither the member key nor the name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import { labelD, labelEvent, KIND_LABELS } from '../device/labels.ts';
import type { Change } from '../src/types.ts';

test('a device names itself; the others read it with its model; relays see no member key and no name', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  await acc.A.setLabel('Pixel 9a', 'Google Pixel 9a');
  await B.setLabel('Chrome on MacBook', 'Chrome 140');
  await acc.A.fetchLabels(); await B.fetchLabels();
  const byKey = (d: any) => new Map(d.members.devices().keys.map((k: any) => [k.key, k]));
  const seen = byKey(B).get(acc.A.kp.pub) as any;
  assert.equal(seen.name, 'Pixel 9a'); assert.equal(seen.model, 'Google Pixel 9a'); assert.equal(seen.same_name, false);
  assert.equal((byKey(acc.A).get(B.kp.pub) as any).name, 'Chrome on MacBook');
  const pub = acc.bus.published.filter((e) => e.kind === KIND_LABELS && e.tags.some((t) => t[0] === 'd' && t[1].startsWith('keykin-labels:')));
  assert.equal(pub.length, 2);
  for (const e of pub) {
    const raw = JSON.stringify(e);
    assert.ok(!raw.includes(acc.A.kp.pub) && !raw.includes(B.kp.pub), 'no member key on the relays');
    assert.ok(!raw.includes('Pixel') && !raw.includes('Chrome'), 'no name on the relays');
  }
});

test('a name not signed by the device it names is not shown; two devices with one name are both flagged', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  // B (or anyone holding the data key) writes a label at A's address, signed with B's own key: refused.
  const forged = labelEvent(acc.g, B.kp, B.baseDk, B.dataKeys.current(), { name: 'Pixel 9a', model: 'x', at: B.now }, B.now);
  forged.tags = forged.tags.map((t) => t[0] === 'd' ? ['d', labelD(B.baseDk, acc.A.kp.pub)] : t);
  await acc.bus.events.publishEvent(await B.sign(forged));
  await B.fetchLabels();
  assert.equal(B.members.devices().keys.find((k) => k.key === acc.A.kp.pub)!.name, null);
  // A stolen B names itself as A: both are flagged.
  await acc.A.setLabel('Pixel 9a', 'Google Pixel 9a');
  await B.setLabel('pixel 9A', 'Google Pixel 9a');
  await acc.A.fetchLabels();
  assert.ok(acc.A.members.devices().keys.every((k) => k.same_name));
});

test('last seen is this device\'s own observation; a redeal re-sends the name under the new data key', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  await acc.A.setLabel('Laptop', 'Mac');
  // B hears from A (a change pushed to it), and only then has a last seen for A.
  const before = B.members.devices().keys.find((k) => k.key === acc.A.kp.pub)!.last_seen;
  const list: Change[] = [{ redeal: { dealer: acc.A.kp.pub } }];
  await acc.A.submit(list, acc.A.approveLock(list));
  const after = B.members.devices().keys.find((k) => k.key === acc.A.kp.pub)!.last_seen;
  assert.ok(after !== null && after !== before);
  assert.equal(B.members.devices().keys.find((k) => k.key === B.kp.pub)!.last_seen, null, 'not for itself');
  // After the redeal, A's next catch-up re-sends its name under the new state's data key; a device that joins now reads it.
  await acc.A.fetch();
  const C = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  await C.fetchLabels();
  assert.equal(C.members.devices().keys.find((k) => k.key === acc.A.kp.pub)!.name, 'Laptop');
});

test('a name is 1–64 characters with no control characters', async () => {
  const acc = await create();
  for (const bad of ['', '   ', 'x'.repeat(65), 'a\nb']) await assert.rejects(acc.A.setLabel(bad, 'm'), (e: any) => e.code === 'malformed', JSON.stringify(bad));
});

test('a replayed older label never wins: the highest `at` does (draft 9 §2)', async () => {
  const acc = await create();
  const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
  const old = await acc.A.setLabel('Old name', 'Mac');
  acc.bus.advance(60);
  await acc.A.setLabel('New name', 'Mac');
  // B (a stolen device, say) re-publishes A's old event content as a newer account event at A's `d`.
  acc.bus.advance(60);
  const { id: _i, sig: _s, ...rest } = old as any;
  await acc.bus.events.publishEvent(await B.sign({ ...rest, created_at: acc.bus.now }));
  await B.fetchLabels();
  assert.equal(B.members.devices().keys.find((k) => k.key === acc.A.kp.pub)!.name, 'New name');
});
