// Upkeep on a device (core §6.7.1–§6.7.3), for every port: a device's snapshot, then two lists it
// receives (a plain redeal, then a remove with its redeal), each as the change events and the sealed
// delivery that reached it, and what the device holds after each: its state, shares, data key and
// members log. Also a delivery from a stranger, which a device ignores, and the dealer's key (test material
// only), so a port can seal deliveries the dealer got wrong.
// Run: node vectors/gen-upkeep.ts > vectors/upkeep.json
import { create, invite } from '../sim/account.ts';
import { wrap, unwrap } from '../src/transport.ts';
import { newKey } from '../src/event.ts';
import { scalarHex } from '../src/curve.ts';
import { stateOf } from '../src/redeal.ts';
import { bytesToHex } from '../src/bytes.ts';
import type { Change } from '../src/types.ts';
import type { DeviceNode } from '../device/node.ts';

const acc = await create();
const A = acc.A;
const B = await invite(acc, A, (l) => A.approveLock(l));
const C = await invite(acc, A, (l) => A.approveLock(l));
await B.fetch();
const before = B.snapshot();
const delivered: any[] = [];
const take = B.takeDelivery.bind(B);
B.takeDelivery = (w) => { delivered.push(w); take(w); };

function after(d: DeviceNode) {
  const k = d.dataKeys.current();
  return { ids: [...d.state!.ids].sort(), state: stateOf(d.state!), shares: [...d.state!.shares].sort((a, b) => a[0] - b[0]).map(([i, s]) => [i, scalarHex(s)]),
    data_key: bytesToHex(k.key), data_key_state: k.state, devices: d.members.devices(), removed: d.members.removed(0) };
}
async function step(list: Change[]) {
  const seen = new Set(B.changes.map((e) => e.id));
  delivered.length = 0;
  await A.submit(list, A.approveLock(list));
  return { list, changes: B.changes.filter((e) => !seen.has(e.id)), deliveries: [...delivered], after: after(B) };
}
const s1 = await step([{ redeal: { dealer: A.kp.pub } }]);
const s2 = await step([{ remove: C.kp.pub }, { redeal: { dealer: A.kp.pub } }]);

// The same delta, sealed by a stranger: never applied, never kept (§6.7.3: only the dealer's delta counts).
const real = unwrap(B.kp.sk, s1.deliveries[0]).body;
const stranger = wrap(newKey().sk, B.kp.pub, real);

console.log(JSON.stringify({
  note: 'Apply each step in order: add its changes, open each delivery with the device key, apply every redeal a delivery from its dealer covers. `after` is what the TS reference holds then.',
  device: B.kp.pub, dealer_sk: bytesToHex(A.kp.sk), before, steps: [s1, s2], stranger_delivery: stranger,
}, null, 1));
