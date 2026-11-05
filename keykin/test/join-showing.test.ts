// Join by showing (device/join.ts `joinByShowing`), red team 23: whoever saw the hello QR can answer it, so a second
// answer stops the join, and no welcome counts before the 6 digits were shown.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Bus } from '../sim/bus.ts';
import { joinByShowing } from '../device/join.ts';
import { parseCode } from '../src/join.ts';
import { newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

function showing(bus: Bus, timeoutMs: number) {
  let code = ''; const digits: number[] = [];
  const p = joinByShowing(bus as any, [], { timeoutMs, onCode: (c) => { code = c; }, askDigits: async (k) => { digits.push(k); return '000000'; } });
  const res = p.then(() => 'joined', (e) => e.code ?? e.message);
  return { res, hello: () => parseCode(code) as any, digits };
}

test('a second answer to a shown code stops the join (contested)', async () => {
  const bus = new Bus();
  const j = showing(bus, 5000);
  await new Promise((r) => setTimeout(r, 10));
  const h = j.hello();
  const a = newKey(), b = newKey();
  bus.add({ kp: a, handle: () => null }); bus.add({ kp: b, handle: () => null });
  const first = await bus.send(a, h.n, { type: 'welcome_offer', s: h.s, g: bytesToHex(randomBytes(32)), m: a.pub });
  assert.equal(first?.type, 'join_hello', 'the first answer gets the hello');
  await bus.send(b, h.n, { type: 'welcome_offer', s: h.s, g: bytesToHex(randomBytes(32)), m: b.pub }).catch(() => null);
  assert.equal(await j.res, 'contested');
});

test('a welcome before the join nonce is never taken', async () => {
  const bus = new Bus();
  const j = showing(bus, 1500);
  await new Promise((r) => setTimeout(r, 10));
  const h = j.hello();
  const a = newKey(); bus.add({ kp: a, handle: () => null });
  await bus.send(a, h.n, { type: 'welcome_offer', s: h.s, g: bytesToHex(randomBytes(32)), m: a.pub });
  // No join_nonce: a welcome straight away (its content doesn't matter; it must not be looked at as final).
  await bus.send(a, h.n, { type: 'welcome', record: {}, changes: [], state: [] }).catch(() => null);
  assert.equal(await j.res, 'timeout');
  assert.deepEqual(j.digits, [], 'the person was never asked for digits');
});

test('core 14.24: the person types the scanning side\'s digits here; a match is confirmed to it, and a late offer is ignored', async () => {
  const { joinCheck } = await import('../src/codes.ts');
  const bus = new Bus();
  const a = newKey(), g = bytesToHex(randomBytes(32)), t = bytesToHex(randomBytes(16));
  const confirms: any[] = [];
  bus.add({ kp: a, handle: (from: string, body: any) => { if (body?.type === 'join_confirm') { confirms.push({ from, ...body }); return { type: 'ack' }; } return null; } });
  let code = ''; let right = '';
  const tries: number[] = [];
  const p = joinByShowing(bus as any, [], { timeoutMs: 2500, onCode: (c) => { code = c; }, askDigits: async (k) => { tries.push(k); return k === 1 ? 'nope' : right; } })
    .then(() => 'joined', (e) => e.code);
  await new Promise((r) => setTimeout(r, 10));
  const h = parseCode(code) as any;
  assert.equal((await bus.send(a, h.n, { type: 'welcome_offer', s: h.s, g, m: a.pub }))?.type, 'join_hello');
  right = joinCheck(g, a.pub, h.n, h.s, t);
  await bus.send(a, h.n, { type: 'join_nonce', t });
  for (let i = 0; i < 20 && !confirms.length; i++) await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(tries, [1, 2]);
  assert.deepEqual(confirms.map((c) => [c.from, c.s, c.t]), [[h.n, h.s, t]], 'join_confirm sealed by n, with s and t');
  const b = newKey(); bus.add({ kp: b, handle: () => null });
  await bus.send(b, h.n, { type: 'welcome_offer', s: h.s, g: bytesToHex(randomBytes(32)), m: b.pub }).catch(() => null);
  assert.equal(await p, 'timeout', 'a late offer after the confirm doesn\'t abort (no welcome came)');
});

test('core 14.24: three wrong entries stop the join; nothing is confirmed', async () => {
  const bus = new Bus();
  const a = newKey(); const confirms: any[] = [];
  bus.add({ kp: a, handle: (_f: string, body: any) => { if (body?.type === 'join_confirm') confirms.push(body); return null; } });
  let code = '';
  const p = joinByShowing(bus as any, [], { timeoutMs: 3000, onCode: (c) => { code = c; }, askDigits: async () => '123456' }).then(() => 'joined', (e) => e.code);
  await new Promise((r) => setTimeout(r, 10));
  const h = parseCode(code) as any;
  await bus.send(a, h.n, { type: 'welcome_offer', s: h.s, g: bytesToHex(randomBytes(32)), m: a.pub });
  await bus.send(a, h.n, { type: 'join_nonce', t: bytesToHex(randomBytes(16)) });
  assert.equal(await p, 'check_mismatch');
  assert.equal(confirms.length, 0);
});
