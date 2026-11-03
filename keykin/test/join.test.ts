// Behaviour case 4 (joining, §4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.ts';
import { Inviter, Joiner, parseCode, sOnWire } from '../src/join.ts';
import { approveLock } from '../src/approval.ts';
import { repairAll } from '../src/repair.ts';
import { newKey } from '../src/event.ts';
import { stateHash, pickSalt } from '../src/codes.ts';
import { computeMembership, takenIndices } from '../src/membership.ts';
import { mul, derivePoint } from '../src/curve.ts';
import type { Change } from '../src/types.ts';

const now = 1_800_000_000;
const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

function join(direction: 'invite' | 'hello') {
  const F = fixture();
  const A = F.devices[0], nk = newKey();
  let inv: Inviter, jn: Joiner;
  if (direction === 'invite') {
    inv = new Inviter({ g: F.g, m: A.kp.pub, now });
    const scanned = parseCode(inv.invite(['wss://r1.test']));
    assert.equal(scanned.kind, 'join');
    jn = new Joiner({ n: nk.pub, now, scanned: scanned as any });
    const h = jn.hello();
    const nonce = inv.onHello(nk.pub, h.msg, now);
    jn.onNonce(A.kp.pub, nonce.msg);
  } else {
    jn = new Joiner({ n: nk.pub, now });
    const scanned = parseCode(jn.helloCode(['wss://r1.test']).replace('keykin:', 'cosign:'));
    inv = new Inviter({ g: F.g, m: A.kp.pub, now, scanned: scanned as any });
    const off = inv.offer();
    assert.equal(off.to, nk.pub);
    const h = jn.onOffer(A.kp.pub, off.msg, now);
    const nonce = inv.onHello(nk.pub, h.msg, now);
    jn.onNonce(A.kp.pub, nonce.msg);
  }
  assert.ok(inv.typed(jn.check), 'the typed check matches');
  // The add, approved by A's lock, group-signed; the repair by A (3) and S1 (1).
  const m0 = computeMembership(F.rec, []);
  const { salt, indices } = pickSalt(F.g, F.epochId, nk.pub, takenIndices(m0));
  const ch: Change = { add: { key: nk.pub, kind: 'device', lock: null, salt } };
  const addEv = F.change(ch, [ch], approveLock(F.g, F.epochId, [ch], now + 3600, A.kp.pub, A.lock!));
  const sigmas = indices.flatMap((i) => {
    const s = repairAll(F.commitment, [{ key: A.kp.pub, shares: A.shares }, { key: F.servers[0].kp.pub, shares: new Map([[4, F.servers[0].share]]) }], i);
    return [...s].map(([from, sigma]) => ({ from, index: i, sigma, state: stateHash([]) }));
  });
  return { F, A, nk, inv, jn, addEv, sigmas, indices };
}

for (const dir of ['invite', 'hello'] as const) {
  test(`case 4: the honest flow, ${dir} direction`, () => {
    const { F, A, jn, addEv, sigmas, indices } = join(dir);
    const r = jn.finish({ from: A.kp.pub, welcome: { record: F.recEv, changes: [addEv], state: [] }, sigmas });
    assert.deepEqual([...r.shares.keys()], indices);
    for (const [i, s] of r.shares) assert.ok(mul(s).equals(derivePoint(F.commitment, BigInt(i))));
  });
}

test('case 4: a racer\'s hello loses on the typed check', () => {
  const F = fixture();
  const A = F.devices[0], honest = newKey(), racer = newKey();
  const inv = new Inviter({ g: F.g, m: A.kp.pub, now });
  const sc = parseCode(inv.invite([])) as any;
  const r = new Joiner({ n: racer.pub, now, scanned: sc }), h = new Joiner({ n: honest.pub, now, scanned: sc });
  inv.onHello(racer.pub, r.hello().msg, now);                     // the racer got there first
  assert.equal(code(() => inv.onHello(honest.pub, h.hello().msg, now)), 'already_accepted');
  // The honest device never gets a nonce, so the person sees no number on it, or a different one:
  r.onNonce(A.kp.pub, { t: inv.accepted!.t });
  const honestScreen = new Joiner({ n: honest.pub, now, scanned: sc }); honestScreen.hello(); honestScreen.onNonce(A.kp.pub, { t: '11'.repeat(16) });
  assert.equal(inv.typed(honestScreen.check), false);
});

test('case 4: drops and refusals', () => {
  const { F, A, nk, jn, addEv, sigmas } = join('invite');
  // A join-code hello not sealed by n.
  const j2 = new Joiner({ n: nk.pub, now });
  const inv2 = new Inviter({ g: F.g, m: A.kp.pub, now, scanned: parseCode(j2.helloCode([])) as any });
  const other = newKey();
  assert.equal(code(() => inv2.onHello(other.pub, { n: other.pub, s: j2.s }, now)), 'not_sealed_by_n');
  assert.equal(code(() => inv2.onHello(nk.pub, { n: nk.pub, s: '00'.repeat(16) }, now)), 'bad_secret');
  assert.equal(code(() => inv2.onHello(nk.pub, { n: nk.pub, s: j2.s }, now + 601)), 'expired');
  // A nonce from a stranger.
  const j3 = new Joiner({ n: nk.pub, now, scanned: parseCode(new Inviter({ g: F.g, m: A.kp.pub, now }).invite([])) as any }); j3.hello();
  assert.equal(code(() => j3.onNonce(other.pub, { t: '22'.repeat(16) })), 'wrong_sender');
  // A welcome from a stranger, for another group, without the inviter's sigma, with a bad sum.
  const welcome = { record: F.recEv, changes: [addEv], state: [] };
  assert.equal(code(() => jn.finish({ from: other.pub, welcome, sigmas })), 'not_sealed_by_m');
  const G = fixture();
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome: { ...welcome, record: G.recEv }, sigmas })), 'wrong_group');
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome, sigmas: sigmas.filter((s) => s.from !== A.kp.pub) })), 'sigma_missing');
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome, sigmas: sigmas.filter((s) => s.from === A.kp.pub) })), 'sigma_missing');
  const bad = sigmas.map((s, k) => (k === 0 ? { ...s, sigma: sigmas[1].sigma } : s));
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome, sigmas: bad })), 'repair_failed', 'a summed share that misses the commitment');
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome: { ...welcome, changes: [] }, sigmas })), 'no_add');
  void sOnWire;
});
