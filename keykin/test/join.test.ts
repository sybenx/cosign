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

test('#17: an attacker welcome naming its own helpers and sigma fails; nothing is stored', () => {
  const { F, A, jn, addEv, sigmas, indices } = join('invite');
  const x = newKey();
  const forged = indices.map((i) => ({ from: x.pub, index: i, sigma: sigmas[0].sigma, state: sigmas[0].state }));
  const welcome = { record: F.recEv, changes: [addEv], state: [], helpers: [x.pub], need: 1 } as any;
  // Sealed by the attacker: refused before anything else.
  assert.equal(code(() => jn.finish({ from: x.pub, welcome, sigmas: forged })), 'not_sealed_by_m');
  // Even claiming to be the inviter: `helpers`/`need` are never read, the inviter's and a server's
  // sigmas are required, and the sum must lie on the group's polynomial.
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome, sigmas: forged })), 'sigma_missing');
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome, sigmas: [...forged.map((f) => ({ ...f, from: A.kp.pub })), ...sigmas.filter((s) => s.from !== A.kp.pub)] })), 'repair_failed');
  // A welcome for a different group key than the scanned invite is refused outright.
  const G = fixture();
  assert.equal(code(() => jn.finish({ from: A.kp.pub, welcome: { ...welcome, record: G.recEv }, sigmas })), 'wrong_group');
  assert.equal(jn.finish({ from: A.kp.pub, welcome, sigmas }).shares.size, 3, 'the honest parts still work');
});

test('join-code direction: an attacker answering the shown code wins nothing', () => {
  // The new device shows its hello code; the attacker scans it first and offers its own account.
  const F = fixture(), evil = fixture();
  const nk = newKey(), E = evil.devices[0];
  const jn = new Joiner({ n: nk.pub, now });
  const sc = parseCode(jn.helloCode([])) as any;
  const attacker = new Inviter({ g: evil.g, m: E.kp.pub, now, scanned: sc });
  const honest = new Inviter({ g: F.g, m: F.devices[0].kp.pub, now, scanned: sc });
  const h = jn.onOffer(E.kp.pub, attacker.offer().msg, now);
  attacker.onHello(nk.pub, h.msg, now);
  jn.onNonce(E.kp.pub, attacker.accepted ? { t: attacker.accepted.t } : {});
  // The honest offer is dropped; the honest inviter never gets a hello, so its typed check can't match.
  assert.equal(code(() => jn.onOffer(F.devices[0].kp.pub, honest.offer().msg, now)), 'already_accepted');
  assert.equal(honest.typed(jn.check), false);
  // The device is bound to the attacker's group key, which it shows as the account it joined (§1.1
  // item 2), so a welcome for the person's real account is refused outright.
  assert.equal(jn.g, evil.g);
  assert.equal(code(() => jn.finish({ from: E.kp.pub, welcome: { record: F.recEv, changes: [], state: [] }, sigmas: [] })), 'wrong_group');
  // A second key of the attacker cannot answer the nonce either: only the key the hello went to.
  assert.equal(code(() => jn.onNonce(newKey().pub, { t: '33'.repeat(16) })), 'wrong_sender');
});
