// Behaviour cases 1 (signing round), 6 (waits), 7 (removed members), 8 (session limits) and
// 9 (destructive rule and lifetimes through a server).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, type Fixture } from './helpers.ts';
import { CoSigner } from '../src/cosigner.ts';
import { OneCall, TwoCall, ecdhRequest, ecdhFinish } from '../src/coordinator.ts';
import { approveLock, approvePair } from '../src/approval.ts';
import { what, stateHash, detachedDigest, holdWaitId } from '../src/codes.ts';
import { newKey, schnorrSign, verifyEvent, wireEvent } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { mul, liftX, xOnly } from '../src/curve.ts';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { Change } from '../src/types.ts';

let clock = 1_800_000_000;
const now = () => clock;
const S0 = stateHash([]);

function server(F: Fixture, k = 0, changes: any[] = []) {
  const s = F.servers[k];
  return new CoSigner({ me: s.kp, host: s.host, kind: 'server', now, record: F.rec, changes,
    state: { ids: new Set(), C: F.commitment, shares: new Map([[s.idx, s.share]]) } });
}
const ctx = (F: Fixture) => ({ g: F.g, epochId: F.epochId, state: S0, C: F.commitment });
const dev = (F: Fixture) => ({ indices: [1, 2, 3], shares: F.devices[0].shares });
const note = (F: Fixture, extra: any = {}) => wireEvent({ pubkey: F.g, created_at: clock, kind: 1, tags: [], content: 'hello', ...extra });
const ask = (S: CoSigner, F: Fixture, from: string, req: any, sentAt = clock) => S.handle(from, req, sentAt);

test('case 1: one-call round, device (3) + server (1); BIP-340 under g', () => {
  const F = fixture(); const S = server(F);
  for (let k = 0; k < 6; k++) {
    const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F, { content: `n${k}` }));
    const ev = r.finish(ask(S, F, F.devices[0].kp.pub, r.request));
    assert.ok(verifyEvent(ev));
  }
});

test('case 1: byte-identical retry gets the cached answer; same id different body is id_reused', () => {
  const F = fixture(); const S = server(F);
  const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F));
  const a1 = ask(S, F, F.devices[0].kp.pub, r.request);
  const a2 = ask(S, F, F.devices[0].kp.pub, structuredClone(r.request));
  assert.deepEqual(a1, a2);
  const changed = { ...r.request, event: note(F, { content: 'other' }) };
  assert.equal(ask(S, F, F.devices[0].kp.pub, changed).code, 'id_reused');
  assert.ok(verifyEvent(r.finish(a1)));
});

test('case 1: signers not exactly the participants; commitments missing an index or carrying junk', () => {
  const F = fixture(); const S = server(F);
  const from = F.devices[0].kp.pub;
  const base = () => new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F)).request;
  assert.equal(ask(S, F, from, { ...base(), signers: [1, 2, 4] }).code, 'bad_signers');
  assert.equal(ask(S, F, from, { ...base(), signers: [1, 2, 3, 4, 7] }).code, 'bad_signers', 'a third participant in a one-call round');
  const r = base();
  assert.equal(ask(S, F, from, { ...r, commitments: r.commitments.slice(1) }).code, 'bad_commitments');
  const r2 = base();
  assert.equal(ask(S, F, from, { ...r2, commitments: [{ ...r2.commitments[0], D: '02' + '00'.repeat(32) }, ...r2.commitments.slice(1)] }).code, 'malformed', 'not a point (identity has no encoding)');
  assert.equal(ask(S, F, newKey().pub, base()).code, 'not_member');
  assert.equal(ask(S, F, F.servers[1].kp.pub, base()).code, 'bad_signers', 'a server does not coordinate');
});

test('case 1: a bad partial is named by member', () => {
  const F = fixture(); const S = server(F);
  const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F));
  const p = ask(S, F, F.devices[0].kp.pub, r.request);
  p.z[0].z = bytesToHex(randomBytes(31)) + '01';
  assert.throws(() => r.finish(p), new RegExp(`bad_partial: member ${F.servers[0].kp.pub}`));
});

test('case 1: state mismatch answers stale with ids', () => {
  const F = fixture(); const S = server(F);
  const r = new OneCall({ ...ctx(F), state: stateHash([bytesToHex(randomBytes(16))]) }, dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F));
  const a = ask(S, F, F.devices[0].kp.pub, r.request);
  assert.equal(a.type, 'stale'); assert.deepEqual(a.ids, []);
});

test('case 9: lifetimes through a server', () => {
  const F = fixture(); const S = server(F);
  const from = F.devices[0].kp.pub;
  const req = () => new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F)).request;
  assert.equal(ask(S, F, from, req(), clock - 91).code, 'expired');
  assert.equal(ask(S, F, from, req(), clock - 89).type, 'partial');
  assert.equal(ask(S, F, from, req(), clock + 31).code, 'dated_ahead');
  assert.equal(ask(S, F, from, { ...req(), cls: 'member' }).code, 'bad_class');
  assert.equal(ask(S, F, from, { ...req(), cls: 'ask' }, clock - 149).type, 'partial');
  assert.equal(ask(S, F, from, { ...req(), type: 'frobnicate' }).code, 'unsupported');
});

test('case 9: future-dated replaceables and deletions are refused, notes may be scheduled', () => {
  const F = fixture(); const S = server(F);
  const sign = (ev: any) => ask(S, F, F.devices[0].kp.pub, new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, ev).request);
  assert.equal(sign(note(F, { created_at: clock + 86400 })).type, 'partial');
  assert.equal(sign(note(F, { kind: 0, created_at: clock + 601, content: '{"name":"x"}' })).code, 'dated_ahead');
  assert.equal(sign(note(F, { kind: 5, created_at: clock + 601, tags: [['e', '00'.repeat(32)]] })).code, 'dated_ahead');
  assert.equal(sign(note(F, { kind: 3, created_at: clock + 599, tags: [['p', '11'.repeat(32)]] })).type, 'partial');
});

test('case 9 + 5: destructive events need a lock approval or a passed hold; one approval works at any co-signer', () => {
  const F = fixture(); const S = server(F, 0), S2 = server(F, 1);
  const A = F.devices[0];
  const wipe = note(F, { kind: 3, tags: [], content: '' });
  const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, wipe);
  assert.equal(ask(S, F, A.kp.pub, r.request).code, 'needs_approval');
  const approval = { lock: { member: A.kp.pub, assertion: A.lock!.assert(F.g, what.sign(r.eventId)) } };
  const r1 = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, wipe, { approval });
  assert.ok(verifyEvent(r1.finish(ask(S, F, A.kp.pub, r1.request))));
  const r2 = new OneCall(ctx(F), dev(F), { key: F.servers[1].kp.pub, indices: [7] }, wipe, { approval });
  assert.ok(verifyEvent(r2.finish(ask(S2, F, A.kp.pub, r2.request))), 'reused at a second co-signer');
  // A burst of single deletions trips the counter.
  const del = (n: number) => note(F, { kind: 5, tags: Array.from({ length: n }, () => ['e', bytesToHex(randomBytes(32))]) });
  const sd = (ev: any) => ask(S, F, A.kp.pub, new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, ev).request);
  assert.equal(sd(del(2)).type, 'partial');
  assert.equal(sd(del(3)).type, 'partial');
  assert.equal(sd(del(1)).code, 'needs_approval', '6 targets in 10 minutes');
  clock += 601;
  assert.equal(sd(del(1)).type, 'partial');
  assert.equal(sd(note(F, { kind: 62 })).code, 'needs_approval');
});

test('case 6: a hold: wait W, then sign with hold; a locked device cancels; a recovery ends running holds', () => {
  const F = fixture(); const S = server(F);
  const A = F.devices[0];
  const vanish = note(F, { kind: 62, content: '' });
  const holdReq = { v: 1, type: 'hold', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'member', event: vanish };
  const n = ask(S, F, A.kp.pub, holdReq);
  assert.equal(n.kind, 'hold');
  const withHold = () => new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, { ...vanish, created_at: clock }, { hold: n.wait });
  // The event is the held one, so created_at must match: build it from the held event.
  const fromHeld = () => new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, vanish, { hold: n.wait });
  assert.equal(ask(S, F, A.kp.pub, fromHeld().request).code, 'hold_not_passed');
  clock += 3 * 86400;
  const r = fromHeld();
  r.request.event.created_at = vanish.created_at;
  assert.equal(ask(S, F, A.kp.pub, r.request, clock).type, 'partial');
  void withHold;
  // A statement for the passed hold.
  const w = S.waited(n.wait)!;
  assert.equal(w.end - w.start, 3 * 86400);
  // Cancel by lock.
  const vanish2 = note(F, { kind: 62, content: 'again' });
  const n2 = ask(S, F, A.kp.pub, { ...holdReq, id: bytesToHex(randomBytes(16)), event: vanish2 });
  const cancel = { v: 1, type: 'cancel', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'member', wait: n2.wait,
    approval: { lock: { member: A.kp.pub, assertion: A.lock!.assert(F.g, what.cancel(n2.wait)) } } };
  assert.equal(ask(S, F, A.kp.pub, cancel).kind, 'cancelled');
  clock += 3 * 86400;
  assert.equal(S.waited(n2.wait), null);
  // A recovery freezes holds.
  const ch = ask(S, F, F.backup.kp.pub, { v: 1, type: 'challenge', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'ask' });
  const rr = bytesToHex(randomBytes(16));
  const rel = ask(S, F, F.backup.kp.pub, { v: 1, type: 'release_request', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'member', r: rr,
    challenge: ch.challenge, sig: schnorrSign(detachedDigest('release_request', F.g, { r: rr, challenge: ch.challenge }), F.backup.kp.sk) });
  assert.equal(rel.kind, 'recovery');
  assert.equal(ask(S, F, A.kp.pub, { ...holdReq, id: bytesToHex(randomBytes(16)), event: note(F, { kind: 62, content: '3' }) }).code, 'frozen');
});

test('case 7: rounds with a removed member are refused at once', async () => {
  const F = fixture();
  const A = F.devices[0], b = newKey();
  const add: Change[] = [{ add: { key: b.pub, kind: 'device', lock: null, salt: 0 } }];
  const addEv = F.change(add[0], add, approveLock(F.g, F.epochId, add, clock + 3600, A.kp.pub, A.lock!));
  const S = server(F, 0, [addEv]);
  assert.ok(S.m.devices.has(b.pub));
  const { deal } = await import('../src/redeal.ts');
  const list: Change[] = [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }];
  const ap = approveLock(F.g, F.epochId, list, clock + 3600, A.kp.pub, A.lock!);
  const d = deal(F.g, A.kp, [], new Map(), F.backup.kp.pub, [5, 6]);
  S.addChanges([F.change(list[0], list, ap), F.change({ redeal: d.redeal }, list, ap)]);
  const bIdx = S.m.record && [...S.m.members.values()].length;
  void bIdx;
  const req = { v: 1, type: 'sign', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'sign', state: S0, event: note(F), signers: [4], commitments: [] };
  assert.equal(ask(S, F, b.pub, req).code, 'removed');
});

test('case 1/8: two-call round for backup + two servers only in a recovery session, only for recovery-approved changes', () => {
  const F = fixture();
  const S1 = server(F, 0), S2 = server(F, 1);
  const B = F.backup;
  const startRecovery = (S: CoSigner) => {
    const ch = ask(S, F, B.kp.pub, { v: 1, type: 'challenge', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'ask' });
    return ask(S, F, B.kp.pub, { v: 1, type: 'release_request', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'member', r: 'ab'.repeat(16),
      challenge: ch.challenge, sig: schnorrSign(detachedDigest('release_request', F.g, { r: 'ab'.repeat(16), challenge: ch.challenge }), B.kp.sk) });
  };
  const me = { key: B.kp.pub, indices: [5, 6], shares: B.shares };
  const cos = [{ key: F.servers[0].kp.pub, indices: [4] }, { key: F.servers[1].kp.pub, indices: [7] }];
  const run = (ev: any) => {
    const t = new TwoCall(ctx(F), me, cos, ev);
    const c1 = ask(S1, F, B.kp.pub, t.commitRequest()), c2 = ask(S2, F, B.kp.pub, t.commitRequest());
    if (c1.type !== 'commitments') return c1;
    t.took(cos[0].key, c1); t.took(cos[1].key, c2);
    const req = t.signRequest();
    const p1 = ask(S1, F, B.kp.pub, req), p2 = ask(S2, F, B.kp.pub, req);
    if (p1.type !== 'partial') return p1;
    return { t, p1, p2, req };
  };
  assert.equal(run(note(F)).code, 'no_recovery_session');
  startRecovery(S1); startRecovery(S2);
  clock += 3 * 86400 + 1;
  assert.equal(run(note(F)).code, 'recovery_session', 'an ordinary event during a session is refused');
  // A second sign naming the same `after` is refused.
  const t = new TwoCall(ctx(F), me, cos, note(F));
  t.took(cos[0].key, ask(S1, F, B.kp.pub, t.commitRequest())); t.took(cos[1].key, ask(S2, F, B.kp.pub, t.commitRequest()));
  ask(S1, F, B.kp.pub, t.signRequest());
  const again = { ...t.signRequest(), id: bytesToHex(randomBytes(16)) };
  assert.equal(ask(S1, F, B.kp.pub, again).code, 'after_used');
});

test('case 1: the two-call round signs for backup + two servers (math, via a change the session allows)', async () => {
  // A recovery-approved add, co-signed in the session by backup (2) + S1 + S2: see sim/ for the whole flow.
  // Here: the two-call machinery alone, with a device coordinating two servers (no I4 rule).
  const F = fixture(); const S1 = server(F, 0), S2 = server(F, 1);
  const A = F.devices[0];
  const t = new TwoCall(ctx(F), { key: A.kp.pub, indices: [1, 2, 3], shares: A.shares }, [{ key: F.servers[0].kp.pub, indices: [4] }, { key: F.servers[1].kp.pub, indices: [7] }], note(F));
  t.took(F.servers[0].kp.pub, ask(S1, F, A.kp.pub, t.commitRequest())); t.took(F.servers[1].kp.pub, ask(S2, F, A.kp.pub, t.commitRequest()));
  const req = t.signRequest();
  const ev = t.finish(new Map([[F.servers[0].kp.pub, ask(S1, F, A.kp.pub, req)], [F.servers[1].kp.pub, ask(S2, F, A.kp.pub, req)]]));
  assert.ok(verifyEvent(ev));
  // Changing the co-signer's own commitment in the list is refused.
  const t2 = new TwoCall(ctx(F), { key: A.kp.pub, indices: [1, 2, 3], shares: A.shares }, [{ key: F.servers[0].kp.pub, indices: [4] }, { key: F.servers[1].kp.pub, indices: [7] }], note(F));
  const c1 = ask(S1, F, A.kp.pub, t2.commitRequest());
  t2.took(F.servers[0].kp.pub, { ...c1, commitments: [{ ...c1.commitments[0], D: c1.commitments[0].E }] });
  t2.took(F.servers[1].kp.pub, ask(S2, F, A.kp.pub, t2.commitRequest()));
  assert.equal(ask(S1, F, A.kp.pub, t2.signRequest()).code, 'bad_commitments');
});

test('§5.5: weighted decryption with proofs; only a device asks; answers are useless alone', () => {
  const F = fixture(); const S = server(F);
  const peer = secp256k1.utils.randomSecretKey();
  const Q = '02' + bytesToHex(secp256k1.getPublicKey(peer, true)).slice(2);
  const req = ecdhRequest(ctx(F), [1, 2, 3], { key: F.servers[0].kp.pub, indices: [4] }, [Q]);
  const ans = ask(S, F, F.devices[0].kp.pub, req);
  const [shared] = ecdhFinish(ctx(F), req, dev(F), { key: F.servers[0].kp.pub, indices: [4] }, ans);
  const expect = mul(BigInt('0x' + bytesToHex(peer)), liftX(F.g));
  assert.equal(xOnly(liftX(shared.slice(2))), xOnly(expect));
  // Tampered proof → refusal by name.
  const bad = structuredClone(ans); bad.answers[0][0].z = '00'.repeat(31) + '01';
  assert.throws(() => ecdhFinish(ctx(F), req, dev(F), { key: F.servers[0].kp.pub, indices: [4] }, bad), /bad_proof/);
  // Repeated index.
  const rep = structuredClone(ans); rep.answers[0].push(rep.answers[0][0]);
  assert.throws(() => ecdhFinish(ctx(F), req, dev(F), { key: F.servers[0].kp.pub, indices: [4] }, rep), /bad_answer/);
  assert.equal(ask(S, F, F.backup.kp.pub, { ...req, id: bytesToHex(randomBytes(16)) }).code, 'not_device');
});

test('§5.7 item 5 and §6.7.5: account machinery and signposts are guarded', async () => {
  const F = fixture(); const S = server(F);
  const { signpostD } = await import('../src/codes.ts');
  const sign = (ev: any) => ask(S, F, F.devices[0].kp.pub, new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, ev).request);
  assert.equal(sign(note(F, { kind: 30242, tags: [['d', 'keykin']] })).code, 'machinery');
  assert.equal(sign(note(F, { kind: 24302, content: '{}' })).code, 'not_a_change');
  const d = signpostD(F.backup.kp.pub);
  assert.equal(sign(note(F, { kind: 5, tags: [['a', `30078:${F.g}:${d}`]] })).code, 'machinery');
  assert.equal(sign(note(F, { kind: 30078, tags: [['d', d], ['n', '7'], ['h', '00']] })).code, 'signpost_n');
  assert.equal(sign(note(F, { kind: 30078, tags: [['d', d], ['n', '0'], ['h', '00']] })).code, 'signpost_h');
});

test('§5.6: answered ids survive a restart; nonces do not', () => {
  const F = fixture(); const S = server(F);
  const A = F.devices[0];
  const r = new OneCall(ctx(F), dev(F), { key: F.servers[0].kp.pub, indices: [4] }, note(F));
  const a1 = ask(S, F, A.kp.pub, r.request);
  const t = new TwoCall(ctx(F), { key: A.kp.pub, indices: [1, 2, 3], shares: A.shares }, [{ key: F.servers[0].kp.pub, indices: [4] }, { key: F.servers[1].kp.pub, indices: [7] }], note(F));
  t.took(F.servers[0].kp.pub, ask(S, F, A.kp.pub, t.commitRequest()));
  const snap = S.snapshot();
  assert.ok(!snap.includes(String(F.servers[0].share.toString(16))), 'no share in the snapshot');
  const S2 = server(F); S2.restore(snap);
  assert.deepEqual(ask(S2, F, A.kp.pub, structuredClone(r.request)), a1, 'the same answer after a restart');
  assert.equal(ask(S2, F, A.kp.pub, { ...r.request, event: note(F, { content: 'x' }) }).code, 'id_reused');
  t.took(F.servers[1].kp.pub, { type: 'commitments', commitments: [{ i: 7, D: t.commitments[0].D, E: t.commitments[0].E }] });
  assert.equal(ask(S2, F, A.kp.pub, t.signRequest()).code, 'unknown_after', 'two-call nonces are gone after a restart');
});

test('#16: decryption answers must cover exactly the partner\'s indices, with proofs', () => {
  const F = fixture(); const S = server(F);
  const peer = secp256k1.utils.randomSecretKey();
  const Q = '02' + bytesToHex(secp256k1.getPublicKey(peer, true)).slice(2);
  const co = { key: F.servers[0].kp.pub, indices: [4] };
  const req = ecdhRequest(ctx(F), [1, 2, 3], co, [Q]);
  const ans = ask(S, F, F.devices[0].kp.pub, req);
  const fin = (a: any, indices = [4]) => () => ecdhFinish(ctx(F), req, dev(F), { ...co, indices }, a);
  assert.throws(fin({ ...ans, answers: [[]] }), /bad_answer/, 'empty parts');
  assert.throws(fin({ ...ans, answers: [] }), /bad_answer/, 'no answer for the point');
  assert.throws(fin({ type: 'ecdh_partial' }), /bad_answer/, 'no answers at all');
  assert.throws(fin(ans, [4, 7]), /bad_answer/, 'a missing index');
  const dup = structuredClone(ans); dup.answers[0].push(dup.answers[0][0]);
  assert.throws(fin(dup, [4, 4]), /bad_answer|repeated_index/, 'duplicates refused even when the claimed set repeats');
  const noProof = structuredClone(ans); delete noProof.answers[0][0].z; delete noProof.answers[0][0].R1;
  assert.throws(fin(noProof), /bad_proof/, 'proofs are mandatory');
  assert.ok(fin(ans)().length === 1);
});
