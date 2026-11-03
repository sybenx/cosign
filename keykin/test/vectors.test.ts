// docs/keykin/vectors/vectors.json, every computed case (core §14).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as codes from '../src/codes.ts';
import { jcs, sha, bytesToHex, hexToBytes } from '../src/bytes.ts';
import * as cv from '../src/curve.ts';
import { verifyDleq } from '../src/ecdh.ts';
import { futureDateOk, destructive } from '../src/destructive.ts';
import { checkLifetime } from '../src/lifetimes.ts';

const V = JSON.parse(readFileSync(new URL('../../docs/keykin/vectors/vectors.json', import.meta.url), 'utf8')).cases;

test('join_check', () => {
  for (const c of V.join_check) assert.equal(codes.joinCheck(c.g, c.m, c.n, c.s, c.t), c.code);
  assert.notEqual(V.join_check[0].code, V.join_check[1].code);
});

test('list_hash and pair_code', () => {
  assert.equal(jcs(V.list_hash[0].list), V.list_hash[0].jcs);
  for (const c of V.list_hash) assert.equal(codes.listHash(c.list), c.sha256);
  const p = V.pair_code;
  assert.equal(codes.pairCode(p.g, p.list_hash, p.r), p.code);
});

test('indices', () => {
  const c = V.indices;
  const idx = codes.deviceIndices(c.g, c.epoch_id, c.key, c.salt);
  assert.deepEqual(idx, c.indices);
  assert.deepEqual(idx.map(cv.idHex), c.identifiers_32byte);
});

test('wait_ids', () => {
  const c = V.wait_ids;
  assert.equal(codes.holdWaitId(c.event_id), c.hold);
  assert.equal(codes.recoveryWaitId(c.backup_key, c.epoch_id, c.r), c.recovery);
});

test('lock_challenge', () => {
  const g = V.join_check[0].g, ev = V.wait_ids.event_id, lh = V.list_hash[0].sha256;
  const [a, b, c] = V.lock_challenge;
  assert.equal(codes.lockChallenge(g, codes.what.sign(ev)), a.challenge);
  assert.equal(codes.lockChallenge(g, codes.what.change(lh, V.indices.epoch_id, b.expiry)), b.challenge);
  assert.equal(codes.lockChallenge(g, codes.what.cancel(V.wait_ids.recovery)), c.challenge);
});

test('waited_statement_digest', () => {
  const c = V.waited_statement_digest;
  assert.equal(bytesToHex(codes.waitedDigest(V.join_check[0].g, c.kind, c.wait, c.start, c.end)), c.digest);
});

test('commitment_rebuild', () => {
  const c = V.commitment_rebuild;
  const C0 = cv.pointFrom(c.commitment[0]);
  const pts: [bigint, cv.Point][] = [[0n, C0], ...c.device_indices.map((i: number, k: number) => [BigInt(i), cv.pointFrom(c.device_points[k])] as [bigint, cv.Point])];
  const rebuilt = cv.rebuildCommitment(pts);
  assert.deepEqual(cv.commitmentHex(rebuilt), c.rebuilt);
  assert.ok(cv.sameCommitment(rebuilt, cv.commitmentFrom(c.commitment)));
  assert.ok(!cv.sameCommitment(rebuilt, cv.commitmentFrom(c.negative.commitment)));
  const C = cv.commitmentFrom(c.commitment);
  for (const [i, p] of Object.entries(c.derived_points)) assert.equal(cv.compHex(cv.derivePoint(C, BigInt(i))), p);
});

test('ecdh_dleq', () => {
  const c = V.ecdh_dleq;
  const C = cv.commitmentFrom(V.commitment_rebuild.commitment);
  assert.equal(codes.stateHash(c.state_ids), c.state);
  assert.equal(cv.scalarHex(cv.lagrange(BigInt(c.i), c.signers.map(BigInt))), c.lambda_i);
  const ans = { i: c.i, Y: c.Y, R1: c.R1, R2: c.R2, z: c.z };
  const ctx = { g: c.g, epochId: c.epoch_id, state: c.state, signers: c.signers };
  assert.equal(verifyDleq(ctx, C, c.Q, ans), true);
  assert.equal(verifyDleq(ctx, C, c.Q, { ...ans, z: c.negative[0].z }), false);
  assert.throws(() => verifyDleq(ctx, C, '02' + '00'.repeat(32), ans));
});

test('future_dates', () => {
  const now = 1_800_000_000;
  for (const c of V.future_dates) assert.equal(futureDateOk({ kind: c.kind, created_at: now + c.ahead_s, tags: [] }, now), c.accept, JSON.stringify(c));
});

test('stateless_destructive', () => {
  for (const c of V.stateless_destructive) {
    const e = c.event;
    const tags = e.tags ?? Array.from({ length: e.targets ?? 0 }, (_, k) => ['e', k.toString(16).padStart(64, '0')]);
    const ev = { kind: e.kind, content: e.content ?? '', tags, created_at: 0 };
    const needs = destructive(ev, e.unapproved_targets_last_10min ?? 0) ? 'approval or hold' : 'nothing';
    assert.equal(needs, c.needs, JSON.stringify(c));
  }
});

test('lifetimes', () => {
  const now = 1_800_000_000;
  for (const c of V.lifetimes) {
    const ok = checkLifetime(c.type, c.cls, now - (c.age_s ?? 0), now) === null;
    assert.equal(ok, c.accept, JSON.stringify(c));
  }
});

test('helper_seat', () => assert.deepEqual(codes.helperSeat(V.helper_seat.g), V.helper_seat.indices));

test('redeal_apply', () => {
  const c = V.redeal_apply;
  const C = cv.commitmentFrom(V.commitment_rebuild.commitment);
  const D = c.D.map((h: string) => cv.pointFrom(h));
  assert.deepEqual(cv.commitmentHex(cv.addRedeal(C, D)), c.C_S);
  assert.equal(cv.compHex(cv.deriveDelta(D, BigInt(c.device_index))), c.delta_i_G);
  assert.equal(cv.compHex(cv.derivePoint(cv.addRedeal(C, D), BigInt(c.device_index))), c.new_P_i);
  c.paper_reissue.b.forEach((b: number, k: number) => assert.equal(cv.compHex(cv.deriveDelta(D, BigInt(b))), c.paper_reissue.delta_b_G[k]));
});

test('data_key', () => {
  const c = V.data_key;
  assert.equal(codes.dataKey(c.base, [...c.seeds_sorted].reverse()), c.dk_S);
});

test('signpost', () => {
  const c = V.signpost;
  assert.equal(codes.signpostD(c.backup_key), c.d);
  assert.equal(codes.signpostH(c.epoch_id, c.servers), c.h);
  assert.equal(codes.signpostDeviceKey(V.data_key.base), c.device_copy_key);
});

test('seated_reply_digest', () => {
  const c = V.seated_reply_digest;
  assert.equal(bytesToHex(codes.seatedDigest(c.H_key, hexToBytes(c.challenge), sha('sealed-reply-ciphertext'))), c.digest);
});

test('core 13.8: the §5.8 tests are exact', () => {
  const ev = (kind: number, content: string, tags: string[][] = []) => ({ kind, content, tags, created_at: 0 });
  assert.equal(destructive(ev(0, '{"name":"x","name":"y"}')), true, 'a duplicate key counts as empty');
  assert.equal(destructive(ev(0, '{"about":{"a":1,"a":2},"name":"x"}')), true);
  assert.equal(destructive(ev(0, '["name"]')), true, 'not an object');
  assert.equal(destructive(ev(0, '{"name":"   "}')), true, 'whitespace only');
  assert.equal(destructive(ev(0, '{"name":"a\\"b"}')), false);
  assert.equal(destructive(ev(10000, 'encrypted private items')), false, 'a list with private items is not empty');
  assert.equal(destructive(ev(3, '')), true);
  assert.equal(destructive(ev(10002, '', [['r', 'https://x']])), true, 'an r tag that is not a relay URL');
  assert.equal(destructive(ev(10002, '', [['r', 'wss://x']])), false);
});
