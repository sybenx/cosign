import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as F from '../src/frost.ts';
import { mul, derivePoint, compHex } from '../src/curve.ts';
import { randomBytes, bytesToHex, sha } from '../src/bytes.ts';

const DEV = [1, 2, 3], SRV = [4], PAPER = [5, 6];
const setup = () => F.deal(BigInt('0x' + bytesToHex(randomBytes(32))), [...DEV, ...SRV, 7, 8, ...PAPER]);

function round(C: any, shares: Map<number, bigint>, who: number[], msg: string) {
  const cs = who.map((i) => F.commit(C, i, shares.get(i)!, F.hedge(shares.get(i)!, sha(msg, String(i)))));
  const commits = cs.map((c) => c.commit);
  const zs = cs.map((c) => ({ i: c.commit.i, z: F.signShare(C, c.commit.i, shares.get(c.commit.i)!, c.nonces, msg, commits) }));
  return { commits, zs, sig: F.aggregate(C, msg, commits, zs) };
}

test('device (3) + server (1) signs a plain BIP-340 signature; share points derive', () => {
  const { commitment: C, shares } = setup();
  for (const [i, s] of shares) assert.equal(F.sharePoint(C, i), compHex(derivePoint(C, BigInt(i))));
  assert.ok(mul(shares.get(1)!).equals(derivePoint(C, 1n)));
  // Many rounds: R's y parity varies per round, so both the even and odd-R paths of the TR
  // ciphersuite are exercised (P(no odd R in 24 rounds) = 2^-24).
  for (let k = 0; k < 24; k++) round(C, shares, [...DEV, ...SRV], bytesToHex(sha('ev', String(k))));
});

test('large hashed indices work as 32-byte identifiers', () => {
  const big = [70000, 1073807360, 555555555];
  const { commitment: C, shares } = F.deal(12345n, [...big, 4]);
  round(C, shares, [...big, 4], bytesToHex(sha('x')));
});

test('a bad partial is caught by verifyShare and aggregate refuses', () => {
  const { commitment: C, shares } = setup();
  const msg = bytesToHex(sha('m'));
  const cs = [...DEV, ...SRV].map((i) => F.commit(C, i, shares.get(i)!, F.hedge(shares.get(i)!, sha('c', String(i)))));
  const commits = cs.map((c) => c.commit);
  const zs = cs.map((c) => ({ i: c.commit.i, z: F.signShare(C, c.commit.i, shares.get(c.commit.i)!, c.nonces, msg, commits) }));
  zs[3].z = zs[2].z;
  assert.equal(F.verifyShare(C, msg, commits, 4, zs[3].z), false);
  assert.equal(F.verifyShare(C, msg, commits, 3, zs[2].z), true);
  assert.throws(() => F.aggregate(C, msg, commits, zs));
});

test('nonces are single use', () => {
  const { commitment: C, shares } = setup();
  const c = F.commit(C, 1, shares.get(1)!, F.hedge(shares.get(1)!, sha('a')));
  c.nonces.take();
  assert.throws(() => c.nonces.take(), /nonce_used/);
});

test('same OS randomness, different context: different nonces (vectors.md case 2)', () => {
  const { commitment: C, shares } = setup();
  const os = randomBytes(32);
  const a = F.commit(C, 4, shares.get(4)!, F.hedge(shares.get(4)!, sha('request-1'), os));
  const b = F.commit(C, 4, shares.get(4)!, F.hedge(shares.get(4)!, sha('request-2'), os));
  assert.notEqual(a.commit.D, b.commit.D);
  assert.notEqual(a.commit.D, a.commit.E);
  const a2 = F.commit(C, 4, shares.get(4)!, F.hedge(shares.get(4)!, sha('request-1'), os));
  assert.equal(a.commit.D, a2.commit.D, 'hedge is deterministic in its inputs');
});

test('repair: device (3) + server (1) repair a new index; the summed share matches', () => {
  const { commitment: C, shares } = setup();
  const helpers = [...DEV, ...SRV], target = 99999;
  const deltas = helpers.map((h) => F.repairDeltas(C, helpers, h, shares.get(h)!, target));
  // Device (indices 1-3) sums what is addressed to its indices into one sigma; the server likewise.
  const sigDev = F.repairSigma(deltas.flatMap((d) => DEV.map((i) => d.get(i)!)));
  const sigSrv = F.repairSigma(deltas.map((d) => d.get(4)!));
  const s = F.repairShare(C, [sigDev, sigSrv], target);
  assert.ok(mul(s).equals(derivePoint(C, BigInt(target))));
  assert.throws(() => F.repairShare(C, [sigDev], target), /repair_failed/);
  // Seat replacement: repairing an existing seat index gives the same value (Upkeep §6.7).
  const d7 = helpers.map((h) => F.repairDeltas(C, helpers, h, shares.get(h)!, 7));
  const s7 = F.repairShare(C, [F.repairSigma(d7.flatMap((d) => DEV.map((i) => d.get(i)!))), F.repairSigma(d7.map((d) => d.get(4)!))], 7);
  assert.equal(s7, shares.get(7));
});
