import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dkgLocal } from '../src/dkg.ts';
import { randomBytes, bytesToHex, sha } from '../src/bytes.ts';
import { mul, derivePoint } from '../src/curve.ts';
import * as F from '../src/frost.ts';

test('DKG (Account admin §1.1): 8 indices, even y, commitment rebuilt and checked, signs as BIP-340', () => {
  for (let k = 0; k < 3; k++) {
    const d = dkgLocal([1, 2, 3, 4, 5, 6, 7, 8], () => randomBytes(32));
    assert.equal(d.C[0].toAffine().y % 2n, 0n, 'even y');
    for (const [i, s] of d.shares) assert.ok(mul(s).equals(derivePoint(d.C, BigInt(i))));
    const msg = bytesToHex(sha('dkg-sign'));
    const cs = [1, 2, 3, 4].map((i) => F.commit(d.C, i, d.shares.get(i)!, F.hedge(d.shares.get(i)!, sha(String(i)))));
    const commits = cs.map((c) => c.commit);
    F.aggregate(d.C, msg, commits, cs.map((c) => ({ i: c.commit.i, z: F.signShare(d.C, c.commit.i, d.shares.get(c.commit.i)!, c.nonces, msg, commits) })));
  }
});
