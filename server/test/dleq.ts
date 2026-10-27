// The DLEQ on a decryption partial (frost.ts `ecdhProve`/`ecdhVerify`), on its own.
//
//   node test/dleq.ts
//
// A partial used to be unverifiable: `ecdhCombine` rejects only the identity, so one wrong
// contribution made the asker derive a value nobody else has, and the only symptom was a MAC
// failure wherever the plaintext was wanted. These are the cases that must be caught.

import { readFileSync, existsSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as F from '../frost.ts';

let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const sc = (l: string) => ((F.toInt(sha256(utf8ToBytes(l))) % F.N) + F.N) % F.N || 1n;
const xOf = (k: bigint) => F.bytesToHex(F.G.multiply(k).toBytes(true)).slice(2);

const g = F.deal(null, 3, 2);
const participants = [1, 3];
const peerX = xOf(sc('a peer'));
const share = (i: number) => g.shares[i - 1];
const prove = (i: number, p = participants, x = peerX) => F.ecdhProve({ idx: i, secret: share(i).secret, participants: p, peerX: x });
const verify = (a: Partial<Parameters<typeof F.ecdhVerify>[0]>) => F.ecdhVerify({ idx: 1, participants, peerX, sharePub: share(1).pub, point: '', proof: '', ...a } as any);

const one = prove(1);
check('a partial comes out the same as ecdhPartial', one.point === F.ecdhPartial({ idx: 1, secret: share(1).secret, participants, peerX }));
check('its proof is 98 bytes', one.proof.length === 196, `${one.proof.length / 2} bytes`);
check('an honest partial verifies', verify({ point: one.point, proof: one.proof }));

// The attack §6 of docs/app-keys.md names: a partner returns (lambda_i * s_i + d) * Q.
const Q = F.Point.fromHex('02' + peerX);
const off = F.bytesToHex(F.Point.fromHex(one.point).add(Q.multiply(7n)).toBytes(true));
check('an offset partial does not', !verify({ point: off, proof: one.proof }));

// A partial that is a real partial, of the wrong share.
const three = prove(3);
check('another share’s partial does not', !verify({ idx: 1, point: three.point, proof: three.proof }));
check('nor with the right index and the wrong share point', !verify({ idx: 3, point: three.point, proof: three.proof, sharePub: share(1).pub }));

// Replay into a round with a different participant list, so a different lambda.
const other = [2, 3];
check('a proof cannot be lifted into another participant set', !F.ecdhVerify({ idx: 3, participants: other, peerX, sharePub: share(3).pub, point: three.point, proof: three.proof }));
check('nor onto another peer', !F.ecdhVerify({ idx: 3, participants, peerX: xOf(sc('another peer')), sharePub: share(3).pub, point: three.point, proof: three.proof }));

// Malformed proofs are false, never a throw.
for (const [label, proof] of [
  ['empty', ''],
  ['short', one.proof.slice(0, 100)],
  ['not hex', 'z'.repeat(196)],
  ['zero z', one.proof.slice(0, 132) + '0'.repeat(64)],
  ['z = n', one.proof.slice(0, 132) + F.toHex32(F.N)],
  ['R1 not a point', '02' + 'f'.repeat(64) + one.proof.slice(66)],
] as [string, string][]) check(`the ${label} proof is refused, not an exception`, verify({ point: one.point, proof }) === false);

// The whole round, both ways: two honest partials combine to the same x as the plain path.
const mine = prove(3);
const asked = prove(1);
check('two verified partials combine to the shared x', F.bytesToHex(F.ecdhCombine([mine.point, asked.point])) === F.bytesToHex(F.ecdhCombine([
  F.ecdhPartial({ idx: 3, secret: share(3).secret, participants, peerX }),
  F.ecdhPartial({ idx: 1, secret: share(1).secret, participants, peerX }),
])));

// And against the vectors, so the transcript encoding is pinned where Kotlin will read it.
const vf = new URL('../../android/cosign/src/test/resources/frost.json', import.meta.url).pathname;
if (existsSync(vf)) {
  const v = JSON.parse(readFileSync(vf, 'utf8'));
  check('the vectors carry dleq cases', Array.isArray(v.dleq) && v.dleq.length > 0, `${v.dleq?.length ?? 0}`);
  for (const [i, d] of (v.dleq ?? []).entries()) {
    check(`vector ${i} verifies`, F.ecdhVerify({ idx: d.idx, participants: d.participants, peerX: d.peerX, sharePub: d.sharePub, point: d.point, proof: d.proof }));
    const c = F.dleqChallenge(d.idx, d.participants, d.peerX, F.Point.fromHex(d.challenge.L), F.Point.fromHex(d.challenge.A), F.Point.fromHex(d.challenge.R1), F.Point.fromHex(d.challenge.R2));
    check(`vector ${i}'s challenge is the bytes it says`, F.toHex32(c) === d.challenge.expect);
  }
} else {
  check('the vectors exist (node test/vectors.ts)', false, vf);
}

// A real group made by the live servers: the share point in the member list must be the one
// this proof is about, under the scheme the servers actually sign with.
const live = ['test-promote/a', 'test-stale/a', 'test-paper/a', 'test-periodic/a']
  .map(d => new URL(`../${d}/state.json`, import.meta.url).pathname).find(existsSync);
if (live) {
  const S = JSON.parse(readFileSync(live, 'utf8'));
  const flat = S.group.members.flatMap((m: any) => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]);
  const self = S.self.shares[0];
  const sp = flat.find((x: any) => x.idx === self.idx)?.sharePub;
  const parts = [...flat.map((x: any) => x.idx)].sort((a: number, b: number) => a - b).slice(0, S.group.threshold);
  const p = F.ecdhProve({ idx: self.idx, secret: self.secret, participants: parts, peerX });
  check('a real server’s share point is the one the proof is about', !!sp && F.ecdhVerify({ idx: self.idx, participants: parts, peerX, sharePub: sp, point: p.point, proof: p.proof }), live.split('/').slice(-2)[0]);
} else {
  console.log('--  no live test group on disk to check the share-point convention against');
}

console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
