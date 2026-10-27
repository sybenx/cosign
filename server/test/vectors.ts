// Fixed-input vectors for the phone's Kotlin FROST. Writes android/cosign/src/test/resources/frost.json.
// Every sign vector also aggregates with the coordinator's partial into a valid BIP-340 signature.
import { writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as F from '../frost.ts';

const N = F.N, G = F.G, mod = (a: bigint) => ((a % N) + N) % N;
const sc = (label: string) => mod(F.toInt(sha256(utf8ToBytes(label)))) || 1n;
const pt = (k: bigint) => F.bytesToHex(G.multiply(k).toBytes(true));

let a0 = sc('cosign vector a0'); if (!F.evenY(G.multiply(a0))) a0 = N - a0;
const a1 = sc('cosign vector a1');
const share = (i: number) => mod(a0 + a1 * BigInt(i));
const groupX = F.bytesToHex(G.multiply(a0).toBytes(true).slice(1));

const out: any = { groupX, shares: [1, 2, 3].map(i => ({ idx: i, secret: F.toHex32(share(i)), pub: pt(share(i)) })), sign: [], ecdh: [] };
const seen = { flip: 0, noflip: 0 };
for (let t = 0; seen.flip < 3 || seen.noflip < 3; t++) {
  const msg = F.bytesToHex(sha256(utf8ToBytes('msg ' + t)));
  const coord = t % 2 ? 1 : 2, phone = 3;
  const cn = { d: sc(`d ${t} ${coord}`), e: sc(`e ${t} ${coord}`) };
  const pn = { d: sc(`d ${t} ${phone}`), e: sc(`e ${t} ${phone}`) };
  const commits = [{ idx: coord, D: pt(cn.d), E: pt(cn.e) }, { idx: phone, D: pt(pn.d), E: pt(pn.e) }];
  const flip = F.roundFlips(groupX, msg, commits);
  if (flip ? seen.flip >= 3 : seen.noflip >= 3) continue;
  flip ? seen.flip++ : seen.noflip++;
  const zc = F.partialSign({ groupX, msg, commits, idx: coord, secret: F.toHex32(share(coord)), nonces: cn });
  const zp = F.partialSign({ groupX, msg, commits, idx: phone, secret: F.toHex32(share(phone)), nonces: pn });
  const sig = F.aggregate({ groupX, msg, commits, partials: [zc, zp] }); // throws unless it verifies
  out.sign.push({ msg, flip, commits, phone: { idx: phone, d: F.toHex32(pn.d), e: F.toHex32(pn.e) }, expectZ: zp, sig });
}
for (let t = 0; t < 3; t++) {
  const peerX = F.bytesToHex(G.multiply(sc('peer ' + t)).toBytes(true).slice(1));
  const participants = t % 2 ? [1, 3] : [2, 3];
  out.ecdh.push({ peerX, participants, idx: 3, expect: F.ecdhPartial({ idx: 3, secret: F.toHex32(share(3)), participants, peerX }) });
}
// The DLEQ on an ecdh partial (frost.ts `ecdhProve`/`ecdhVerify`). The proof itself is
// randomised, so what a vector can pin is the two things that must match across platforms: the
// challenge's transcript encoding, and that a proof made here verifies there.
out.dleq = [];
for (let t = 0; t < 3; t++) {
  const peerX = F.bytesToHex(G.multiply(sc('dleq peer ' + t)).toBytes(true).slice(1));
  const participants = t % 2 ? [1, 3] : [2, 3];
  const idx = 3, secret = F.toHex32(share(idx));
  const made = F.ecdhProve({ idx, secret, participants, peerX });
  if (!F.ecdhVerify({ idx, participants, peerX, sharePub: pt(share(idx)), point: made.point, proof: made.proof })) throw new Error('a proof this file made does not verify');
  // A fixed transcript for the challenge, so an implementation can check the bytes it hashes
  // without having to reproduce a random nonce.
  const L = G.multiply(mod(F.lagrange(idx, participants) * share(idx)));
  const A = F.Point.fromHex('02' + peerX).multiply(mod(F.lagrange(idx, participants) * share(idx)));
  const R1 = G.multiply(sc('dleq r1 ' + t)), R2 = F.Point.fromHex('02' + peerX).multiply(sc('dleq r1 ' + t));
  out.dleq.push({
    peerX, participants, idx, sharePub: pt(share(idx)),
    point: made.point, proof: made.proof,
    challenge: {
      L: F.bytesToHex(L.toBytes(true)), A: F.bytesToHex(A.toBytes(true)),
      R1: F.bytesToHex(R1.toBytes(true)), R2: F.bytesToHex(R2.toBytes(true)),
      expect: F.toHex32(F.dleqChallenge(idx, participants, peerX, L, A, R1, R2)),
    },
  });
}
out.lagrange = [[1, [1, 3]], [3, [1, 3]], [3, [2, 3]], [2, [2, 3]]].map(([i, p]: any) => ({ i, p, expect: F.toHex32(F.lagrange(i, p)) }));
writeFileSync(new URL('../../android/cosign/src/test/resources/frost.json', import.meta.url), JSON.stringify(out, null, 2));
console.log(`wrote ${out.sign.length} sign vectors (${seen.flip} with R negated), ${out.ecdh.length} ecdh, ${out.dleq.length} dleq, ${out.lagrange.length} lagrange`);
