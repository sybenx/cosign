// A decryption partner that sends only some of its pieces makes a wrong key, in silence.
//
//   node test/ecdh-cover.ts
//
// Each Chaum-Pedersen proof released in 0.12.7 speaks for one index and nothing else. So a
// partner holding three shares that answers with two parts passes every check `frostEcdh` ran
// before this: each part verifies against the rebuilt point, and `checked.size != parts.size`
// compares the answer against itself. `theirs` is then one point short, `ecdhCombine` refuses
// only the identity, and the combined value is nobody's conversation key — a MAC failure
// wherever the plaintext was wanted, with no member named, because every proof passed.

import * as F from '../frost.ts';

let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };

// This browser or phone holds 1-3; the partner holds 4-6, as a device partner does.
const dealt = F.deal(null, 6, 4);
const mine = dealt.shares.filter(s => s.idx <= 3);
const partner = dealt.shares.filter(s => s.idx >= 4);
const peerX = F.bytesToHex(F.randomBytes(32)).slice(0, 64);
const peer = F.deal(null, 1, 1);
const participants = dealt.shares.map(s => s.idx);

const myParts = mine.map(s => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants, peerX: peer.groupX }));
const theirParts = partner.map(s => F.ecdhProve({ idx: s.idx, secret: s.secret, participants, peerX: peer.groupX }));

const whole = F.ecdhCombine([...myParts, ...theirParts.map(p => p.point)]);
const short = F.ecdhCombine([...myParts, ...theirParts.slice(0, 2).map(p => p.point)]);

const sharePub = (idx: number) => dealt.shares.find(s => s.idx === idx)!.pub;
const verifies = (p: F.EcdhPart) => F.ecdhVerify({ idx: p.idx, participants, peerX: peer.groupX, sharePub: sharePub(p.idx), point: p.point, proof: p.proof });

check('every part a partner sends verifies on its own', theirParts.every(verifies));
check('two of its three verify just as well', theirParts.slice(0, 2).every(verifies));
check('and the answer is self-consistent: as many checked as sent', theirParts.slice(0, 2).length === 2);

// The bug, shown rather than asserted away.
check('a short answer still combines, with no error thrown', short.length === 32);
check('to a value that is not the conversation key', F.bytesToHex(short) !== F.bytesToHex(whole),
  `${F.bytesToHex(short).slice(0, 12)} vs the real ${F.bytesToHex(whole).slice(0, 12)}`);

// The check: every one of its indices, and no others.
const sameSet = (a: number[], b: number[]) => [...a].sort((x, y) => x - y).join() === [...b].sort((x, y) => x - y).join();
const want = partner.map(s => s.idx);
check('the coverage check refuses two of three', !sameSet(want, theirParts.slice(0, 2).map(p => p.idx)));
check('and takes all three', sameSet(want, theirParts.map(p => p.idx)));
check('and refuses an index that is not the partner’s', !sameSet(want, [4, 5, 1]));

// A repeated index would also pass "as many checked as sent": three parts, two indices.
const repeated = [theirParts[0], theirParts[0], theirParts[1]];
check('a repeated index is refused too', !sameSet(want, repeated.map(p => p.idx)));
check('though every one of those parts verifies', repeated.every(verifies));

console.log(failures ? `${failures} FAILED` : 'all passed');
process.exit(failures ? 1 : 0);
