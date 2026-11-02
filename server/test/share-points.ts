// A share point from the member list is not evidence of anything.
//
//   node test/share-points.ts
//
// The library verifies a partial against the point it is handed, and a server's member list is
// where that point comes from (`mergeMembers` copies a peer's `sharePub`). So a member whose
// point a dishonest server chose can produce a partial that **verifies**, with the unmodified
// library, by signing with the secret behind the point it supplied. The aggregate still fails —
// it cannot forge the group's signature — but anything decided at verification time has already
// been decided wrongly, and on this server that is `viaServer`: the mark that keeps a member it
// only heard about from reporting devices lost or taking the account out.

import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { W } from '../wasm.ts';

let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };

await W.ready?.();
const dealt = F.deal(null, 4, 4);
const group: Sig.Group = { groupX: dealt.groupX, threshold: 4, members: dealt.shares.map(s => ({ idx: s.idx, sharePub: s.pub })) };
const msg = F.bytesToHex(F.randomBytes(32));

check('the honest group rebuilds its own points', !!Sig.sound(group));
check('and rebuilds them to the same values', Sig.sharePoints(Sig.sound(group)!).every(p => p.sharePub === group.members.find(m => m.idx === p.idx)!.sharePub));

// A dishonest server adds a "device" claiming three shares, with points it chose and the
// secrets behind them. Three of its points plus this server's one make the threshold, which is
// the shape `attempt` runs: one partner, enough shares between them.
const evilIdx = [5, 6, 7];
const evil = evilIdx.map(idx => ({ ...F.deal(null, 1, 1).shares[0], idx }));
const poisoned: Sig.Group = { ...group, members: [...group.members, ...evil.map(e => ({ idx: e.idx, sharePub: e.pub }))] };

const rebuilt = Sig.sound(poisoned);
check('an injected member\u2019s points are rebuilt, not taken', !!rebuilt && evil.every(e => rebuilt.members.find(m => m.idx === e.idx)!.sharePub !== e.pub),
  rebuilt ? `${rebuilt.members.find(m => m.idx === 5)!.sharePub.slice(0, 12)} vs the one it supplied ${evil[0].pub.slice(0, 12)}` : 'could not rebuild');

// The fake member commits and signs with its own secrets, against the poisoned group.
const honest = Sig.commit(poisoned, 1, dealt.shares[0].secret);
const theirs = evil.map(e => ({ e, c: Sig.commit(poisoned, e.idx, e.secret) }));
const commits = [honest.commit, ...theirs.map(t => t.c.commit)];
const zs: [number, string][] = theirs.map(t => [t.e.idx, Sig.partial(2, poisoned, t.e.idx, t.e.secret, t.c.nonces, msg, commits)]);

// The bug, shown rather than asserted away: the library accepts them against the list's points.
const listJson = JSON.stringify({ groupX: poisoned.groupX, threshold: 4, members: Sig.sharePoints(poisoned) });
check('the library accepts them against the points the list supplied',
  zs.every(([i, z]) => W.verifyPartial(listJson, msg, JSON.stringify(commits), i, z) === true));

// The fix.
check('verifying against points rebuilt from the key refuses them', Sig.verifiedPartials(poisoned, msg, commits, zs) === false);

// And an honest round still verifies the sound way.
const all = [1, 2, 3, 4].map(i => ({ i, c: Sig.commit(group, i, dealt.shares[i - 1].secret) }));
const hc = all.map(x => x.c.commit);
const hzs: [number, string][] = all.map(x => [x.i, Sig.partial(2, group, x.i, dealt.shares[x.i - 1].secret, x.c.nonces, msg, hc)]);
check('an honest round still verifies', Sig.verifiedPartials(group, msg, hc, hzs) === true);

// Fail-closed: tamper with a point inside the first `threshold` and nothing can be rebuilt.
const broken: Sig.Group = { ...group, members: group.members.map((m, i) => i === 0 ? { ...m, sharePub: evil[0].pub } : m) };
check('a point tampered with inside the threshold fails closed', Sig.sound(broken) === null);
check('and verification refuses rather than falling back', Sig.verifiedPartials(broken, msg, hc, hzs) === false);

console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
