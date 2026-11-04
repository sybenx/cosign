// Co-signer vectors (core §5.6–§5.8, vectors.md cases 1, 9): a server's view (record, changes, its
// share) and a sequence of requests, each with the answer type or refusal code the reference gives.
// Run: node vectors/gen-cosigner.ts > vectors/cosigner.json
import { fixture } from '../test/helpers.ts';
import { CoSigner } from '../src/cosigner.ts';
import { OneCall, TwoCall } from '../src/coordinator.ts';
import { approveLock } from '../src/approval.ts';
import { what, stateHash } from '../src/codes.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { scalarHex } from '../src/curve.ts';
import { newKey, wireEvent } from '../src/event.ts';
import type { Change } from '../src/types.ts';

const F = fixture();
const A = F.devices[0];
const now = 1_900_000_000;
const b = newKey();
const add: Change[] = [{ add: { key: b.pub, kind: 'device', lock: null, salt: 0 } }];
const changes = [F.change(add[0], add, approveLock(F.g, F.epochId, add, now + 3600, A.kp.pub, A.lock!))];
const S = new CoSigner({ me: F.servers[0].kp, host: F.servers[0].host, kind: 'server', now: () => now, record: F.rec, changes,
  state: { ids: new Set(), C: F.commitment, shares: new Map([[4, F.servers[0].share]]) } });
const ctx = { g: F.g, epochId: F.epochId, state: stateHash([]), C: F.commitment };
const dev = { indices: [1, 2, 3], shares: A.shares };
// Events as a coordinator sends them (§9.5): the six fields, id included.
const note = (x: any = {}) => wireEvent({ pubkey: F.g, created_at: now, kind: 1, tags: [], content: 'hi', ...x });
const req = (ev: any, extra: any = {}) => new OneCall(ctx, dev, { key: F.servers[0].kp.pub, indices: [4] }, ev, extra).request;
const steps: { name: string; from: string; sent_at: number; request: any; expect: string }[] = [];
const run = (name: string, from: string, request: any, sentAt = now) => {
  const a = S.handle(from, request, sentAt);
  steps.push({ name, from, sent_at: sentAt, request, expect: a.type === 'error' ? a.code : a.type });
};
const r1 = req(note());
run('one-call note', A.kp.pub, r1);
run('byte-identical retry', A.kp.pub, structuredClone(r1));
run('same id, other body', A.kp.pub, { ...r1, event: note({ content: 'other' }) });
run('expired', A.kp.pub, req(note()), now - 91);
run('dated ahead', A.kp.pub, req(note()), now + 31);
run('class not allowed', A.kp.pub, { ...req(note()), cls: 'member' });
run('unknown type', A.kp.pub, { ...req(note()), type: 'frobnicate' });
run('prototype type', A.kp.pub, { ...req(note()), type: 'constructor' });
run('not a member', newKey().pub, req(note()));
run('signers not the participants', A.kp.pub, { ...req(note()), signers: [1, 2, 4] });
run('a third participant', A.kp.pub, { ...req(note()), signers: [1, 2, 3, 4, 7] });
const rc = req(note()); run('a commitment missing', A.kp.pub, { ...rc, commitments: rc.commitments.slice(1) });
run('stale state', A.kp.pub, { ...req(note()), state: stateHash([bytesToHex(randomBytes(16))]) });
run('wrong pubkey', A.kp.pub, { ...req(note()), event: note({ pubkey: newKey().pub }) });
run('replaceable dated ahead', A.kp.pub, req(note({ kind: 0, created_at: now + 601, content: '{"name":"x"}' })));
run('note scheduled ahead', A.kp.pub, req(note({ created_at: now + 86400 })));
run('epoch record is machinery', A.kp.pub, req(note({ kind: 30242, tags: [['d', 'keykin']] })));
run('a list event alone', A.kp.pub, req(note({ kind: 24302, content: JSON.stringify({ v: 1, g: F.g, epoch: F.epochId, change: { remove: b.pub }, list: [{ remove: b.pub }, { redeal: { dealer: A.kp.pub } }], approval: {} }), tags: [['v', '1'], ['epoch', F.epochId]] })));
run('wipe a follow list without approval', A.kp.pub, req(note({ kind: 3, content: '' })));
const wipe = note({ kind: 3, content: '', created_at: now });
const w = new OneCall(ctx, dev, { key: F.servers[0].kp.pub, indices: [4] }, wipe);
run('wipe with the lock', A.kp.pub, new OneCall(ctx, dev, { key: F.servers[0].kp.pub, indices: [4] }, wipe, { approval: { lock: { member: A.kp.pub, assertion: A.lock!.assert(F.g, what.sign(w.eventId)) } } }).request);
run('vanish without approval', A.kp.pub, req(note({ kind: 62 })));
run('ecdh from the backup', F.backup.kp.pub, { v: 1, type: 'ecdh', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'sign', state: stateHash([]), points: ['02' + F.g], signers: [4, 5, 6] });
run('hold from a device', A.kp.pub, { v: 1, type: 'hold', g: F.g, epoch: F.epochId, id: bytesToHex(randomBytes(16)), cls: 'member', event: note({ kind: 62 }) });
run('a stranger again', newKey().pub, req(note()));
// Two-call (§5.1): the commit is answered with commitments; a one-call request with the commit's shape is not.
const tc = new TwoCall(ctx, { key: A.kp.pub, ...dev }, [{ key: F.servers[0].kp.pub, indices: [4] }], note({ content: 'two-call' }));
run('two-call commit', A.kp.pub, tc.commitRequest('sign'));
run('sign after an unknown commit', A.kp.pub, { ...tc.signRequest('sign'), after: bytesToHex(randomBytes(16)) });
console.log(JSON.stringify({ note: 'Generated by keykin/vectors/gen-cosigner.ts. A server holding index 4 at state [], clock fixed; run the steps in order on one co-signer.',
  g: F.g, now, record: F.recEv, changes, server: { key: F.servers[0].kp.pub, host: F.servers[0].host.pub, index: 4, share: scalarHex(F.servers[0].share) },
  // The coordinating device's shares (a test fixture), so a port can drive a two-call round itself.
  device: { key: A.kp.pub, shares: [...A.shares].map(([i, x]) => [i, scalarHex(x)]) }, steps }, null, 1));
