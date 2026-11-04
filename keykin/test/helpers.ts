// Test fixtures: a whole account built by a dealer whose group secret the test knows, so changes
// can be group-signed directly. Real accounts never have that (vectors.md note).

import { finalizeEvent } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.ts';
import { helperSeat } from '../src/codes.ts';
import { commitmentHex, scalarHex, xOnly, mod } from '../src/curve.ts';
import { deal } from '../src/frost.ts';
import { newKey, type KeyPair, type NostrEvent } from '../src/event.ts';
import { softLock, type SoftLock } from '../src/lock.ts';
import { approvalHash } from '../src/approval.ts';
import { KIND_CHANGE, KIND_EPOCH, type Approval, type Change, type EpochContent, type MemberEntry } from '../src/types.ts';

export interface Fixture {
  secret: bigint; g: string; epochId: string; rec: EpochContent; recEv: NostrEvent;
  devices: { kp: KeyPair; lock: SoftLock | null; shares: Map<number, bigint> }[];
  servers: { kp: KeyPair; host: KeyPair; idx: number; share: bigint }[];
  backup: { kp: KeyPair; shares: Map<number, bigint> };
  commitment: ReturnType<typeof deal>['commitment'];
  sign(kind: number, content: string, tags: string[][], created_at?: number): NostrEvent;
  change(change: Change, list: Change[], approval: Approval, extra?: object): NostrEvent;
}

export function fixture(opts: { lockless?: boolean; mutate?: (c: EpochContent) => void } = {}): Fixture {
  const a = newKey(), srv = [newKey(), newKey(), newKey()], hosts = [newKey(), newKey(), newKey()], bk = newKey();
  const secret = mod(BigInt('0x' + bytesToHex(randomBytes(32))));
  const d = deal(secret, [1, 2, 3, 4, 7, 8, 5, 6]);
  const sk = d.secret, g = xOnly(d.commitment[0]);
  const lock = opts.lockless ? null : softLock();
  const epochId = bytesToHex(randomBytes(16));
  const members: MemberEntry[] = [
    { key: a.pub, kind: 'device', shares: [1, 2, 3], ...(lock ? { lock: lock.pub } : {}) },
    ...srv.map((s, k) => ({ key: s.pub, kind: 'server', shares: [[4, 7, 8][k]], host: hosts[k].pub, operator: hosts[0].pub, own: false, https: `https://s${k}.test` })),
    { key: bk.pub, kind: 'backup', shares: [5, 6] },
  ];
  const rec: EpochContent = { v: 1, g, epoch: { n: 1, id: epochId }, prev: null, t: 4, commitment: commitmentHex(d.commitment), role: 'master', origin: 'import',
    relays: ['wss://r1.test', 'wss://r2.test', 'wss://r3.test'], members, removed: [], backup: '00'.repeat(32),
    seats: { servers: [4, 7, 8], backup: [5, 6], helper: helperSeat(g) } };
  opts.mutate?.(rec);
  const sign = (kind: number, content: string, tags: string[][], created_at = Math.floor(Date.now() / 1000)) =>
    finalizeEvent({ kind, created_at, tags, content }, hexToBytes(scalarHex(sk))) as NostrEvent;
  const recEv = sign(KIND_EPOCH, JSON.stringify(rec), [['d', 'keykin'], ['v', '1'], ['epoch', '1']]);
  return {
    secret: sk, g, epochId, rec, recEv, commitment: d.commitment,
    devices: [{ kp: a, lock, shares: new Map([1, 2, 3].map((i) => [i, d.shares.get(i)!])) }],
    servers: srv.map((s, k) => ({ kp: s, host: hosts[k], idx: [4, 7, 8][k], share: d.shares.get([4, 7, 8][k])! })),
    backup: { kp: bk, shares: new Map([5, 6].map((i) => [i, d.shares.get(i)!])) },
    sign,
    change(change, list, approval, extra = {}) {
      return sign(KIND_CHANGE, JSON.stringify({ v: 1, g, epoch: epochId, change, list, approval, ...extra }), [['v', '1'], ['epoch', epochId]]);
    },
  };
}
export { approvalHash };
