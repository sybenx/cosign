// Refresh (COSIGN.md §7.3): every remaining member moves to a new epoch with the same
// group key, so a removed member's pieces stop combining with anything.
//
// Each dealer (at least one device and one server, so neither alone knows every
// change) picks a random polynomial g of degree t-1 with g(0) = 0 and sends each
// remaining share j its delta g(j), sealed to the member holding j, with commitments
// to g's coefficients. A member checks every delta against its dealer's commitments,
// adds them all to its shares, and works out every share's new point from the same
// commitments, so the whole group's points move together. Scalar arithmetic only:
// the shares stay plain FROST shares.
//
// The same runner is used by the servers and the test phone; the app has its own copy.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

const Fn = secp256k1.Point.Fn;
const G = secp256k1.Point.BASE;
const N = Fn.ORDER;
const mod = (a: bigint) => ((a % N) + N) % N;
const scalar = (hex: string) => mod(BigInt('0x' + hex));
const hex32 = (x: bigint) => x.toString(16).padStart(64, '0');
const point = (hex: string) => secp256k1.Point.fromHex(hex);

export interface RefreshPlan {
  epoch: number;
  threshold: number;
  /** Member keys that deal: a device and a server, at least. */
  dealers: string[];
  /** Every share index that moves to the new epoch, with the member key holding it. */
  holders: { idx: number; pk: string }[];
  /** Every share's point before the refresh. Everyone starts from these, whatever it has heard since. */
  points: [number, string][];
  /** A silent periodic refresh (COSIGN.md §7.7): held as pending until a device checks it and commits. */
  periodic?: boolean;
  /** Which attempt (periodic): a dropped attempt and the next one have the same epoch. */
  id?: string;
  /**
   * Servers left out of this epoch (periodic, COSIGN.md §7.7): ones that have gone silent.
   * Their shares get no deltas, so they stop combining with anything. Each server checks
   * for itself that it has seen that silence before it takes a plan that drops one.
   */
  drop?: number[];
}

/** One dealer's part: a delta for each share, and the points of g's coefficients a1..a(t-1). */
export interface Dealt { commits: string[]; deltas: [number, string][] }

export function deal(plan: RefreshPlan): Dealt {
  const coeffs = Array.from({ length: plan.threshold - 1 }, () => mod(BigInt('0x' + bytesToHex(randomBytes(32)))) || 1n);
  const g = (x: bigint) => coeffs.reduceRight((acc, c) => mod((acc + c) * x), 0n); // a1·x + a2·x² + …, zero at 0
  return {
    commits: coeffs.map(c => G.multiply(c).toHex(true)),
    deltas: plan.holders.map(h => [h.idx, hex32(g(BigInt(h.idx)))]),
  };
}

/** g(j)·G from the commitments: Σ Ck·j^k. */
export function deltaPoint(commits: string[], j: number) {
  let acc = secp256k1.Point.ZERO, x = BigInt(j);
  for (const c of commits) { acc = acc.add(point(c).multiply(x)); x = mod(x * BigInt(j)); }
  return acc;
}

export const checkDelta = (commits: string[], j: number, delta: string) => {
  const d = scalar(delta);
  return d === 0n ? deltaPoint(commits, j).equals(secp256k1.Point.ZERO) : G.multiply(d).equals(deltaPoint(commits, j));
};

/** A share plus its deltas. */
export const addDeltas = (secret: string, deltas: string[]) => hex32(deltas.reduce((acc, d) => mod(acc + scalar(d)), scalar(secret)));

/** A share's new point: the old one plus every dealer's delta point. */
export function newPoint(oldPub: string, j: number, dealers: string[][]) {
  return dealers.reduce((acc, commits) => acc.add(deltaPoint(commits, j)), point(oldPub)).toHex(true);
}

export interface RefreshResult { epoch: number; shares: { idx: number; secret: string }[]; points: [number, string][] }

/**
 * One member's side: deal if it's a dealer, collect every dealer's part for its own
 * shares, check them, and finish with its new shares and every share's new point.
 */
export class RefreshRun {
  plan: RefreshPlan;
  done: RefreshResult | null = null;
  private me: string;
  private mine: number[];
  private shares: { idx: number; secret: string }[];
  private oldPoints: Map<number, string>;
  private got = new Map<string, { commits: string[]; deltas: Map<number, string> }>(); // dealer → its part
  private ours: Dealt | null = null;
  private send: (toPk: string, msg: object) => void;
  private onDone: (r: RefreshResult) => void;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(plan: RefreshPlan, me: string, shares: { idx: number; secret: string }[],
    send: (toPk: string, msg: object) => void, onDone: (r: RefreshResult) => void) {
    this.plan = plan; this.me = me; this.send = send; this.onDone = onDone; this.oldPoints = new Map(plan.points);
    this.mine = plan.holders.filter(h => h.pk === me).map(h => h.idx);
    this.shares = shares.filter(s => this.mine.includes(s.idx));
    // Our shares must be the ones the plan starts from.
    for (const s of this.shares) if (G.multiply(scalar(s.secret)).toHex(true) !== this.oldPoints.get(s.idx)) throw new Error('refresh: the plan doesn’t start from our shares');
    if (plan.dealers.includes(me)) {
      this.ours = deal(plan);
      this.got.set(me, { commits: this.ours.commits, deltas: new Map(this.ours.deltas.filter(([j]) => this.mine.includes(j))) });
    }
  }

  /** Every member's deltas, one message each (to be sealed to it), commitments to all. */
  outgoing(): [string, object][] {
    if (!this.ours) return [];
    const by = new Map<string, [number, string][]>();
    for (const [j, d] of this.ours.deltas) {
      const pk = this.plan.holders.find(h => h.idx === j)!.pk;
      if (pk !== this.me) by.set(pk, [...by.get(pk) ?? [], [j, d]]);
    }
    return [...by].map(([pk, deltas]) => [pk, { type: 'refresh_part', epoch: this.plan.epoch, ...(this.plan.id ? { id: this.plan.id } : {}), commits: this.ours!.commits, deltas }]);
  }

  /** Send our part now and again every 4 s until we're done (and a little after). */
  start() {
    const tick = () => { for (const [pk, m] of this.outgoing()) this.send(pk, m); };
    tick(); this.timer = setInterval(tick, 4000);
    this.finish();
  }
  stop() { clearInterval(this.timer); }

  /** A dealer's part. Anything that doesn't check out is dropped, and the run waits for a good one. */
  take(msg: any, fromPk: string) {
    // The same attempt only: a dropped periodic attempt and the next one share an epoch.
    if (msg.epoch !== this.plan.epoch || (msg.id ?? null) !== (this.plan.id ?? null) || !this.plan.dealers.includes(fromPk) || this.got.has(fromPk) || this.done) return;
    const commits: string[] = msg.commits;
    if (!Array.isArray(commits) || commits.length !== this.plan.threshold - 1) return;
    const deltas = new Map<number, string>();
    try {
      for (const [j, d] of msg.deltas ?? []) if (this.mine.includes(j) && checkDelta(commits, j, String(d))) deltas.set(j, String(d));
    } catch { return; }
    if (deltas.size !== this.mine.length) return;
    this.got.set(fromPk, { commits, deltas });
    this.finish();
  }

  private finish() {
    if (this.done || this.plan.dealers.some(d => !this.got.has(d))) return;
    const parts = this.plan.dealers.map(d => this.got.get(d)!);
    const shares = this.shares.map(s => ({ idx: s.idx, secret: addDeltas(s.secret, parts.map(p => p.deltas.get(s.idx)!)) }));
    const points: [number, string][] = this.plan.holders.map(h => [h.idx, newPoint(this.oldPoints.get(h.idx)!, h.idx, parts.map(p => p.commits))]);
    // Our new shares must make our new points, or something is off: keep the old ones.
    for (const s of shares) if (G.multiply(scalar(s.secret)).toHex(true) !== points.find(p => p[0] === s.idx)![1]) throw new Error('refresh: a new share doesn’t match its point');
    this.done = { epoch: this.plan.epoch, shares, points };
    setTimeout(() => this.stop(), 20_000);
    this.onDone(this.done);
  }
}
