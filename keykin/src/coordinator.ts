// The coordinator's side of a signing round (core §5.1–§5.4) and of a decryption (§5.5). It keeps
// its nonces in memory, computes its shares at most once per nonce, checks every partial against
// `P_i^S`, names the member whose partial fails, and checks the result as plain BIP-340.

import { bytesToHex, randomBytes, sha, concatBytes, hexToBytes, utf8ToBytes, refuse, KeykinError } from './bytes.ts';
import { eventId, type NostrEvent, type Unsigned } from './event.ts';
import { commit, signShare, verifyShare, aggregate, hedge, type SignCommit, type Nonces } from './frost.ts';
import { checkEcdhAnswers, ownPart, sumPoints, type EcdhAnswer } from './ecdh.ts';
import type { Commitment } from './curve.ts';
import type { Approval } from './types.ts';
import type { Cls } from './lifetimes.ts';

export interface Signer { key: string; indices: number[] }
export interface RoundContext { g: string; epochId: string; state: string; C: Commitment }

const newId = () => bytesToHex(randomBytes(16));
const u32s = (xs: number[]) => concatBytes(...xs.map((x) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, x); return b; }));

/** One-call round (§5.1): a request to one co-signer, with this coordinator's commitments. */
export class OneCall {
  readonly id = newId();
  readonly request: any;
  readonly eventId: string;
  #nonces: Nonces[];
  #shares: Map<number, bigint>;
  #ctx: RoundContext;
  #co: Signer;
  readonly event: Unsigned;
  constructor(ctx: RoundContext, me: { indices: number[]; shares: Map<number, bigint> }, co: Signer, event: Unsigned, extra: { approval?: Approval; hold?: string; cls?: Cls } = {}) {
    if (event.pubkey !== ctx.g) refuse('wrong_pubkey');
    this.#ctx = ctx; this.#co = co; this.#shares = me.shares; this.event = event;
    this.eventId = eventId(event);
    const signers = [...me.indices, ...co.indices].sort((a, b) => a - b);
    const context = concatBytes(hexToBytes(this.eventId), u32s(signers), hexToBytes(this.id), hexToBytes(co.key));
    const cs = me.indices.map((i) => commit(ctx.C, i, me.shares.get(i)!, hedge(me.shares.get(i)!, context)));
    this.#nonces = cs.map((c) => c.nonces);
    this.request = { v: 1, type: 'sign', g: ctx.g, epoch: ctx.epochId, id: this.id, cls: extra.cls ?? 'sign', state: ctx.state, event,
      signers, commitments: cs.map((c) => c.commit), ...(extra.approval ? { approval: extra.approval } : {}), ...(extra.hold ? { hold: extra.hold } : {}) };
  }
  /** Finish with the co-signer's `partial`: the signed event, or a refusal naming the member. */
  finish(partial: any): NostrEvent {
    if (partial?.type !== 'partial') throw new KeykinError(partial?.code ?? 'no_partial', `from ${this.#co.key.slice(0, 8)}`);
    const theirs: SignCommit[] = partial.commitments ?? [];
    if (JSON.stringify(theirs.map((c) => c.i).sort()) !== JSON.stringify([...this.#co.indices].sort())) refuse('bad_partial', `member ${this.#co.key}`);
    const commits = [...this.request.commitments, ...theirs];
    const mine = this.#nonces.map((n) => ({ i: n.i, z: signShare(this.#ctx.C, n.i, this.#shares.get(n.i)!, n, this.eventId, commits) }));
    for (const z of partial.z ?? []) if (!verifyShare(this.#ctx.C, this.eventId, commits, z.i, z.z)) refuse('bad_partial', `member ${this.#co.key}`);
    if ((partial.z ?? []).length !== this.#co.indices.length) refuse('bad_partial', `member ${this.#co.key}`);
    const sig = aggregate(this.#ctx.C, this.eventId, commits, [...mine, ...partial.z]);
    return { ...this.event, id: this.eventId, sig };
  }
  /** Discard the nonces (another co-signer answered first, §5.1). */
  abandon() { for (const n of this.#nonces) if (!n.used) n.take(); }
}

/** Two-call round (§5.1), for rounds with more than one co-signer (a recovery round). */
export class TwoCall {
  readonly commitId = newId();
  readonly signId = newId();
  readonly eventId: string;
  readonly signers: number[];
  #nonces: Nonces[]; #shares: Map<number, bigint>; #ctx: RoundContext; #cos: Signer[]; #mine: SignCommit[];
  #theirs = new Map<string, SignCommit[]>();
  readonly event: Unsigned;
  constructor(ctx: RoundContext, me: { key: string; indices: number[]; shares: Map<number, bigint> }, cos: Signer[], event: Unsigned) {
    this.#ctx = ctx; this.#cos = cos; this.#shares = me.shares; this.event = event;
    this.eventId = eventId(event);
    this.signers = [...me.indices, ...cos.flatMap((c) => c.indices)].sort((a, b) => a - b);
    const context = concatBytes(hexToBytes(this.eventId), u32s(this.signers), hexToBytes(this.commitId), utf8ToBytes('two-call'));
    const cs = me.indices.map((i) => commit(ctx.C, i, me.shares.get(i)!, hedge(me.shares.get(i)!, context)));
    this.#nonces = cs.map((c) => c.nonces); this.#mine = cs.map((c) => c.commit);
  }
  commitRequest(cls: Cls = 'ask') { return { v: 1, type: 'commit', g: this.#ctx.g, epoch: this.#ctx.epochId, id: this.commitId, cls, state: this.#ctx.state, signers: this.signers, event: this.event }; }
  took(co: string, answer: any) {
    if (answer?.type !== 'commitments') throw new KeykinError(answer?.code ?? 'no_commitments', co);
    this.#theirs.set(co, answer.commitments);
  }
  get commitments(): SignCommit[] { return [...this.#mine, ...this.#cos.flatMap((c) => this.#theirs.get(c.key) ?? [])]; }
  signRequest(cls: Cls = 'ask', extra: { approval?: Approval } = {}) {
    return { v: 1, type: 'sign', g: this.#ctx.g, epoch: this.#ctx.epochId, id: this.signId, cls, state: this.#ctx.state, event: this.event,
      signers: this.signers, commitments: this.commitments, after: this.commitId, ...extra };
  }
  finish(partials: Map<string, any>): NostrEvent {
    const commits = this.commitments;
    const zs: { i: number; z: string }[] = [];
    for (const co of this.#cos) {
      const p = partials.get(co.key);
      if (p?.type !== 'partial') refuse(p?.code ?? 'no_partial', `member ${co.key}`);
      for (const z of p.z) { if (!co.indices.includes(z.i) || !verifyShare(this.#ctx.C, this.eventId, commits, z.i, z.z)) refuse('bad_partial', `member ${co.key}`); zs.push(z); }
    }
    for (const n of this.#nonces) zs.push({ i: n.i, z: signShare(this.#ctx.C, n.i, this.#shares.get(n.i)!, n, this.eventId, commits) });
    return { ...this.event, id: this.eventId, sig: aggregate(this.#ctx.C, this.eventId, commits, zs) };
  }
}

/** A decryption request (§5.5) and the coordinator's own part. */
export function ecdhRequest(ctx: RoundContext, myIndices: number[], co: Signer, points: string[]) {
  const signers = [...myIndices, ...co.indices].sort((a, b) => a - b);
  return { v: 1, type: 'ecdh', g: ctx.g, epoch: ctx.epochId, id: newId(), cls: 'sign', state: ctx.state, points, signers };
}
/** `x·Q` for each point, from the co-signer's checked answer and this device's own shares. */
export function ecdhFinish(ctx: RoundContext, req: any, me: { indices: number[]; shares: Map<number, bigint> }, co: Signer, answer: any): string[] {
  if (answer?.type !== 'ecdh_partial') refuse(answer?.code ?? 'no_answer', `member ${co.key}`);
  checkEcdhAnswers({ g: ctx.g, epochId: ctx.epochId, state: ctx.state, signers: req.signers }, ctx.C, req.points, co.indices, answer.answers);
  return req.points.map((Q: string, q: number) => {
    let acc = sumPoints(answer.answers[q].map((a: EcdhAnswer) => a.Y));
    for (const i of me.indices) acc = acc.add(ownPart(req.signers, i, me.shares.get(i)!, Q));
    return acc.toHex(true);
  });
}
export { sha };
