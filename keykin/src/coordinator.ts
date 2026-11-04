// The coordinator's side of a signing round (core §5.1–§5.4) and of a decryption (§5.5). It keeps
// its nonces in memory, computes its shares at most once per nonce, checks every partial against
// `P_i^S`, names the member whose partial fails, and checks the result as plain BIP-340.

import { bytesToHex, randomBytes, sha, concatBytes, hexToBytes, utf8ToBytes, refuse, KeykinError } from './bytes.ts';
import { eventId, wireEvent, type NostrEvent, type Unsigned } from './event.ts';
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
  constructor(ctx: RoundContext, me: { indices: number[]; shares: Map<number, bigint> }, co: Signer, event: Unsigned, extra: { approval?: Approval; hold?: string; cls?: Cls; list_events?: NostrEvent[]; material?: unknown } = {}) {
    if (event.pubkey !== ctx.g) refuse('wrong_pubkey');
    this.#ctx = ctx; this.#co = co; this.#shares = me.shares; this.event = event;
    this.eventId = eventId(event);
    const signers = [...me.indices, ...co.indices].sort((a, b) => a - b);
    const context = concatBytes(hexToBytes(this.eventId), u32s(signers), hexToBytes(this.id), hexToBytes(co.key));
    const cs = me.indices.map((i) => commit(ctx.C, i, me.shares.get(i)!, hedge(me.shares.get(i)!, context)));
    this.#nonces = cs.map((c) => c.nonces);
    this.request = { v: 1, type: 'sign', g: ctx.g, epoch: ctx.epochId, id: this.id, cls: extra.cls ?? 'sign', state: ctx.state, event: wireEvent(event),
      signers, commitments: cs.map((c) => c.commit), ...(extra.approval ? { approval: extra.approval } : {}), ...(extra.hold ? { hold: extra.hold } : {}), ...(extra.list_events ? { list_events: extra.list_events } : {}), ...(extra.material ? { material: extra.material } : {}) };
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

/** One-call round for a whole list (§6.7.10): every event in one `sign`, each with its own nonces. */
export class ListCall {
  readonly id = newId();
  readonly request: any;
  readonly events: Unsigned[];
  #ids: string[]; #nonces: Nonces[][]; #shares: Map<number, bigint>; #ctx: RoundContext; #co: Signer;
  constructor(ctx: RoundContext, me: { indices: number[]; shares: Map<number, bigint> }, co: Signer, events: Unsigned[], extra: { material?: unknown; cls?: Cls } = {}) {
    if (events.some((e) => e.pubkey !== ctx.g)) refuse('wrong_pubkey');
    this.#ctx = ctx; this.#co = co; this.#shares = me.shares; this.events = events;
    this.#ids = events.map(eventId);
    const signers = [...me.indices, ...co.indices].sort((a, b) => a - b);
    const cs = this.#ids.map((evId) => me.indices.map((i) => commit(ctx.C, i, me.shares.get(i)!,
      hedge(me.shares.get(i)!, concatBytes(hexToBytes(evId), u32s(signers), hexToBytes(this.id), hexToBytes(co.key))))));
    this.#nonces = cs.map((x) => x.map((c) => c.nonces));
    this.request = { v: 1, type: 'sign', g: ctx.g, epoch: ctx.epochId, id: this.id, cls: extra.cls ?? 'ask', state: ctx.state, signers,
      list_events: events.map((event, e) => ({ event: wireEvent(event), commitments: cs[e].map((c) => c.commit) })), ...(extra.material ? { material: extra.material } : {}) };
  }
  finish(partial: any): NostrEvent[] {
    if (partial?.type !== 'partial' || !Array.isArray(partial.events) || partial.events.length !== this.events.length)
      throw new KeykinError(partial?.code ?? 'no_partial', `from ${this.#co.key.slice(0, 8)}`);
    return this.events.map((ev, e) => {
      const theirs: SignCommit[] = partial.events[e].commitments ?? [];
      const zs = partial.events[e].z ?? [];
      const want = JSON.stringify([...this.#co.indices].sort((a, b) => a - b));
      if (JSON.stringify(theirs.map((c) => c.i).sort((a, b) => a - b)) !== want || JSON.stringify(zs.map((z: any) => z.i).sort((a: number, b: number) => a - b)) !== want) refuse('bad_partial', `member ${this.#co.key}`);
      const commits = [...this.request.list_events[e].commitments, ...theirs];
      for (const z of zs) if (!verifyShare(this.#ctx.C, this.#ids[e], commits, z.i, z.z)) refuse('bad_partial', `member ${this.#co.key}`);
      const mine = this.#nonces[e].map((n) => ({ i: n.i, z: signShare(this.#ctx.C, n.i, this.#shares.get(n.i)!, n, this.#ids[e], commits) }));
      return { ...ev, id: this.#ids[e], sig: aggregate(this.#ctx.C, this.#ids[e], commits, [...mine, ...zs]) };
    });
  }
  abandon() { for (const ns of this.#nonces) for (const n of ns) if (!n.used) n.take(); }
}

/** Two-call round (§5.1), for rounds with more than one co-signer (a recovery round). Several
 *  events (a list) take one commitment set each (`commit {count}`, §6.7.10). */
export class TwoCall {
  readonly commitId = newId();
  readonly signId = newId();
  readonly eventId: string;
  readonly signers: number[];
  readonly events: Unsigned[];
  #ids: string[];
  #nonces: Nonces[][]; #shares: Map<number, bigint>; #ctx: RoundContext; #cos: Signer[]; #mine: SignCommit[][];
  #theirs = new Map<string, SignCommit[][]>();
  readonly event: Unsigned;
  constructor(ctx: RoundContext, me: { key: string; indices: number[]; shares: Map<number, bigint> }, cos: Signer[], event: Unsigned | Unsigned[]) {
    this.#ctx = ctx; this.#cos = cos; this.#shares = me.shares;
    this.events = Array.isArray(event) ? event : [event];
    this.event = this.events[0];
    this.#ids = this.events.map(eventId);
    this.eventId = this.#ids[0];
    this.signers = [...me.indices, ...cos.flatMap((c) => c.indices)].sort((a, b) => a - b);
    const sets = this.#ids.map((evId) => me.indices.map((i) => commit(ctx.C, i, me.shares.get(i)!,
      hedge(me.shares.get(i)!, concatBytes(hexToBytes(evId), u32s(this.signers), hexToBytes(this.commitId), utf8ToBytes('two-call'))))));
    this.#nonces = sets.map((x) => x.map((c) => c.nonces)); this.#mine = sets.map((x) => x.map((c) => c.commit));
  }
  get isList() { return this.events.length > 1; }
  commitRequest(cls: Cls = 'ask') {
    return { v: 1, type: 'commit', g: this.#ctx.g, epoch: this.#ctx.epochId, id: this.commitId, cls, state: this.#ctx.state, signers: this.signers,
      ...(this.isList ? { count: this.events.length } : { event: wireEvent(this.event) }) };
  }
  took(co: string, answer: any) {
    if (answer?.type !== 'commitments') throw new KeykinError(answer?.code ?? 'no_commitments', co);
    this.#theirs.set(co, this.isList ? answer.sets : [answer.commitments]);
  }
  commitmentsFor(e: number): SignCommit[] { return [...this.#mine[e], ...this.#cos.flatMap((c) => this.#theirs.get(c.key)?.[e] ?? [])]; }
  get commitments(): SignCommit[] { return this.commitmentsFor(0); }
  signRequest(cls: Cls = 'ask', extra: { approval?: Approval; material?: unknown } = {}) {
    const base = { v: 1, type: 'sign', g: this.#ctx.g, epoch: this.#ctx.epochId, id: this.signId, cls, state: this.#ctx.state, signers: this.signers, after: this.commitId, ...extra };
    return this.isList ? { ...base, list_events: this.events.map((event, e) => ({ event: wireEvent(event), commitments: this.commitmentsFor(e) })) }
      : { ...base, event: wireEvent(this.event), commitments: this.commitments };
  }
  finishAll(partials: Map<string, any>): NostrEvent[] {
    return this.events.map((ev, e) => {
      const commits = this.commitmentsFor(e);
      const zs: { i: number; z: string }[] = [];
      for (const co of this.#cos) {
        const p = partials.get(co.key);
        if (p?.type !== 'partial') refuse(p?.code ?? 'no_partial', `member ${co.key}`);
        const mineZ = this.isList ? p.events?.[e]?.z : p.z;
        const got = (mineZ ?? []).map((z: any) => z.i).sort((a: number, b: number) => a - b);
        if (JSON.stringify(got) !== JSON.stringify([...co.indices].sort((a, b) => a - b))) refuse('bad_partial', `member ${co.key}`);
        for (const z of mineZ) { if (!verifyShare(this.#ctx.C, this.#ids[e], commits, z.i, z.z)) refuse('bad_partial', `member ${co.key}`); zs.push(z); }
      }
      for (const n of this.#nonces[e]) zs.push({ i: n.i, z: signShare(this.#ctx.C, n.i, this.#shares.get(n.i)!, n, this.#ids[e], commits) });
      return { ...ev, id: this.#ids[e], sig: aggregate(this.#ctx.C, this.#ids[e], commits, zs) };
    });
  }
  finish(partials: Map<string, any>): NostrEvent { return this.finishAll(partials)[0]; }
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
