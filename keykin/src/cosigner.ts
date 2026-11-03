// A co-signer (core §5.7): every check before it gives a partial, plus the waits it runs (§5.8,
// §6.3, §6.5). A server runs one per account; a device runs one too when another device-class
// member asks it, adding its own policy. Storage (deliveries, inboxes, the change set) is the
// host's; this class keeps only what Core says a co-signer keeps, and takes the clock as input.

import { bytesToHex, randomBytes, sha, jcsBytes, hexN, refuse, KeykinError } from './bytes.ts';
import { holdWaitId, recoveryWaitId, what, detachedDigest, stateHash, signpostD, signpostH } from './codes.ts';
import { checkLifetime, bodyHash, ReplayCache, type Cls } from './lifetimes.ts';
import { futureDateOk, destructive, deletionTargets, BurstCounter, type Ev } from './destructive.ts';
import { commit, signShare, hedge, type SignCommit, type Nonces } from './frost.ts';
import { ecdhAnswer } from './ecdh.ts';
import { checkAssertion } from './lock.ts';
import { eventId, schnorrVerify, tag, type KeyPair, type NostrEvent, type Unsigned } from './event.ts';
import { checkApproval, approvalType, checkWaited, signWaited, changeWhat, MAX_EXPIRY_S, W_DEFAULT } from './approval.ts';
import { computeMembership, parseChange, type Membership } from './membership.ts';
import { pointFrom, commitmentFrom, type Commitment } from './curve.ts';
import { stateOf, commitmentAt, type State } from './redeal.ts';
import { verifyRerepair, redealMissing, postListView, type Upload } from './upkeep.ts';
import { itemHash } from './redeal.ts';
import { takenIndices } from './membership.ts';
import { jcs } from './bytes.ts';
import { KIND_CHANGE, KIND_EPOCH, KIND_SIGNPOST, type EpochContent, type MemberEntry, type Waited } from './types.ts';

export const NONCE_TTL_S = 120;
export const SESSION_S = 7 * 86400;
export const MAX_HOLDS = 10;
export const STATEMENT_MAX_AGE_S = 7 * 86400;

export interface Hold { wait: string; eventId: string; device: string; start: number; end: number; cancelled: boolean }
export interface Recovery { wait: string; backup: string; r: string; start: number; end: number; cancelled: boolean; withdrawn: boolean }

export interface CoSignerOpts {
  me: KeyPair; host?: KeyPair; kind: 'server' | 'device' | 'helper';
  now: () => number; W?: number;
  record: EpochContent; state: State; changes?: NostrEvent[];
  /** A device co-signer's own destructive policy (Device policy module): may ask its person. */
  policy?: (event: Unsigned, from: string) => boolean;
  /** Upkeep duties a host adds before co-signing a redeal or seat change (§6.7.3). Throws to refuse. */
  upkeep?: (parsed: ReturnType<typeof parseChange>, m: Membership) => void;
  /** A server's upload store (§6.7.3): required for `kind: 'server'`, so a redeal is never
   *  co-signed without its deliveries held. */
  uploads?: { get(redealId: string): Upload | undefined; liveSeatHolders(view: Map<string, MemberEntry>): number };
}

const ERR = (re: string, code: string) => ({ v: 1, type: 'error', re, code });

export class CoSigner {
  o: CoSignerOpts;
  m: Membership;
  state: State;
  changes: NostrEvent[];
  replay = new ReplayCache();
  burst = new BurstCounter();
  holds = new Map<string, Hold>();
  recoveries = new Map<string, Recovery>();
  challenges = new Map<string, { exp: number; to: string }>();   // challenge hex → expiry, and who asked
  signpostIds = new Set<string>();
  #twoCall = new Map<string, { nonces: Nonces[]; mine: SignCommit[]; at: number; used: boolean; from: string; signers: number[] }>();

  constructor(o: CoSignerOpts) {
    this.o = o; this.state = o.state; this.changes = o.changes ?? [];
    this.m = computeMembership(o.record, this.changes, o.W ?? W_DEFAULT);
  }
  get W() { return this.o.W ?? W_DEFAULT; }
  get g() { return this.o.record.g; }
  get myIndices() { return [...this.state.shares.keys()].sort((a, b) => a - b); }

  /** Take changes (a delivery, `changes`, a catch-up union): the membership is recomputed. */
  addChanges(evs: NostrEvent[]) {
    const ids = new Set(this.changes.map((e) => e.id));
    const next = [...this.changes, ...evs.filter((e) => !ids.has(e.id))];
    const m = computeMembership(this.o.record, next, this.W);
    // A member refuses to adopt a view that breaks an invariant (§3.3), and shows it.
    if (m.invariantError) { this.refusedBatches.push({ events: evs, why: m.invariantError }); return false; }
    this.changes = next; this.m = m;
    return true;
  }
  refusedBatches: { events: NostrEvent[]; why: string }[] = [];
  setState(s: State) { this.state = s; }

  /** Use up a challenge this co-signer issued to `to` (one of `to`), if fresh (§6.1, §6.5). */
  takeChallenge(c: string, to: string | string[], now = this.o.now()): boolean {
    const x = this.challenges.get(c);
    if (!x || x.exp < now || !(Array.isArray(to) ? to : [to]).includes(x.to)) return false;
    this.challenges.delete(c);
    return true;
  }

  /** May this member help repair `participant` for `seal_to` (§4.2 step 3, §4.4, §6.7.4)? Throws if not.
   *  The sigma always goes to the index's assigned owner, never to whoever asks. */
  answeredRepair = new Set<string>();
  authorizeRepair(from: string, body: { participant: number; seal_to: string; why: string; state: string; proof?: any }, now = this.o.now()) {
    const m = this.m;
    if (body.state !== stateOf(this.state)) refuse('stale');
    const p = body.participant;
    if (m.record.seats.backup.includes(p)) refuse('backup_seat', 'never repaired by need_repair or a join');
    const owner = [...m.members.values()].find((x) => x.shares.includes(p));
    if (!owner || m.removed.has(owner.key) || owner.kind === 'backup') refuse('not_assigned', 'no valid change assigns this index');
    if (body.seal_to !== owner!.key) refuse('not_assigned', 'a repair is sealed only to the index\'s owner');
    const requester = this.m.members.get(from);
    switch (body.why) {
      case 'add': {
        // A join: the inviting device, or the backup holder in a recovery session (§4.4).
        if (owner!.kind !== 'device' || !m.accepted.some((x) => x.type === 'add' && (x.c.change as any).add.key === owner!.key)) refuse('not_assigned');
        const okFrom = (requester?.kind === 'device' && from !== owner!.key) || (requester?.kind === 'backup' && this.session(now)?.backup === from);
        if (!okFrom) refuse('not_inviter');
        break;
      }
      case 'seat': {
        // `need_repair`: the seat's current holder asks, or a current device fills the seat in the
        // foreground (F1); either way the sigma is sealed to the holder. Once per key and index.
        if (!['server', 'helper'].includes(owner!.kind)) refuse('not_assigned');
        if (from !== owner!.key && !(requester?.kind === 'device')) refuse('not_assigned');
        if (this.answeredRepair.has(`${owner!.key}:${p}`)) refuse('already_answered');
        break;
      }
      case 'rerepair': {
        // The owner proves its share at an earlier state of its own chain, over a challenge issued to it.
        const pr = body.proof;
        if (!pr || !this.takeChallenge(pr.challenge, owner!.key, now)) refuse('stale_challenge');
        const oldIds = new Set<string>(pr.state ?? []);
        if ([...oldIds].some((i) => !m.redeals.has(i))) refuse('unknown_state');
        const C = commitmentAt(commitmentFrom(m.record.commitment), [...m.redeals.values()].filter((x) => oldIds.has(x.r.id)).map((x) => x.r));
        if (pr.proof?.i !== p || !verifyRerepair(m.g, owner!.key, C, pr.challenge, pr.proof)) refuse('bad_proof');
        if (!requester || requester.kind === 'backup') refuse('not_member');
        break;
      }
      default: refuse('bad_repair');
    }
  }
  /** A `need_repair` answer that succeeded uses up the server's one answer (§6.7.4). */
  repairSucceeded(owner: string, index: number) { this.answeredRepair.add(`${owner}:${index}`); }

  /** The current signpost's event id (§6.7.5), from co-signing it or from a welcome: its delete is refused. */
  noteSignpost(id: string) { this.signpostIds.add(id); }

  /** What a server keeps across a restart (§2, §5.6): answered ids, waits, cancels, challenges.
   *  Never nonces: a restart loses every round in flight (§5.2). Shares are the host's to store. */
  snapshot() {
    return JSON.stringify({ replay: this.replay.dump(), holds: [...this.holds.values()], recoveries: [...this.recoveries.values()],
      cancels: this.cancels, challenges: [...this.challenges], signposts: [...this.signpostIds] });
  }
  restore(json: string) {
    const x = JSON.parse(json);
    this.replay.load(x.replay);
    this.holds = new Map(x.holds.map((h: Hold) => [h.wait, h]));
    this.recoveries = new Map(x.recoveries.map((r: Recovery) => [r.wait, r]));
    this.cancels = x.cancels; this.cancelledWaits = new Set(x.cancels.map((c: any) => c.wait));
    this.challenges = new Map(x.challenges); this.signpostIds = new Set(x.signposts);
  }

  /** A recovery session for the current backup key: open from the end of its wait for 7 days. */
  session(now = this.o.now()): Recovery | null {
    for (const r of this.recoveries.values())
      if (!r.cancelled && !r.withdrawn && r.backup === this.m.backupKey && r.end <= now && now <= r.end + SESSION_S) return r;
    return null;
  }
  /** A recovery wait or session in progress freezes holds and new notice channels (§6.3). */
  frozen(now = this.o.now()) {
    return [...this.recoveries.values()].some((r) => !r.cancelled && !r.withdrawn && r.backup === this.m.backupKey && now <= r.end + SESSION_S);
  }

  /** Handle one request from `from` (the seal's key). `sentAt` is the rumor's `created_at`. */
  handle(from: string, msg: any, sentAt: number, meta: { inboxAge?: number } = {}): any {
    const now = this.o.now();
    const id = typeof msg?.id === 'string' && /^[0-9a-f]{32}$/.test(msg.id) ? msg.id : '';
    if (!id || msg.v !== 1) return ERR(id, 'malformed');
    if (msg.g !== this.g) return ERR(id, 'wrong_group');
    if (msg.epoch !== this.m.epochId) return ERR(id, 'wrong_epoch');
    if (typeof msg.type !== 'string' || !Object.hasOwn(this.handlers, msg.type)) return ERR(id, 'unsupported');
    const life = checkLifetime(msg.type, msg.cls, sentAt, now, meta.inboxAge ?? 0);
    if (life) return ERR(id, life);
    const hash = bodyHash(msg);
    const seen = this.replay.check(from, id, hash, now);
    if ('answer' in seen) return seen.answer;
    if ('reused' in seen) return ERR(id, 'id_reused');
    if ('full' in seen) return ERR(id, 'too_many_requests');
    this.replay.claim(from, id, hash, msg.cls as Cls, now, sentAt);
    let answer: any;
    try { answer = (this.handlers as any)[msg.type].call(this, from, msg, now); }
    catch (e) { answer = ERR(id, e instanceof KeykinError ? e.code : 'internal'); (answer as any).detail = String((e as Error).message ?? e); }
    this.replay.answer(from, id, answer);
    return answer;
  }

  private sender(from: string): MemberEntry {
    if (this.m.removed.has(from)) refuse('removed');
    const s = this.m.members.get(from);
    if (!s) refuse('not_member');
    return s!;
  }

  handlers = {
    sign(this: CoSigner, from: string, msg: any, now: number) { return this.sign(from, msg, now); },
    commit(this: CoSigner, from: string, msg: any, now: number) { return this.commitTwoCall(from, msg, now); },
    ecdh(this: CoSigner, from: string, msg: any, now: number) { return this.ecdh(from, msg, now); },
    hold(this: CoSigner, from: string, msg: any, now: number) { return this.hold(from, msg, now); },
    cancel(this: CoSigner, from: string, msg: any, now: number) { return this.cancel(from, msg, now); },
    withdraw(this: CoSigner, from: string, msg: any) { return this.withdraw(from, msg); },
    challenge(this: CoSigner, from: string, msg: any, now: number) { return this.challenge(from, msg, now); },
    release_request(this: CoSigner, from: string, msg: any, now: number) { return this.releaseRequest(from, msg, now); },
    state_get(this: CoSigner, _from: string, msg: any) { return { v: 1, type: 'state', re: msg.id, ids: [...this.state.ids].sort() }; },
  };

  private stale(msg: any) {
    return msg.state !== stateOf(this.state) ? { v: 1, type: 'stale', re: msg.id, ids: [...this.state.ids].sort() } : null;
  }

  /** §5.7 item 1 and the I4 rule: who may coordinate this round. */
  private coordinator(from: string, participants: MemberEntry[], now: number): 'everyday' | 'recovery' {
    const s = this.sender(from);
    const deviceClass = participants.some((p) => p.kind === 'device' || p.kind === 'helper');
    if (s.kind === 'device' || s.kind === 'helper') return 'everyday';
    if (s.kind === 'backup' && !deviceClass) {
      const sess = this.session(now);
      if (!sess || sess.backup !== from) refuse('no_recovery_session');
      return 'recovery';
    }
    return refuse('not_coordinator');
  }

  /** §5.7 item 2: `signers` is exactly the participants' indices, at least 4. */
  private participants(signers: unknown, from: string, twoCall = false): MemberEntry[] {
    if (!Array.isArray(signers) || signers.some((i) => !Number.isSafeInteger(i))) refuse('bad_signers');
    const owner = new Map<number, MemberEntry>();
    for (const m of this.m.members.values()) for (const i of m.shares) owner.set(i, m);
    const parts = new Map<string, MemberEntry>();
    for (const i of signers as number[]) {
      const m = owner.get(i);
      if (!m) refuse('bad_signers', `index ${i} is no current member's`);
      parts.set(m!.key, m!);
    }
    if (!parts.has(from) || !parts.has(this.o.me.pub)) refuse('bad_signers', 'must include the sender and this co-signer');
    if (!twoCall && parts.size !== 2) refuse('bad_signers', 'a one-call round has exactly two participants');
    const expect = [...parts.values()].flatMap((p) => p.shares).sort((a, b) => a - b);
    const got = [...(signers as number[])].sort((a, b) => a - b);
    if (JSON.stringify(expect) !== JSON.stringify(got)) refuse('bad_signers', 'every index of every participant, once');
    if (got.length < 4) refuse('bad_signers', 'worth less than 4');
    for (const p of parts.values()) if (this.m.removed.has(p.key)) refuse('removed');
    return [...parts.values()];
  }

  private checkCommitments(cs: unknown, indices: number[]) {
    if (!Array.isArray(cs)) refuse('bad_commitments');
    const got = (cs as SignCommit[]).map((c) => c?.i).sort((a, b) => a - b);
    if (JSON.stringify(got) !== JSON.stringify([...indices].sort((a, b) => a - b))) refuse('bad_commitments', 'must cover exactly the other participants\' indices');
    for (const c of cs as SignCommit[]) { pointFrom(c.D, 'D'); pointFrom(c.E, 'E'); }
  }

  /** §5.7 items 4–7 on the event. Returns whether the event was destructive and approved by lock. */
  private checkEvent(from: string, msg: any, mode: 'everyday' | 'recovery', now: number) {
    const ev: Unsigned = msg.event;
    if (!ev || typeof ev !== 'object' || ev.pubkey !== this.g) refuse('wrong_pubkey');
    if (!Number.isSafeInteger(ev.kind) || !Number.isSafeInteger(ev.created_at) || !Array.isArray(ev.tags) || typeof ev.content !== 'string') refuse('malformed');
    const evId = eventId(ev);
    if (!futureDateOk(ev as Ev, now)) refuse('dated_ahead');
    // Account machinery (item 5).
    if (ev.kind === KIND_EPOCH) refuse('machinery', 'an epoch record is made only at creation');
    const signpostDs = new Set(this.m.backupKeys.map(signpostD));
    if (ev.kind === 5 && ev.tags.some((t) => (t[0] === 'e' && this.signpostIds.has(t[1])) || (t[0] === 'a' && [...signpostDs].some((d) => t[1] === `${KIND_SIGNPOST}:${this.g}:${d}`))))
      refuse('machinery', 'a signpost delete is always refused');
    if (ev.kind === KIND_SIGNPOST && signpostDs.has(tag(ev, 'd') ?? '')) { this.checkSignpost(from, ev); return { evId, lockApproved: false, signpost: true }; }
    if (ev.kind === KIND_CHANGE) { this.checkChangeToSign(from, ev, mode, now, msg); return { evId, lockApproved: false }; }
    if (mode === 'recovery') refuse('recovery_session', 'only recovery-approved changes in a session');
    // The stateless destructive rule (item 7).
    let lockApproved = false;
    if (destructive(ev as Ev, this.burst.recent(now))) {
      if (msg.hold !== undefined) {
        const h = this.holds.get(msg.hold);
        if (!h || h.eventId !== evId || h.cancelled || h.end > now) refuse('hold_not_passed');
      } else if (msg.approval?.lock) {
        const coord = this.m.members.get(from)!;
        if (msg.approval.lock.member !== from || !coord.lock) refuse('needs_approval');
        const e = checkAssertion(this.g, coord.lock!, what.sign(evId), msg.approval.lock.assertion);
        if (e) refuse(e);
        lockApproved = true;
      } else refuse('needs_approval');
    }
    if (this.o.policy && !this.o.policy(ev, from)) refuse('declined');
    return { evId, lockApproved };
  }

  /** §5.7 item 5 for a change: valid, fresh, and safe to add to this co-signer's membership. */
  private checkChangeToSign(from: string, ev: Unsigned, mode: 'everyday' | 'recovery', now: number, msg: any) {
    const self = { ...ev, id: eventId(ev), sig: '' } as NostrEvent;
    const p = parseChange(this.o.record, self, false);
    const a = p.c.approval;
    const t = approvalType(a);
    const { error, approvers } = checkApproval(this.m.authority, p.c.list, a);
    if (error) refuse(error);
    if (mode === 'recovery' && t !== 'recovery') refuse('recovery_session', 'only recovery-approved changes');
    // Freshness: the co-signer's job, once (§3.2).
    if (t === 'lock' || t === 'pair' || t === 'paper') {
      if (!(a.expiry! > now && a.expiry! <= now + MAX_EXPIRY_S + 30)) refuse('approval_expired');
    }
    for (const k of approvers) if (this.m.removed.has(k) || !this.m.devices.has(k)) refuse('approver_removed');
    // Only the current lock counts here (every member accepts any lock the device ever had, §3.2).
    if (t === 'lock') {
      const cur = this.m.locks.get(a.lock!.member);
      if (!cur || checkAssertion(this.g, cur, changeWhat(this.g, this.m.epochId, p.c.list, a.expiry!), a.lock!.assertion)) refuse('not_current_lock');
    }
    // A list is co-signed as one: its redeal first, then each other change with the signed redeal
    // presented beside it, so a seat or remove never applies without its redeal (§6.7.2).
    const listEvents: NostrEvent[] = [];
    if (p.type !== 'redeal' && p.c.list.some((x) => 'redeal' in x)) {
      const rd = (msg.list_events ?? []).find((e: NostrEvent) => {
        try { const q = parseChange(this.o.record, e); return q.type === 'redeal' && q.listHash === p.listHash; } catch { return false; }
      });
      if (!rd) refuse('list_redeal_first', 'present the co-signed redeal of this list');
      listEvents.push(rd);
    }
    if (t === 'paper') {
      if (a.paper!.backup !== this.m.backupKey) refuse('not_current_backup');
      if (a.paper!.server !== (this.o.host?.pub ?? this.o.me.pub)) refuse('wrong_challenge_server');
      if (!this.takeChallenge(a.paper!.challenge, [a.paper!.member, a.paper!.backup], now)) refuse('stale_challenge');
    }
    if (t === 'recovery') {
      const r = a.recovery!;
      if (r.backup !== this.m.backupKey || from !== r.backup) refuse('not_holder', 'recovery approvals come only from the holder\'s own connection');
      const sess = this.session(now);
      if (!sess || sess.backup !== from) refuse('no_recovery_session');
      if (r.waited.some((w: Waited) => now > w.end + STATEMENT_MAX_AGE_S)) refuse('statement_too_old');
    }
    // The change must leave a valid membership: try it (§3.3).
    const ch: any = p.c.change;
    const trial = computeMembership(this.o.record, [...this.changes, ...listEvents], this.W, [self]);
    if (trial.refused.some((x) => x.id === self.id)) refuse(trial.refused.find((x) => x.id === self.id)!.code);
    if (trial.invariantError) refuse('invariant', trial.invariantError);
    const leaving = new Set<string>(p.c.list.flatMap((x: any) => ('remove' in x ? [x.remove] : 'seat' in x ? [this.m.seats.get(x.seat.seat)?.holder?.key ?? ''] : 'paper' in x ? [x.paper.replaces] : [])));
    for (const k of this.m.members.keys()) if (!trial.members.has(k) && !leaving.has(k)) refuse('invariant', 'the change would drop a member it does not name');
    switch (p.type) {
      case 'add': {
        if (this.m.removed.has(ch.add.key) || this.m.members.has(ch.add.key)) refuse('key_removed');
        const taken = takenIndices(this.m);
        if (trial.voidAdds.has(ch.add.key) || trial.members.get(ch.add.key)?.shares.some((i) => taken.has(i))) refuse('index_taken');
        break;
      }
      case 'remove': {
        if (!this.m.devices.has(ch.remove)) refuse('remove_not_device');
        if (ch.to !== undefined && (!this.m.devices.has(ch.to) || ch.to === ch.remove)) refuse('bad_self_remove');
        break;
      }
      case 'lock': {
        if (!this.m.devices.has(ch.lock.member)) refuse('not_member');
        const cur = this.m.locks.get(ch.lock.member)?.pub ?? null;
        if (ch.lock.replaces !== cur && !(cur === null && String(ch.lock.replaces).startsWith('void:'))) refuse('lock_conflict', 'replaces is not the current lock');
        if (jcs(trial.locks.get(ch.lock.member)) !== jcs(ch.lock.new)) refuse('lock_conflict');
        break;
      }
      case 'seat': {
        const cur = this.m.seats.get(ch.seat.seat);
        const holder = cur?.holder?.key ?? null;
        const okReplaces = ch.seat.replaces === holder || (holder === null && cur!.voided.some((v) => ch.seat.replaces === `void:${v}`)) || (holder === null && !cur!.voided.length && ch.seat.replaces === null);
        if (!okReplaces) refuse('seat_conflict', 'replaces is not the current holder');
        const n = ch.seat.new;
        if (n) {
          const hosts = [...this.m.members.values()].map((x) => x.host).filter(Boolean);
          if (this.m.members.has(n.key) || this.m.removed.has(n.key) || hosts.includes(n.host)) refuse('invariant', 'I7');
        }
        // The new server's host-signed enroll reply is the Server profile module's (not checked here).
        break;
      }
      case 'paper': {
        if (ch.paper.replaces !== this.m.backupKey) refuse('not_current_backup');
        if (this.m.members.has(ch.paper.key) || this.m.removed.has(ch.paper.key)) refuse('invariant', 'a paper key is a fresh key');
        // The base material item travels with the request: its hash is `inner`, signed by K (§6.7.3).
        const it = msg.material;
        if (!it || itemHash(it) !== ch.paper.inner || it.to !== ch.paper.key || !schnorrVerify(it.sig, sha(itemHash(it)), ch.paper.key)) refuse('bad_material');
        break;
      }
      case 'redeal': {
        const r = ch.redeal;
        if (r.abandons.some((x: string) => this.m.redeals.get(x)?.withRemove)) refuse('abandons_remove_redeal');
        if (r.base.some((b: string) => this.m.abandoned.has(b))) refuse('abandoned');
        if (this.m.abandoned.has(r.id)) refuse('abandoned');
        if (this.o.kind === 'server') {
          if (!this.o.uploads) refuse('no_upload_store');
          const view = postListView(this.m, p.c.list);
          const missing = redealMissing(this.m, p.c.list, r, this.o.uploads!.get(r.id), this.o.uploads!.liveSeatHolders(view));
          if (missing.length) refuse('missing', missing.join(','));
        }
        break;
      }
    }
    this.o.upkeep?.(p, this.m);
  }

  /** §6.7.5: a signpost only from a device, with the right `n` and an `h` matching this view. */
  private checkSignpost(from: string, ev: Unsigned) {
    if (!this.m.devices.has(from)) refuse('machinery', 'signposts come from devices');
    const n = Number(tag(ev, 'n'));
    const count = this.m.accepted.filter((p) => p.type === 'seat' || p.type === 'paper').length;
    if (n !== count) refuse('signpost_n');
    const servers = [...this.m.seats.entries()].filter(([k, s]) => k.startsWith('server:') && s.holder).map(([, s]) => ({ host: s.holder!.host, https: s.holder!.https, relays: s.holder!.relays ?? [] }));
    if (tag(ev, 'h') !== signpostH(this.m.epochId, servers)) refuse('signpost_h');
  }

  private sign(from: string, msg: any, now: number) {
    this.sender(from);
    const st = this.stale(msg); if (st) return st;
    const twoCall = msg.after !== undefined;
    const parts = this.participants(msg.signers, from, twoCall);
    const mode = this.coordinator(from, parts, now);
    const mine = this.myIndices;
    let nonces: Nonces[], myCommits: SignCommit[];
    if (!twoCall) {
      this.checkCommitments(msg.commitments, this.m.members.get(from)!.shares);
      if (mode === 'recovery') refuse('two_call', 'a recovery round has more than one co-signer');
    } else {
      const k = `${from}:${msg.after}`;
      const kept = this.#twoCall.get(k);
      if (!kept || now - kept.at > NONCE_TTL_S) refuse('unknown_after');
      if (kept!.used) refuse('after_used');
      kept!.used = true;
      this.checkCommitments(msg.commitments, msg.signers);
      if (JSON.stringify(kept!.signers) !== JSON.stringify(msg.signers)) refuse('bad_signers', 'differs from the commit');
      for (const c of kept!.mine) {
        const x = (msg.commitments as SignCommit[]).find((y) => y.i === c.i);
        if (!x || x.D !== c.D || x.E !== c.E) refuse('bad_commitments', 'not the commitments returned for after');
      }
    }
    const { evId, lockApproved, signpost } = this.checkEvent(from, msg, mode, now) as { evId: string; lockApproved: boolean; signpost?: boolean };
    if (!twoCall) {
      const ctx = sha(jcsBytes(msg));
      const cs = mine.map((i) => commit(this.state.C, i, this.state.shares.get(i)!, hedge(this.state.shares.get(i)!, ctx)));
      nonces = cs.map((c) => c.nonces); myCommits = cs.map((c) => c.commit);
    } else {
      const kept = this.#twoCall.get(`${from}:${msg.after}`)!;
      nonces = kept.nonces; myCommits = kept.mine;
      this.#twoCall.delete(`${from}:${msg.after}`);
    }
    const all = twoCall ? (msg.commitments as SignCommit[]) : [...msg.commitments, ...myCommits];
    const z = nonces.map((n) => ({ i: n.i, z: signShare(this.state.C, n.i, this.state.shares.get(n.i)!, n, evId, all) }));
    if (msg.event.kind === 5 && !lockApproved && msg.hold === undefined) this.burst.add(now, deletionTargets(msg.event));
    if (signpost) this.noteSignpost(evId);
    return { v: 1, type: 'partial', re: msg.id, commitments: twoCall ? [] : myCommits, z };
  }

  private commitTwoCall(from: string, msg: any, now: number) {
    this.sender(from);
    const st = this.stale(msg); if (st) return st;
    const parts = this.participants(msg.signers, from, true);
    this.coordinator(from, parts, now);
    for (const [k, v] of this.#twoCall) if (now - v.at > NONCE_TTL_S) this.#twoCall.delete(k);
    const ctx = sha(jcsBytes(msg));
    const cs = this.myIndices.map((i) => commit(this.state.C, i, this.state.shares.get(i)!, hedge(this.state.shares.get(i)!, ctx)));
    this.#twoCall.set(`${from}:${msg.id}`, { nonces: cs.map((c) => c.nonces), mine: cs.map((c) => c.commit), at: now, used: false, from, signers: msg.signers });
    return { v: 1, type: 'commitments', re: msg.id, commitments: cs.map((c) => c.commit) };
  }

  private ecdh(from: string, msg: any, now: number) {
    const s = this.sender(from);
    if (s.kind !== 'device') refuse('not_device', 'only a current device coordinates a decryption');
    const st = this.stale(msg); if (st) return st;
    this.participants(msg.signers, from);
    if (!Array.isArray(msg.points) || !msg.points.length) refuse('malformed');
    msg.points.forEach((q: string) => pointFrom(q, 'Q'));
    const reqHash = sha(jcsBytes(msg));
    const ctx = { g: this.g, epochId: this.m.epochId, state: stateOf(this.state), signers: msg.signers };
    const answers = msg.points.map((Q: string) => this.myIndices.map((i) => ecdhAnswer(ctx, this.state.C, i, this.state.shares.get(i)!, Q, reqHash)));
    void now;
    return { v: 1, type: 'ecdh_partial', re: msg.id, answers };
  }

  private hold(from: string, msg: any, now: number) {
    const s = this.sender(from);
    if (s.kind !== 'device') refuse('not_device');
    if (this.frozen(now)) refuse('frozen', 'a recovery is running');
    const ev: Unsigned = msg.event;
    if (!ev || ev.pubkey !== this.g) refuse('wrong_pubkey');
    const evId = eventId(ev), wait = holdWaitId(evId);
    const mine = [...this.holds.values()].filter((h) => h.device === from && !h.cancelled && h.end > now - SESSION_S);
    if (!this.holds.has(wait) && mine.length >= MAX_HOLDS) refuse('too_many_holds');
    const h = this.holds.get(wait) ?? { wait, eventId: evId, device: from, start: now, end: now + this.W, cancelled: this.cancelledWaits.has(wait) };
    this.holds.set(wait, h);
    return { v: 1, type: 'notice', re: msg.id, kind: 'hold', wait, start: h.start, end: h.end };
  }

  /** A waited statement for a passed wait (§6.3), signed by this server's host key. */
  waited(wait: string, now = this.o.now()): Waited | null {
    if (!this.o.host) return null;
    const h = this.holds.get(wait), r = this.recoveries.get(wait);
    const w = h ?? r;
    if (!w || w.cancelled || (r && r.withdrawn) || w.end > now) return null;
    return signWaited(this.g, this.o.host, h ? 'hold' : 'recovery', wait, w.start, w.end);
  }

  private cancel(from: string, msg: any, now: number) {
    const s = this.sender(from);
    if (s.kind !== 'device') refuse('not_device', 'a helper never cancels');
    if (msg.approval?.lock && msg.approval.lock.member !== from) refuse('needs_approval');
    this.takeCancel({ wait: msg.wait, approval: msg.approval });
    void now;
    return { v: 1, type: 'notice', re: msg.id, kind: 'cancelled', wait: msg.wait };
  }

  /** Accepted cancels, kept as deliveries for peers (§6.3, §7.1): a server that missed one fetches it. */
  cancels: { wait: string; approval: any }[] = [];
  cancelledWaits = new Set<string>();
  /** Check and apply a cancel, whoever relayed it: its lock assertion or pair is the authority. */
  takeCancel(c: { wait: string; approval: any }) {
    hexN(c.wait, 32, 'wait');
    const w = what.cancel(c.wait);
    const a = c.approval ?? {};
    if (a.lock) {
      const dev = this.m.members.get(a.lock.member);
      if (!dev || dev.kind !== 'device' || this.m.removed.has(dev.key) || !dev.lock) refuse('needs_approval');
      const e = checkAssertion(this.g, dev!.lock!, w, a.lock.assertion); if (e) refuse(e);
    } else if (a.pair) {
      const [x, y] = a.pair;
      if (x.member === y.member || !this.m.devices.has(x.member) || !this.m.devices.has(y.member)) refuse('approver_not_device');
      const d = detachedDigest('pair', this.g, { what: bytesToHex(w), r: x.r });
      if (!schnorrVerify(x.sig, d, x.member) || !schnorrVerify(y.code_sig, d, y.member)) refuse('bad_signature');
    } else refuse('needs_approval');
    const t = this.holds.get(c.wait) ?? this.recoveries.get(c.wait);
    if (t) t.cancelled = true;
    if (!this.cancelledWaits.has(c.wait)) { this.cancelledWaits.add(c.wait); this.cancels.push(c); }
  }

  private withdraw(from: string, msg: any) {
    const h = this.holds.get(msg.wait), r = this.recoveries.get(msg.wait);
    if (h && h.device === from) h.cancelled = true;
    else if (r && r.backup === from) r.withdrawn = true;
    else refuse('not_requester');
    return { v: 1, type: 'notice', re: msg.id, kind: 'withdrawn', wait: msg.wait };
  }

  private challenge(from: string, msg: any, now: number) {
    if (!this.m.members.has(from) || this.m.removed.has(from)) refuse('not_member');
    const c = bytesToHex(randomBytes(16));
    this.challenges.set(c, { exp: now + 120 + 30, to: from });
    for (const [k, e] of this.challenges) if (e.exp < now) this.challenges.delete(k);
    return { v: 1, type: 'challenge', re: msg.id, challenge: c, server: this.o.host?.pub ?? this.o.me.pub };
  }

  /** §6.5 steps 1–3. The first request starts the wait; once it has passed, the same request
   *  (same `r`) gets the waited statement, and the host adds the release bundle. */
  private releaseRequest(from: string, msg: any, now: number) {
    if (from !== this.m.backupKey) refuse('not_current_backup');
    const { r, challenge, sig } = msg;
    hexN(r, 16, 'r');
    const wait = recoveryWaitId(from, this.m.epochId, r);
    const existing = this.recoveries.get(wait);
    if (!existing) {
      if (!this.takeChallenge(challenge, from, now)) refuse('stale_challenge');
      if (!schnorrVerify(sig, detachedDigest('release_request', this.g, { r, challenge }), from)) refuse('bad_signature');
      const rec: Recovery = { wait, backup: from, r, start: now, end: now + this.W, cancelled: this.cancelledWaits.has(wait), withdrawn: false };
      this.recoveries.set(wait, rec);
      for (const h of this.holds.values()) h.cancelled = true;     // a recovery ends running holds
      return { v: 1, type: 'notice', re: msg.id, kind: 'recovery', wait, start: rec.start, end: rec.end };
    }
    if (existing.cancelled || existing.withdrawn) refuse('cancelled');
    const w = this.waited(wait, now);
    if (!w) return { v: 1, type: 'notice', re: msg.id, kind: 'recovery', wait, start: existing.start, end: existing.end };
    return { v: 1, type: 'release', re: msg.id, wait, waited: w };
  }
}

export { checkWaited, stateHash };
