// A co-signer (core §5.7): every check before it gives a partial, plus the waits it runs (§5.8,
// §6.3, §6.5). A server runs one per account; a device runs one too when another device-class
// member asks it, adding its own policy. Storage (deliveries, inboxes, the change set) is the
// host's; this class keeps only what Core says a co-signer keeps, and takes the clock as input.

import { bytesToHex, randomBytes, sha, jcsBytes, hexN, refuse, KeykinError, concatBytes, u32be, strictJson } from './bytes.ts';
import { holdWaitId, recoveryWaitId, what, detachedDigest, stateHash, signpostD, signpostH } from './codes.ts';
import { checkLifetime, bodyHash, ReplayCache, type Cls } from './lifetimes.ts';
import { futureDateOk, destructive, deletionTargets, BurstCounter, type Ev } from './destructive.ts';
import { commit, signShare, hedge, type SignCommit, type Nonces } from './frost.ts';
import { ecdhAnswer } from './ecdh.ts';
import { checkAssertion } from './lock.ts';
import { eventId, eventShape, schnorrVerify, verifyEvent, tag, type KeyPair, type NostrEvent, type Unsigned } from './event.ts';
import { checkApproval, approvalType, approvalHash, placeholderList, changeKey, checkWaited, signWaited, changeWhat, MAX_EXPIRY_S, W_DEFAULT } from './approval.ts';
import { computeMembership, parseChange, adopt, type Membership } from './membership.ts';
import { pointFrom, commitmentFrom, scalarHex, type Commitment } from './curve.ts';
import { stateOf, commitmentAt, type State } from './redeal.ts';
import { verifyRerepair, redealMissing, postListView, postListBackup, type Upload } from './upkeep.ts';
import { itemHash } from './redeal.ts';
import { RepairHelper } from './repair.ts';
import { requestApprovers } from './requests.ts';
import { checkEnroll } from './serverprofile.ts';
import { checkHeirPiece, heirWaitId, type HeirRecord } from './backup.ts';
import { takenIndices, signpostCount, signpostServers } from './membership.ts';
import { jcs } from './bytes.ts';
import { KIND_CHANGE, KIND_EPOCH, KIND_SIGNPOST, type Approval, type Change, type EpochContent, type MemberEntry, type Waited } from './types.ts';

export const NONCE_TTL_S = 120;
/** §5.7 item 8: what the helper may coordinate. */
export const HELPER_KINDS = new Set([1, 1111, 7, 6, 16, 9734, 20, 21, 22, 22242]);
export const MAX_STOPS_PER_MEMBER = 3;
export const HELPER_NEVER = new Set(['hold', 'cancel', 'push_register', 'notify_register', 'need_seeds', 'take_out', 'ecdh']);
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
  #twoCall = new Map<string, { nonces: Nonces[][]; mine: SignCommit[][]; at: number; used: boolean; from: string; signers: number[] }>();

  constructor(o: CoSignerOpts) {
    this.o = o; this.state = o.state; this.changes = o.changes ?? [];
    this.m = computeMembership(o.record, this.changes, o.W ?? W_DEFAULT);
  }
  get W() { return this.o.W ?? W_DEFAULT; }
  get g() { return this.o.record.g; }
  get myIndices() { return [...this.state.shares.keys()].sort((a, b) => a - b); }

  /** Take changes (a delivery, `changes`, a catch-up union): the membership is recomputed. */
  addChanges(evs: NostrEvent[]) {
    // A member refuses to adopt a change that breaks an invariant (§3.3), and shows it. Refused ones
    // are retried with every later batch, so the view depends only on the set held.
    const r = adopt(this.o.record, this.changes, [...evs, ...this.refusedChanges.map((x) => x.ev)], this.W);
    this.changes = r.changes; this.m = r.m; this.refusedChanges = r.refused;
    // A helper seat change clears only the stops it names (§5.7).
    for (const p of this.m.accepted) { const ch: any = p.c.change; if (ch.seat?.seat === 'helper' && Array.isArray(ch.seat.clears_stops)) this.clearStops(ch.seat.clears_stops, this.o.now()); }
    return !r.refused.some((x) => evs.includes(x.ev));
  }
  refusedChanges: { ev: NostrEvent; why: string }[] = [];
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
  authorizeRepair(from: string, body: { participant: number; seal_to: string; why: string; state: string; proof?: any; helpers?: { key: string; indices: number[] }[]; list?: Change[]; approval?: Approval }, now = this.o.now()) {
    const m = this.m;
    if (body.state !== stateOf(this.state)) refuse('stale');
    const p = body.participant;
    this.checkHelpers(body.helpers, p, body.seal_to, body, now);
    if (body.why === 'paper') return this.authorizePaperRepair(from, body as any, now);
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
        // Repair helpers check the enrol reply's host signature only (Server profile §4).
        if (owner!.kind === 'server' && owner!.enroll !== undefined) { const e = checkEnroll(owner!, this.g); if (e) refuse(e); }
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
  /** The helper list is checked against this view, never taken on trust: every entry is a current
   *  member with exactly its own indices, this co-signer is in it with its own, nobody twice, worth at
   *  least 4, and neither the new owner nor the backup helps (they would learn the share). */
  private checkHelpers(helpers: { key: string; indices: number[] }[] | undefined, participant: number, sealTo: string, body: any = {}, now = this.o.now()) {
    if (!Array.isArray(helpers) || !helpers.length) refuse('bad_helpers');
    const seen = new Set<string>();
    let worth = 0;
    for (const h of helpers!) {
      const mem = this.m.members.get(h?.key);
      if (!mem || this.m.removed.has(h.key) || seen.has(h.key)) refuse('bad_helpers', 'helpers are distinct current members');
      if (mem!.kind === 'backup' && !(this.session()?.backup === h.key) && !this.paperHelps(h.key, helpers!, sealTo, body, now))
        refuse('bad_helpers', 'the backup helps only in its recovery session, or with a device under a paper approval of the change being filled');
      if (JSON.stringify([...h.indices].sort((a, b) => a - b)) !== JSON.stringify([...mem!.shares].sort((a, b) => a - b))) refuse('bad_helpers', 'each helper lists exactly its own indices');
      if (h.key === sealTo || h.indices.includes(participant)) refuse('bad_helpers', 'the new holder never helps');
      seen.add(h.key); worth += h.indices.length;
    }
    if (!seen.has(this.o.me.pub)) refuse('bad_helpers', 'this co-signer is one of the helpers');
    if (worth < 4) refuse('bad_helpers', 'helpers worth at least 4');
  }

  /** Core 14.9: the backup may help fill a seat with a current device, under a valid `paper` approval
   *  (its own key) of the very list that makes `seal_to` the seat's holder. */
  private paperHelps(backup: string, helpers: { key: string }[], sealTo: string, body: any, now: number): boolean {
    const a = body.approval, list = body.list;
    if (!a?.paper || a.paper.backup !== backup || !Array.isArray(list)) return false;
    if (!list.some((c: any) => c.seat?.new?.key === sealTo)) return false;
    if (!helpers.some((h) => this.m.devices.has(h.key))) return false;
    // Every member's check plus the expiry; the paper challenge is the issuing server's to check (§6.2).
    const { error } = checkApproval(this.m.authority, list, a);
    return error === null && a.expiry > now && a.expiry <= now + MAX_EXPIRY_S + 30 && a.paper.backup === this.m.backupKey;
  }

  /** F7 step 2 (§4.3, §6.7.10): the backup seat repaired towards a new paper key K, only under a
   *  valid, fresh approval of `[paper K, redeal]`, by its approving device, sealed to K, once per K. */
  private authorizePaperRepair(from: string, body: { participant: number; seal_to: string; list: Change[]; approval: Approval }, now: number) {
    const m = this.m;
    if (!m.record.seats.backup.includes(body.participant)) refuse('not_assigned');
    const pc = (body.list ?? []).find((c) => 'paper' in c) as { paper: { key: string; replaces: string } } | undefined;
    if (!pc) refuse('bad_list', 'a paper repair needs its [paper, redeal] approval');
    this.checkFresh(from, body.list, body.approval, now, approvalHash(body.list));
    const t = approvalType(body.approval);
    const { approvers } = checkApproval(m.authority, body.list, body.approval);
    if (t === 'recovery' ? this.session(now)?.backup !== from : !approvers.includes(from) || !m.devices.has(from)) refuse('not_approver', 'the approving device (or the holder, under recovery) makes the repair');
    const K = pc!.paper.key;
    if (pc!.paper.replaces !== m.backupKey) refuse('not_current_backup');
    if (body.seal_to !== K) refuse('not_assigned', 'sealed only to the new paper key');
    if (m.members.has(K) || m.removed.has(K)) refuse('invariant', 'a paper key is a fresh key');
    const k = `paper:${K}:${body.participant}`;
    if (this.answeredRepair.has(k)) refuse('already_answered', 'never a second repair towards the same K');
    this.answeredRepair.add(k);
  }

  /** Account admin §3: `account_delete {id, approval}`, an approved request (lock, pair or paper with this
   *  server's own challenge), checked here at first hand. Returns what the tombstone keeps. */
  checkDelete(from: string, msg: any, now = this.o.now(), relayed = false): { request: any; changes: NostrEvent[] } {
    const { approval } = msg;
    // A request relayed in a peer's `deleted` is checked here too, never taken on the peer's word (core
    // §3.2): its sender is its approving device; only the first server took its own paper challenge.
    if (relayed) from = approval?.lock?.member ?? approval?.pair?.[0]?.member ?? approval?.paper?.member;
    const dev = this.sender(from);
    if (dev.kind !== 'device') refuse('not_device');
    if (!approval?.lock && !approval?.pair && !approval?.paper) refuse('needs_approval', 'a delete needs lock, pair or paper; there is no hold path');
    const me = this.o.host?.pub ?? this.o.me.pub;
    const approvers = requestApprovers(this.m, this.g, 'account_delete', msg, { from: approval?.pair ? undefined : from, me,
      take: relayed ? undefined : (c, b) => this.takeChallenge(c, b, now) });
    // The changes that make each approver a device, so anyone can check the tombstone's proof.
    // With their lock changes and, for a paper approval, the paper change of that key (review 5 B10).
    const paperKey = approval?.paper ? approval.paper.backup : null;
    const changes = this.m.accepted.filter((p) => (p.type === 'add' && approvers.includes((p.c.change as any).add.key))
      || (p.type === 'lock' && approvers.includes((p.c.change as any).lock.member))
      || (p.type === 'paper' && paperKey && (p.c.change as any).paper.key === paperKey)).map((p) => p.ev);
    return { request: msg, changes };
  }

  /** Help a repair (§4.2 step 3, §6.7.4, §6.7.10): authorised first, and the finish seals only to
   *  what this start authorised. Hosts call these, never the helper directly. */
  #repair = new RepairHelper();
  repairStart(from: string, body: any, now = this.o.now()) {
    this.authorizeRepair(from, body, now);
    return this.#repair.start(this.o.me, this.state.C, this.state.shares, from, body, stateOf(this.state));
  }
  repairFinish(from: string, body: any) { return this.#repair.finish(this.o.me, from, body, stateOf(this.state)); }

  /** A `need_repair` answer that succeeded uses up the server's one answer (§6.7.4). */
  repairSucceeded(owner: string, index: number) { this.answeredRepair.add(`${owner}:${index}`); }

  /** The current signpost's event id (§6.7.5), from co-signing it or from a welcome: its delete is refused. */
  noteSignpost(id: string) { this.signpostIds.add(id); }
  /** A signpost delivered by a device (§6.7.10): only a group-signed kind 30078 with this account's
   *  signpost `d` is taken, and it replaces the older one for that `d`. */
  signpostByD = new Map<string, { id: string; at: number }>();
  takeSignpost(ev: NostrEvent): boolean {
    const d = tag(ev, 'd') ?? '';
    if (ev?.kind !== KIND_SIGNPOST || ev.pubkey !== this.g || !verifyEvent(ev) || !new Set(this.m.backupKeys.map(signpostD)).has(d)) return false;
    const cur = this.signpostByD.get(d);
    if (cur && cur.at > ev.created_at) return false;
    if (cur) this.signpostIds.delete(cur.id);
    this.signpostByD.set(d, { id: ev.id, at: ev.created_at });
    this.signpostIds.add(ev.id);
    return true;
  }

  /** What a server keeps across a restart (§2, §5.6): answered ids, waits, cancels, challenges, §5.8's
   *  counter, helper stops, heir records with this server's piece. Never nonces, kept or two-call: a
   *  restart loses every round in flight (§5.2). Shares are the host's to store. */
  snapshot() {
    return JSON.stringify({ replay: this.replay.dump(), holds: [...this.holds.values()], recoveries: [...this.recoveries.values()],
      cancels: this.cancels, challenges: [...this.challenges], signposts: [...this.signpostIds], stops: [...this.stops], cleared: [...this.clearedStops],
      burst: this.burst.dump(), used: [...this.usedChallenges], answered: [...this.answeredRepair],
      heirs: [...this.heirs].map(([k, h]) => [k, { ...h, piece: scalarHex(h.piece) }]) });
  }
  restore(json: string) {
    const x = JSON.parse(json);
    this.burst.load(x.burst ?? []); this.usedChallenges = new Map(x.used ?? []); this.answeredRepair = new Set(x.answered ?? []);
    this.heirs = new Map((x.heirs ?? []).map(([k, h]: [string, any]) => [k, { ...h, piece: BigInt('0x' + h.piece) }]));
    this.replay.load(x.replay);
    this.holds = new Map(x.holds.map((h: Hold) => [h.wait, h]));
    this.recoveries = new Map(x.recoveries.map((r: Recovery) => [r.wait, r]));
    this.cancels = x.cancels; this.cancelledWaits = new Set(x.cancels.map((c: any) => c.wait));
    this.challenges = new Map(x.challenges); this.signpostIds = new Set(x.signposts);
    this.stops = new Map(x.stops ?? []); this.clearedStops = new Map(x.cleared ?? []);
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
    // Helper module §1: a helper never sends these.
    if (this.m.members.get(from)?.kind === 'helper' && HELPER_NEVER.has(msg.type)) return ERR(id, 'helper_refused');
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

  /** Helper stops (§5.7): account state. In force by id → who sent it; cleared ids never return. */
  stops = new Map<string, { by: string; at: number }>();
  clearedStops = new Map<string, number>();
  takeStop(from: string, msg: { id?: string; stop?: string; by: string }, now: number) {
    const id = msg.stop ?? msg.id!;
    hexN(id, 16, 'stop id');
    if (!this.m.devices.has(from) || msg.by !== from) refuse('not_device', 'any current device stops the helper, naming itself');
    if (this.clearedStops.has(id) || this.stops.has(id)) return;
    if ([...this.stops.values()].filter((x) => x.by === from).length >= MAX_STOPS_PER_MEMBER) refuse('already_stopped');
    this.stops.set(id, { by: from, at: now });
  }
  clearStops(ids: string[], now: number) { for (const id of ids) { this.stops.delete(id); this.clearedStops.set(id, now); } }

  // --- Backup module §4: the heir ---------------------------------------------------------
  heirs = new Map<string, { record: HeirRecord; x: number; piece: bigint; removed?: boolean; cancelledAt?: number }>();
  heirWaits = new Map<string, { set: string; H: string; start: number; end: number; cancelled: boolean }>();
  /** Take an heir record and this server's piece, only when a co-signed `paper` change names its hash. */
  takeHeir(record: HeirRecord, x: number, piece: bigint): string | null {
    const h = bytesToHex(sha(jcs(record)));
    const pinned = this.m.accepted.some((p) => p.type === 'paper' && (p.c.change as any).paper.key === record.set && (p.c.change as any).paper.heir === h);
    if (!pinned) return 'not_pinned';
    if (record.wait_days < 30) return 'bad_heir';
    if (!checkHeirPiece(record, x, piece)) return 'bad_piece';
    this.heirs.set(record.set, { record, x, piece });
    return null;
  }
  private heirFor(from: string, set: string) {
    const h = this.heirs.get(set);
    if (!h || h.removed || h.record.H !== from) refuse('no_heir');
    if (set !== this.m.backupKey) refuse('not_current_set', 'a later paper replaced this set');
    return h!;
  }

  handlers = {
    heir_request(this: CoSigner, from: string, msg: any, now: number) {
      const h = this.heirFor(from, msg.set);
      if (!this.takeChallenge(msg.challenge, from, now)) refuse('stale_challenge');
      if (h.cancelledAt !== undefined && now - h.cancelledAt < 30 * 86400) refuse('heir_cooldown');
      if ([...this.heirWaits.values()].some((w) => w.set === msg.set && !w.cancelled)) refuse('heir_wait_running');
      const wait = heirWaitId(from, msg.set, msg.request);
      this.heirWaits.set(wait, { set: msg.set, H: from, start: now, end: now + h.record.wait_days * 86400, cancelled: this.cancelledWaits.has(wait) });
      return { v: 1, type: 'notice', re: msg.id, kind: 'heir', wait, end: now + h.record.wait_days * 86400 };
    },
    heir_get(this: CoSigner, from: string, msg: any, now: number) {
      const h = this.heirFor(from, msg.set);
      const w = [...this.heirWaits.entries()].find(([, x]) => x.set === msg.set && x.H === from && !x.cancelled && x.end <= now);
      if (!w) refuse('heir_wait_not_passed');
      return { v: 1, type: 'heir_piece', re: msg.id, record: h.record, x: h.x, piece: scalarHex(h.piece) };
    },
    heir_remove(this: CoSigner, from: string, msg: any) {
      if (!this.m.devices.has(from)) refuse('not_device', 'any current device removes the heir');
      const h = this.heirs.get(msg.set);
      if (h) { h.removed = true; h.piece = 0n; }
      for (const w of this.heirWaits.values()) if (w.set === msg.set) w.cancelled = true;
      return { v: 1, type: 'notice', re: msg.id, kind: 'heir_removed' };
    },
    helper_stop(this: CoSigner, from: string, msg: any, now: number) {
      this.takeStop(from, { stop: msg.stop, by: msg.by }, now);
      return { v: 1, type: 'notice', re: msg.id, kind: 'helper_stopped', stops: [...this.stops.keys()] };
    },
    helper_resume(this: CoSigner, from: string, msg: any, now: number) {
      // An approval over the request (§6.1: type ‖ id ‖ SHA-256(JCS(body without the approval))): lock,
      // two devices, or the paper with this server's own challenge (core §6.2).
      const dev = this.sender(from);
      if (dev.kind !== 'device') refuse('not_device');
      const a = msg.approval;
      if (!a?.lock && !a?.pair && !a?.paper) refuse('needs_approval', 'a resume needs lock, pair or paper');
      requestApprovers(this.m, this.g, 'helper_resume', msg, { from: a?.pair ? undefined : from, me: this.o.host?.pub ?? this.o.me.pub, take: (c, b) => this.takeChallenge(c, b, now) });
      if (!Array.isArray(msg.ids)) refuse('malformed');
      this.clearStops(msg.ids, now);
      return { v: 1, type: 'notice', re: msg.id, kind: 'helper_resumed', stops: [...this.stops.keys()] };
    },
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
    // §5.7 item 8: a helper never co-signs; a device never co-signs a helper round; a stop in force
    // refuses every round the helper coordinates or takes part in.
    if (this.o.kind === 'helper') refuse('helper_never_cosigns');
    if (participants.some((p) => p.kind === 'helper')) {
      if (this.o.kind === 'device') refuse('helper_round', 'a device never co-signs a round the helper coordinates');
      if (this.stops.size) refuse('helper_stopped');
    }
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

  /** §9.5: a co-signer takes exactly `pubkey`, `created_at`, `kind`, `tags`, `content` and `id`, and
   *  recomputes the id. */
  private checkWire(ev: unknown) {
    eventShape(ev, 'cosign');
    if ((ev as any).pubkey !== this.g) refuse('wrong_pubkey');
    if ((ev as any).id !== eventId(ev as Unsigned)) refuse('malformed', 'the event id differs from its fields');
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
    // §6.7.5 (14.18): by `e` id, or by an `a` value that contains both g and a signpost d anywhere,
    // whatever its kind part or splitting (relays read `a` loosely); hex compared ignoring case.
    if (ev.kind === 5 && ev.tags.some((t) => typeof t[1] === 'string' && ((t[0] === 'e' && this.signpostIds.has(t[1].toLowerCase()))
      || (t[0] === 'a' && t[1].toLowerCase().includes(this.g) && [...signpostDs].some((d) => t[1].toLowerCase().includes(d))))))
      refuse('machinery', 'a signpost delete is always refused');
    if (ev.kind === KIND_SIGNPOST && signpostDs.has(tag(ev, 'd') ?? '')) { this.checkSignpost(from, ev); return { evId, lockApproved: false, signpost: true }; }
    if (ev.kind === KIND_CHANGE) { this.checkListToSign(from, [ev], mode, now, msg); return { evId, lockApproved: false }; }
    if (mode === 'recovery') refuse('recovery_session', 'only recovery-approved changes in a session');
    if (this.m.members.get(from)?.kind === 'helper') {
      if (!HELPER_KINDS.has(ev.kind)) refuse('helper_kind', 'the helper signs only everyday posts and reactions');
      if (ev.created_at - now > 600) refuse('dated_ahead');
    }
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

  /** An approval as every member checks it, plus the co-signer's freshness (§3.2, once): expiry,
   *  approvers still current, only the current lock, the paper challenge (used once per list, so every
   *  change of the list shares it), the recovery session. `use` names what consumes the challenge. */
  private usedChallenges = new Map<string, string>();
  checkFresh(from: string, list: Change[], a: Approval, now: number, use: string) {
    const t = approvalType(a);
    const { error, approvers } = checkApproval(this.m.authority, list, a);
    if (error) refuse(error);
    if (t === 'lock' || t === 'pair' || t === 'paper') {
      if (!(a.expiry! > now && a.expiry! <= now + MAX_EXPIRY_S + 30)) refuse('approval_expired');
    }
    for (const k of approvers) if (this.m.removed.has(k) || !this.m.devices.has(k)) refuse('approver_removed');
    if (t === 'lock') {
      const cur = this.m.locks.get(a.lock!.member);
      if (!cur || checkAssertion(this.g, cur, changeWhat(this.g, this.m.epochId, list, a.expiry!), a.lock!.assertion)) refuse('not_current_lock');
    }
    if (t === 'paper') {
      if (a.paper!.backup !== this.m.backupKey) refuse('not_current_backup');
      if (a.paper!.server !== (this.o.host?.pub ?? this.o.me.pub)) refuse('wrong_challenge_server');
      const prior = this.usedChallenges.get(a.paper!.challenge);
      if (prior !== undefined) { if (prior !== use) refuse('stale_challenge'); }
      else if (!this.takeChallenge(a.paper!.challenge, a.paper!.backup, now)) refuse('stale_challenge');   // bound to the backup key (14.3)
      else this.usedChallenges.set(a.paper!.challenge, use);
    }
    if (t === 'recovery') {
      const r = a.recovery!;
      if (r.backup !== this.m.backupKey || from !== r.backup) refuse('not_holder', 'recovery approvals come only from the holder\'s own connection');
      const sess = this.session(now);
      if (!sess || sess.backup !== from) refuse('no_recovery_session');
      if (r.waited.some((w: Waited) => now > w.end + STATEMENT_MAX_AGE_S)) refuse('statement_too_old');
    }
  }

  /** §5.7 item 5 for a list of changes: every event of the list, in one request (§6.7.10), checked
   *  once at the pre-redeal state: valid, fresh, and safe to add to this co-signer's membership. */
  private checkListToSign(from: string, evs: Unsigned[], mode: 'everyday' | 'recovery', now: number, msg: any) {
    const selves = evs.map((ev) => ({ ...ev, id: eventId(ev), sig: '' }) as NostrEvent);
    const ps = selves.map((e) => parseChange(this.o.record, e, false));
    const p0 = ps[0];
    if (ps.some((p) => p.listHash !== p0.listHash)) refuse('bad_list', 'one list per request');
    // Every entry of the list exactly once.
    const want = p0.c.list.map(changeKey);
    const got = ps.map((p) => changeKey(placeholderList([p.c.change])[0]));
    if (want.length !== got.length || want.some((w) => got.filter((g) => g === w).length !== want.filter((x) => x === w).length))
      refuse('list_incomplete', 'every event of a list travels in one request');
    if (ps.some((p) => jcs(p.c.approval) !== jcs(p0.c.approval))) refuse('bad_list', 'one approval per list');
    const a = p0.c.approval;
    const t = approvalType(a);
    this.checkFresh(from, p0.c.list, a, now, p0.listHash);
    if (mode === 'recovery' && t !== 'recovery') refuse('recovery_session', 'only recovery-approved changes');
    // F3 (§6.7.2): a seat list no current seat holder co-signs, here a device co-signing it, needs
    // `pair`, `paper` or `recovery`, never a lock alone.
    if (this.o.kind !== 'server' && p0.c.list.some((x) => 'seat' in x) && !(t === 'pair' || t === 'paper' || t === 'recovery')) refuse('approval_not_allowed', 'F3 needs pair, paper or recovery');
    // Across the list: no two seats to one key or host, and the paper key is nobody else's.
    const seatNews = p0.c.list.flatMap((x: any) => (x.seat?.new ? [x.seat.new] : []));
    if (new Set(seatNews.map((n: any) => n.key)).size !== seatNews.length || new Set(seatNews.map((n: any) => n.host)).size !== seatNews.length) refuse('invariant', 'one key or host in two seats');
    const paperKey = (p0.c.list.find((x: any) => 'paper' in x) as any)?.paper.key;
    if (paperKey && seatNews.some((n: any) => n.key === paperKey)) refuse('invariant', 'a paper key is a fresh key');
    // The list must leave a valid membership: try it (§3.3).
    const trial = computeMembership(this.o.record, this.changes, this.W, selves);
    for (const e of selves) { const r = trial.refused.find((x) => x.id === e.id); if (r) refuse(r.code); }
    if (trial.invariantError) refuse('invariant', trial.invariantError);
    const leaving = new Set<string>(p0.c.list.flatMap((x: any) => ('remove' in x ? [x.remove] : 'seat' in x ? [this.m.seats.get(x.seat.seat)?.holder?.key ?? ''] : 'paper' in x ? [x.paper.replaces] : [])));
    for (const k of this.m.members.keys()) if (!trial.members.has(k) && !leaving.has(k)) refuse('invariant', 'the change would drop a member it does not name');
    for (const p of ps) {
      const ch: any = p.c.change;
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
          // Server profile §4: a server's `new` entry carries its host-signed enrol reply, unexpired at
          // this co-sign (and, in F3, at the device's approval).
          if (n && String(ch.seat.seat).startsWith('server:')) { const e = checkEnroll(n, this.g, now); if (e) refuse(e); }
          // Helper module §3.1: the helper's operator never runs a server (helper + one dishonest server is the key).
          if (n) {
            const helperOp = ch.seat.seat === 'helper' ? n.operator : this.m.seats.get('helper')?.holder?.operator;
            const serverOps = new Set([...this.m.seats.entries()].filter(([k, x]) => k.startsWith('server:') && x.holder && k !== ch.seat.seat).map(([, x]) => x.holder!.operator));
            if (ch.seat.seat !== 'helper') serverOps.add(n.operator);
            if (helperOp && serverOps.has(helperOp)) refuse('helper_operator', 'the helper\'s operator may not run a server');
          }
          break;
        }
        case 'paper': {
          if (ch.paper.replaces !== this.m.backupKey) refuse('not_current_backup');
          if (this.m.members.has(ch.paper.key) || this.m.removed.has(ch.paper.key)) refuse('invariant', 'a paper key is a fresh key');
          // The base material item travels with the request: its hash is `inner`, signed by K (§6.7.10).
          const it = msg.material;
          if (!it || itemHash(it) !== ch.paper.inner || it.to !== ch.paper.key || !schnorrVerify(it.sig, sha(itemHash(it)), ch.paper.key)) refuse('bad_material');
          break;
        }
        case 'redeal': {
          const r = ch.redeal;
          if (r.abandons.some((x: string) => this.m.redeals.get(x)?.withRemove)) refuse('abandons_remove_redeal');
          if (r.base.some((b: string) => this.m.abandoned.has(b))) refuse('abandoned');
          if (this.m.abandoned.has(r.id)) refuse('abandoned');
          if (r.paper_to !== postListBackup(this.m, p.c.list)) refuse('bad_paper_to');
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
  }

  /** §6.7.5: a signpost only from a device, with the right `n` and an `h` matching this view. */
  private checkSignpost(from: string, ev: Unsigned) {
    if (!this.m.devices.has(from)) refuse('machinery', 'signposts come from devices');
    if (tag(ev, 'n') !== String(signpostCount(this.m))) refuse('signpost_n'); // compared as a string (§9.5)
    if (tag(ev, 'h') !== signpostH(this.m.epochId, signpostServers(this.m))) refuse('signpost_h');
  }

  /** `sign` (§5.1): one event, or every event of a list (`list_events`, §6.7.10), each with its own
   *  commitments, nonces and partials (one nonce pair never signs two events, §5.2). Partials for
   *  every event or for none. */
  private sign(from: string, msg: any, now: number) {
    this.sender(from);
    const st = this.stale(msg); if (st) return st;
    const twoCall = msg.after !== undefined;
    const parts = this.participants(msg.signers, from, twoCall);
    const mode = this.coordinator(from, parts, now);
    const isList = msg.list_events !== undefined;
    const items: { event: Unsigned; commitments: SignCommit[] }[] = isList ? msg.list_events : [{ event: msg.event, commitments: msg.commitments }];
    if (!Array.isArray(items) || !items.length || items.length > 16) refuse('malformed');
    for (const it of items) this.checkWire(it?.event);
    const mine = this.myIndices;
    let kept: { nonces: Nonces[][]; mine: SignCommit[][] } | null = null;
    if (!twoCall) {
      for (const it of items) this.checkCommitments(it.commitments, this.m.members.get(from)!.shares);
      if (mode === 'recovery') refuse('two_call', 'a recovery round has more than one co-signer');
    } else {
      const k = `${from}:${msg.after}`;
      const kk = this.#twoCall.get(k);
      if (!kk || now - kk.at > NONCE_TTL_S) refuse('unknown_after');
      if (kk!.used) refuse('after_used');
      kk!.used = true;
      if (JSON.stringify(kk!.signers) !== JSON.stringify(msg.signers)) refuse('bad_signers', 'differs from the commit');
      if (kk!.nonces.length !== items.length) refuse('bad_commitments', 'one set per event, as committed');
      items.forEach((it, e) => {
        this.checkCommitments(it.commitments, msg.signers);
        for (const c of kk!.mine[e]) {
          const x = it.commitments.find((y) => y.i === c.i);
          if (!x || x.D !== c.D || x.E !== c.E) refuse('bad_commitments', 'not the commitments returned for after');
        }
      });
      kept = kk!;
    }
    // The checks: a list once, as a whole; a single event by §5.7.
    const evs = items.map((it) => it.event);
    let single: { evId: string; lockApproved: boolean; signpost?: boolean } | null = null;
    if (isList) {
      if (evs.some((e) => !e || e.pubkey !== this.g || e.kind !== KIND_CHANGE)) refuse('bad_list', 'a list is account changes');
      evs.forEach((e) => { if (!futureDateOk(e as Ev, now)) refuse('dated_ahead'); });
      this.checkListToSign(from, evs, mode, now, msg);
    } else {
      if (msg.event?.kind === KIND_CHANGE) {
        let c: any; try { c = strictJson(msg.event.content); } catch { /* parse refuses below */ }
        if (Array.isArray(c?.list) && c.list.length > 1) refuse('list_in_one_request', 'every event of a list travels in one request');
      }
      single = this.checkEvent(from, msg, mode, now) as { evId: string; lockApproved: boolean; signpost?: boolean };
    }
    // Nonces: fresh per event (one-call) or the ones kept for `after` (two-call).
    const ctx = sha(jcsBytes(msg));
    const out = items.map((it, e) => {
      const evId = eventId(it.event);
      let nonces: Nonces[], myCommits: SignCommit[];
      if (kept) { nonces = kept.nonces[e]; myCommits = kept.mine[e]; }
      else {
        const cs = mine.map((i) => commit(this.state.C, i, this.state.shares.get(i)!, hedge(this.state.shares.get(i)!, concatBytes(ctx, u32be(e)))));
        nonces = cs.map((c) => c.nonces); myCommits = cs.map((c) => c.commit);
      }
      const all = kept ? it.commitments : [...it.commitments, ...myCommits];
      const z = nonces.map((n) => ({ i: n.i, z: signShare(this.state.C, n.i, this.state.shares.get(n.i)!, n, evId, all) }));
      return { commitments: kept ? [] : myCommits, z };
    });
    if (twoCall) this.#twoCall.delete(`${from}:${msg.after}`);
    if (single) {
      if (msg.event.kind === 5 && !single.lockApproved && msg.hold === undefined) this.burst.add(now, deletionTargets(msg.event));
      if (single.signpost) this.noteSignpost(single.evId);
      return { v: 1, type: 'partial', re: msg.id, ...out[0] };
    }
    return { v: 1, type: 'partial', re: msg.id, events: out };
  }

  private commitTwoCall(from: string, msg: any, now: number) {
    this.sender(from);
    const st = this.stale(msg); if (st) return st;
    const parts = this.participants(msg.signers, from, true);
    this.coordinator(from, parts, now);
    if (msg.event !== undefined) this.checkWire(msg.event);
    const count = msg.count ?? 1;
    if (!Number.isSafeInteger(count) || count < 1 || count > 16) refuse('malformed', 'count');
    for (const [k, v] of this.#twoCall) if (now - v.at > NONCE_TTL_S) this.#twoCall.delete(k);
    const ctx = sha(jcsBytes(msg));
    const sets = Array.from({ length: count }, (_, e) => this.myIndices.map((i) => commit(this.state.C, i, this.state.shares.get(i)!, hedge(this.state.shares.get(i)!, concatBytes(ctx, u32be(e))))));
    this.#twoCall.set(`${from}:${msg.id}`, { nonces: sets.map((cs) => cs.map((c) => c.nonces)), mine: sets.map((cs) => cs.map((c) => c.commit)), at: now, used: false, from, signers: msg.signers });
    return count === 1 && msg.count === undefined
      ? { v: 1, type: 'commitments', re: msg.id, commitments: sets[0].map((c) => c.commit) }
      : { v: 1, type: 'commitments', re: msg.id, sets: sets.map((cs) => cs.map((c) => c.commit)) };
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
    this.checkWire(ev);
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
    // Backup §4.3: any current device ends an heir wait, lock or not; only heir waits.
    const hw = this.heirWaits.get(msg.wait);
    if (hw && !msg.approval) {
      hw.cancelled = true;
      const h = this.heirs.get(hw.set); if (h) h.cancelledAt = now;
      if (!this.cancelledWaits.has(msg.wait)) { this.cancelledWaits.add(msg.wait); this.cancels.push({ wait: msg.wait, approval: { heir_by: from } }); }
      return { v: 1, type: 'notice', re: msg.id, kind: 'cancelled', wait: msg.wait };
    }
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
    if (c.approval?.heir_by && this.m.devices.has(c.approval.heir_by)) {
      const hw = this.heirWaits.get(c.wait);
      if (hw) { hw.cancelled = true; const h = this.heirs.get(hw.set); if (h) h.cancelledAt = this.o.now(); }
      if (!this.cancelledWaits.has(c.wait)) { this.cancelledWaits.add(c.wait); this.cancels.push(c); }
      return;
    }
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
    const isHeir = [...this.heirs.values()].some((h) => h.record.H === from && !h.removed);
    if ((!this.m.members.has(from) || this.m.removed.has(from)) && !isHeir) refuse('not_member');
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
