// A Keykin device (core §3–§8; Account admin; Backup; Helper; Server profile's device side): a member
// that holds 3 shares, coordinates its own rounds, keeps the account's history, and drives every flow.
// Written against a `Transport`, so the simulation's Bus, RelayNet over real relays and an app's own
// transport run the same code; its state goes to a `Store` (snapshot/restore). The paper holder's
// recovery role and a recovery contact's are here too.

import { bytesToHex, randomBytes, hexToBytes, sha, shaHex, jcsBytes, refuse, KeykinError, utf8ToBytes, b64u, strictJson, utf8Strict } from '../src/bytes.ts';
import { stateHash, pickSalt, detachedDigest, recoveryWaitId, seatedDigest, signpostD, signpostH, what } from '../src/codes.ts';
import * as nip44 from 'nostr-tools/nip44';
import { checkEpochRecord, checkOwnShares } from '../src/record.ts';
import { computeMembership, takenIndices, signpostCount, signpostServers, adopt, type Membership } from '../src/membership.ts';
import { CoSigner } from '../src/cosigner.ts';
import { OneCall, TwoCall, ListCall, ecdhRequest, ecdhFinish } from '../src/coordinator.ts';
import { nip44Open } from '../src/nip44.ts';
import { Nip46Home, listKey } from './nip46.ts';
import { DataKeys } from './datakey.ts';
import { memberSign } from './membersig.ts';
import { Members } from './members.ts';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { cbc } from '@noble/ciphers/aes.js';
import { base64 } from '@scure/base';
import { enrollReply } from '../src/serverprofile.ts';
import { makeHeir, pieceAckDigest } from '../src/backup.ts';
import { backupPieces } from '../src/slip39.ts';
import { dkg1, dkg2, dkg3 } from '../src/dkg.ts';
import { checkDelivery, verifyPaperItem, reissueItem, checkReissue, deal as dealRedeal, applyRedeal, applicable, commitmentAt, stateOf, itemHash, type State, type Item, type Dealt } from '../src/redeal.ts';
import { signpostContent, acceptUpload, redealMissing, postListView, postListBackup, rerepairProof, verifyRerepair, needRepairAllowed, baseItem, openMaterial, type Upload } from '../src/upkeep.ts';
import { RepairHelper } from '../src/repair.ts';
import { repairShare } from '../src/frost.ts';
import { Inbox, PushRegistry, pushPayload, readPush } from '../src/inbox.ts';
import { encryptPush, decryptPush, vapidHeader, checkVapid } from '../src/webpush.ts';
import { p256 } from '@noble/curves/nist.js';
import { wrap, unwrap } from '../src/transport.ts';
import { Inviter, Joiner, parseCode } from '../src/join.ts';
import { approveRecovery, approveLock, approvePaper, approvePaperRequest, placeholderList } from '../src/approval.ts';
import { deletedDigest, verifyDeleted } from '../src/requests.ts';
import { F1Watch, SignWatch, signNotice, signAnswer } from '../src/f1.ts';
import { commitmentFrom, scalarHex, scalarFrom, liftX, type Commitment } from '../src/curve.ts';
import { newKey, pubOf, siteEvent, schnorrSign, schnorrVerify, type KeyPair, type NostrEvent, type Unsigned } from '../src/event.ts';
import { KIND_CHANGE, KIND_SIGNPOST, type Approval, type Change, type EpochContent, type MemberEntry, type Redeal, type Waited } from '../src/types.ts';
import { softLock, type Lock } from '../src/lock.ts';
import { TRANSPORT_FAILED, type Transport, type Node, type PushOut } from '../runtime/net.ts';
import { msg, rid } from '../src/msg.ts';

// --- devices -----------------------------------------------------------------------------

export class DeviceNode implements Node {
  kp = newKey();
  lock: Lock | null;
  rec: EpochContent | null = null; recEv: NostrEvent | null = null;
  changes: NostrEvent[] = [];
  m: Membership | null = null;
  state: State | null = null;
  seeds = new Map<string, string>(); items: Item[] = []; base: Item | null = null;
  baseDk = ''; dkSeeds: string[] = [];
  co: CoSigner | null = null;
  repair = new RepairHelper();
  joiner: Joiner | null = null; inviter: Inviter | null = null;
  pendingSigmas: { from: string; index: number; sigma: string; state: string }[] = [];
  wiped = false;
  /** Core §4.3 step 4: on a lockless account, the backup secret kept sealed (5 points), approving what a
   *  paper would, until any device has a lock or a paper is read back. */
  keptSecret: KeyPair | null = null;
  /** A `paper` approval from the kept secret, with a challenge the server bound to the backup key. */
  async approveWithKept(list: Change[]): Promise<Approval> {
    if (!this.keptSecret) refuse('no_kept_secret');
    const s = this.servers().find((x) => this.bus.alive(x.key))!;
    const ch = await this.bus.send(this.keptSecret!, s.key, msg('challenge', this.g, this.epochId, 'ask'));
    const host = [...this.m!.members.values()].find((x) => x.key === s.key)!.host!;
    return approvePaper(this.g, this.epochId, approvalListOf(list), this.now + 3600, this.kp, this.keptSecret!, ch.challenge, host);
  }
  /** Tell every device the kept copies may go (`kept_done`), naming the change that registered a lock. */
  async keptDone(changeId: string) {
    for (const d of [...this.m!.members.values()].filter((x) => x.kind === 'device' && x.key !== this.kp.pub)) await this.bus.send(this.kp, d.key, { type: 'kept_done', change: changeId });
    this.keptSecret = null;
  }
  /** A device, or the opt-in helper (F6): same node, different rules in the co-signer. */
  role: 'device' | 'helper' = 'device';
  /** Security displays this device owes its person (§1.1 item 8). */
  notices: { kind: string; member: string }[] = [];
  /** A device's own destructive policy (Device policy module): here, always yes. */
  policy = (_e: Unsigned, _f: string) => true;
  bus: Transport; name: string;
  constructor(bus: Transport, name: string, lock: Lock | null) { this.bus = bus; this.name = name; this.lock = lock; }
  /** Where this device's state goes (an app's store: a sealed file, chrome.storage, Android Keystore-sealed
   *  prefs). Written after every message it handles and every change to its membership. */
  store: { save(key: string, text: string): void } | null = null;
  storeKey = '';
  attach(store: { save(key: string, text: string): void }, key = `device-${this.kp.pub.slice(0, 16)}`) { this.store = store; this.storeKey = key; this.persist(); return this; }
  persist() { if (this.store && (this.rec || this.wiped)) this.store.save(this.storeKey, this.snapshot()); }
  get now() { return this.bus.now; }
  get g() { return this.rec!.g; }
  get epochId() { return this.rec!.epoch.id; }
  ctx() { return { g: this.g, epochId: this.epochId, state: stateOf(this.state!), C: this.state!.C }; }
  me() { return { key: this.kp.pub, indices: [...this.state!.shares.keys()], shares: this.state!.shares }; }
  servers() { return [...this.m!.seats.entries()].filter(([k, s]) => k.startsWith('server:') && s.holder).map(([, s]) => s.holder!); }

  adopt(recEv: NostrEvent, changes: NostrEvent[], state: State) {
    this.recEv = recEv; this.rec = checkEpochRecord(recEv, { g: recEv.pubkey, own: { shares: state.shares, C: state.C, device: true } });
    this.changes = [...changes]; this.state = state;
    this.recompute();
    this.#afterState();
  }
  recompute() {
    this.m = computeMembership(this.rec!, this.changes);
    this.co = new CoSigner({ me: this.kp, kind: this.role, now: () => this.now, record: this.rec!, changes: this.changes, state: this.state!, policy: (e, f) => this.policy(e, f) });
    if (this.m.removed.has(this.kp.pub)) this.wipe();
    this.members.update();
    this.persist();
  }
  /** A removed or wiped member destroys everything it holds (core §7.3), the backup secret, push keys and
   *  watches included (review 9 H2). */
  wipe() {
    this.wiped = true; this.state = { ids: new Set(), C: this.state!.C, shares: new Map() };
    this.seeds.clear(); this.items = []; this.base = null; this.baseDk = ''; this.dkSeeds = []; this.dataKeys?.clear();
    this.keptSecret = null; this.kept.clear(); this.pendingDeltas.clear(); this.paperVerified.clear(); this.pendingHeir = null;
    this.pushKeys.clear(); this.notices = []; this.#f1 = null; this.signWatch = new SignWatch();
    this.nip46?.sleep(); this.nip46 = new Nip46Home(this);   // signer keys go with everything else (core §7.3)
  }
  /** Account admin §3: after a delete, only the request, the first `deleted` and the servers' endpoints,
   *  kept so the device can go on sending until each server answers. */
  deleted: { request: any; first: any; endpoints: { key: string; host: string; https?: string }[] } | null = null;
  refusedChanges: NostrEvent[] = [];
  takeChanges(evs: NostrEvent[]) {
    const r = adopt(this.rec!, this.changes, [...evs, ...this.refusedChanges], this.m?.authority.W);
    this.changes = r.changes; this.refusedChanges = r.refused.map((x) => x.ev);
    this.recompute();
  }

  // ---- driving ----
  /** Sign an event with the first live server that answers; `stale` brings us forward and retries. */
  async sign(ev: Partial<Unsigned>, extra: { approval?: Approval; hold?: string; list_events?: NostrEvent[]; material?: Item } = {}): Promise<NostrEvent> {
    // The site's event as §9.5 reads it: absent fields filled, its id, sig and extra fields dropped.
    const { id: _id, ...event } = siteEvent({ created_at: this.now, kind: 1, ...ev }, this.g);
    let lastErr = 'no_server';
    // A refusal that says what the event needs wins over a server that didn't answer (review 12 H4).
    const telling = new Set(['needs_approval', 'hold_not_passed', 'declined', 'dated_ahead', 'machinery', 'wrong_pubkey']);
    const note = (code: string) => { if (!telling.has(lastErr)) lastErr = code; };
    // Core §6.7.9: requests a server left with nothing (no answer, or a partial that doesn't verify; an
    // `error` never counts), reported once another server co-signed the same event.
    const silent: { host: string; id: string }[] = [];
    for (const s of this.servers()) {
      if (!this.bus.alive(s.key)) { note('unreachable'); continue; }
      for (let tries = 0; tries < 2; tries++) {
        const r = new OneCall(this.ctx(), this.me(), { key: s.key, indices: s.shares }, event, extra);
        const a = await this.bus.send(this.kp, s.key, r.request);
        if (a?.type === 'stale') { r.abandon(); await this.fetch(); continue; }
        // No answer: nothing at all, or the transport's own timeout (never an error the server sealed).
        if (a === null || a === undefined || a[TRANSPORT_FAILED]) { r.abandon(); silent.push({ host: s.host!, id: r.request.id }); note('no_answer'); break; }
        if (a?.type !== 'partial') { r.abandon(); note(a?.code ?? 'no_answer'); if (a?.code && telling.has(a.code)) lastErr = a.code; this.lastDetail = a?.detail; break; }
        let signed: NostrEvent;
        try { signed = r.finish(a); } catch (e) { silent.push({ host: s.host!, id: r.request.id }); note((e as KeykinError).code ?? 'bad_partial'); break; }
        for (const x of silent) this.signWatch.unanswered(x.host, x.id, this.now, true);
        this.signWatch.partial(s.host!, r.request.id, this.now);
        const lk = listKey(signed);
        if (lk && signed.created_at > (this.#lists.get(lk) ?? 0)) { this.#lists.set(lk, signed.created_at); }
        return signed;
      }
    }
    throw new KeykinError(lastErr, this.lastDetail);
  }

  /** A whole list with the first live server that answers (§6.7.10). */
  async signList(evs: Unsigned[], extra: { material?: Item } = {}): Promise<NostrEvent[]> {
    let lastErr = 'no_server';
    for (const s of this.servers()) {
      if (!this.bus.alive(s.key)) { lastErr = 'unreachable'; continue; }
      for (let tries = 0; tries < 2; tries++) {
        const r = new ListCall(this.ctx(), this.me(), { key: s.key, indices: s.shares }, evs, extra);
        const a = await this.bus.send(this.kp, s.key, r.request);
        if (a?.type === 'stale') { r.abandon(); await this.fetch(); continue; }
        if (a?.type !== 'partial') { r.abandon(); lastErr = a?.code ?? 'no_answer'; this.lastDetail = a?.detail; break; }
        return r.finish(a);
      }
    }
    throw new KeykinError(lastErr, this.lastDetail);
  }

  /** Catch up: the union of every server's change set, then every server's inbox (§3.2, §8.2). */
  async fetch() {
    for (const s of this.servers()) {
      const a = await this.bus.send(this.kp, s.key, msg('changes_get', this.g, this.epochId, 'ask'));
      if (a?.type === 'changes') this.takeChanges(a.changes);
    }
    if (this.wiped) return;
    for (const s of this.servers()) {
      const a = await this.bus.send(this.kp, s.key, msg('inbox_get', this.g, this.epochId, 'ask'));
      if (a?.type !== 'inbox') continue;
      for (const it of a.items) try {
        // A site's request a watching server kept goes to the NIP-46 home, not into the void (review 11 M1).
        const o = unwrap(this.kp.sk, it.wrap);
        if (o.body?.type === 'nip46' && o.from === s.key) await this.nip46.handle(o.body.event);
        else this.takeDelivery(it.wrap);
      } catch { /* one bad item never wedges the rest */ }
      await this.bus.send(this.kp, s.key, msg('inbox_ack', this.g, this.epochId, 'ask', { iids: a.items.map((x: any) => x.iid) }));
    }
    this.applyAll();
    if (this.notices.some((n) => n.kind === 'bad_paper_item')) await this.reissueMissing();
  }
  pendingDeltas = new Map<string, any>();
  pendingHeir: ReturnType<typeof makeHeir> | null = null;
  /** Paper values kept per redeal (§6.7.1 step 3), encrypted at rest in a real app. */
  kept = new Map<string, { b: number[]; d: bigint[]; dk: string; release: string }>();
  f7 = false;
  /** "Paper item verified" bits, per backup key and redeal (§6.7.6, 14.12). */
  paperVerified = new Map<string, boolean>();
  lastDetail: string | undefined;
  takeDelivery(w: NostrEvent) {
    const o = unwrap(this.kp.sk, w);
    if (o.body.type === 'delta') {
      // Only the redeal's dealer's delta counts; a stranger's never replaces it (§6.7.3).
      const r = this.m!.redeals.get(o.body.redeal)?.r;
      if (r && o.from !== r.dealer) return;
      this.pendingDeltas.set(o.body.redeal, { ...o.body, from: o.from });
    }
  }
  /** Apply every redeal we hold a delta for (§6.7.1), checking our rebuilt commitment each time. */
  applyAll() {
    const m = this.m!;
    for (let again = true; again;) {
      again = false;
      for (const { r } of m.redeals.values()) {
        const d = this.pendingDeltas.get(r.id);
        if (!d || applicable(this.state!, r, m.abandoned)) continue;
        try { checkDelivery(r, d.from ?? r.dealer, d, this.role === 'device'); } catch { this.pendingDeltas.delete(r.id); this.notices.push({ kind: 'bad_delivery', member: d.from }); continue; }
        // §6.7.1 step 0: the paper item, opened with its conversation key; a bad one is shown.
        if (d.paper_item && d.paper_ck) {
          const ok = verifyPaperItem(r, d.paper_item, d.release, d.paper_ck, m.record.seats.backup);
          this.paperVerified.set(`${m.backupKey}:${r.id}`, ok);
          if (!ok) this.notices.push({ kind: 'bad_paper_item', member: r.dealer });
        }
        const deltas = new Map<number, bigint>(d.deltas.map(([i, x]: [number, string]) => [i, scalarFrom(x)]));
        const { state, paperValues } = applyRedeal(m.g, this.state!, r, deltas, true, m.record.seats.backup, m.abandoned);
        this.state = state; this.pendingDeltas.delete(r.id);
        // §6.7.1 step 3: keep δ(b) and the data-key seed until the current paper's item is verified, or,
        // on the device running an F7, until its paper change commits (14.12).
        const verified = this.paperVerified.get(`${m.backupKey}:${r.id}`) === true;
        if (paperValues && (!verified || this.f7)) this.kept.set(r.id, { b: m.record.seats.backup, d: paperValues, dk: d.dk, release: d.release });
        if (d.release) this.seeds.set(r.id, d.release);
        if (d.dk && !this.dkSeeds.includes(d.dk)) this.dkSeeds.push(d.dk);
        this.#afterState();                                 // the new state, now that its seed is in (core §4.5)
        again = true;
      }
    }
    this.recompute();
  }

  approveLock(list: Change[]): Approval { return approveLock(this.g, this.epochId, list, this.now + 3600, this.kp.pub, this.lock!); }

  /** Make, co-sign and deliver a list (§6.7.6: one approval, the dealer uploads, one server co-signs,
   *  the dealer destroys δ, everyone applies). `extraView` adds incoming members for the deltas. */
  async submit(list: Change[], approval: Approval, o: { cosigner?: (evs: Unsigned[], extra: object) => Promise<NostrEvent[]>; dieAfterUpload?: boolean; deliverTo?: string[];
    /** After dealing, before the co-sign: fill in the list (F7's paper `inner`/`state`) and the material. */
    finish?: (dealt: Dealt) => Promise<{ full: Change[]; material?: Item }> } = {}): Promise<NostrEvent[]> {
    const m = this.m!;
    let dealt: Dealt | null = null;
    let full = list;
    if (list.some((c) => 'redeal' in c)) {
      const view = postListView(m, list);
      const recips = new Map([...view.values()].map((x) => [x.key, x.shares]));
      dealt = dealRedeal(this.g, this.kp, [...this.state!.ids], recips, postListBackup(m, list), m.record.seats.backup);
      const items = [...view.values()].map((x) => ({ type: 'delta', to: x.key, release: x.kind !== 'helper',
        wrap: wrap(this.kp.sk, x.key, { type: 'delta', redeal: dealt!.redeal.id,
          deltas: [...dealt!.deltas.get(x.key)!].map(([i, d]) => [i, scalarHex(d)]),
          ...(x.kind !== 'helper' ? { release: dealt!.releaseSeed } : {}),
          ...(x.kind === 'device' ? { dk: dealt!.dkSeed, paper_ck: dealt!.paperCk, paper_item: dealt!.paperItem } : {}) }) }));
      (dealt as any).uploadItems = items;
      // The heir record and each server's piece travel with the list as inert uploads (Backup §1.1 step 5).
      const h = this.pendingHeir;
      if (h) for (const x of [...view.values()].filter((y) => y.kind === 'server'))
        items.push({ type: 'heir_piece', to: x.key, release: false, wrap: wrap(this.kp.sk, x.key, { type: 'heir_piece', x: x.shares[0], piece: scalarHex(h.pieces.get(x.shares[0])!) }) });
      const up = msg('upload', this.g, this.epochId, 'member', { list: approvalListOf(list), approval, redeal: dealt.redeal.id, items, paper_item: dealt.paperItem, ...(h ? { heir_record: h.record } : {}) });
      for (const s of [...view.values()].filter((x) => x.kind === 'server')) await this.bus.send(this.kp, s.key, up);
      full = list.map((c) => ('redeal' in c ? { redeal: dealt!.redeal } : c));
      if (o.dieAfterUpload) { dealt.destroy(); this.bus.kill?.(this.kp.pub); return []; }
    }
    let material: Item | undefined;
    if (o.finish && dealt) { const f = await o.finish(dealt); full = f.full; material = f.material; }
    let signed: NostrEvent[];
    try {
      // Every event of the list in one request, each with its own nonces (§6.7.10, §5.2).
      const evs: Unsigned[] = full.map((c) => ({ pubkey: this.g, created_at: this.now, kind: KIND_CHANGE, tags: [['v', '1'], ['epoch', this.epochId]],
        content: JSON.stringify({ v: 1, g: this.g, epoch: this.epochId, change: c, list: approvalListOf(list), approval }) }));
      const extra = material ? { material } : {};
      signed = o.cosigner ? await o.cosigner(evs, extra) : evs.length === 1 ? [await this.sign(evs[0], extra as any)] : await this.signList(evs, extra);
    } catch (e) { dealt?.destroy(); throw e; }
    // Deliver the list as one to every server (and live device); then apply our own delta and destroy δ.
    const targets = o.deliverTo ?? [...m.members.values(), ...postListView(m, list).values()].filter((x) => x.kind === 'server').map((x) => x.key);
    for (const t of new Set(targets)) await this.bus.send(this.kp, t, { type: 'change', events: signed, ...(material ? { material } : {}) });
    // Live devices get the list and their own delivery directly (21059); asleep ones fetch from inboxes.
    if (dealt) for (const x of postListView(m, list).values()) if (x.kind === 'device' && x.key !== this.kp.pub && this.bus.alive(x.key)) {
      await this.bus.send(this.kp, x.key, { type: 'change', events: signed });
      const w = (dealt as any).uploadItems?.find((it: any) => it.to === x.key)?.wrap;
      if (w) await this.bus.send(this.kp, x.key, { type: 'delta_push', wrap: w });
    }
    if (material) this.base = material;
    this.takeChanges(signed);
    if (dealt && !this.wiped) {
      const mine = dealt.deltas.get(this.kp.pub);
      if (mine) this.pendingDeltas.set(dealt.redeal.id, { type: 'delta', redeal: dealt.redeal.id, deltas: [...mine].map(([i, d]) => [i, scalarHex(d)]), release: dealt.releaseSeed, dk: dealt.dkSeed,
        paper_ck: dealt.paperCk, paper_item: dealt.paperItem, from: this.kp.pub });
      this.applyAll();
      dealt.destroy();
    }
    return signed;
  }

  /** Publish the signpost (§6.7.5): co-signed like any event (the co-signer checks `n` and `h`), then
   *  its id delivered to every server so each refuses a delete aimed at it. */
  async publishSignpost(): Promise<NostrEvent> {
    const m = this.m!;
    const ev = await this.sign({ kind: KIND_SIGNPOST, tags: [['d', signpostD(m.backupKey!)], ['n', String(signpostCount(m))], ['h', signpostH(m.epochId, signpostServers(m))]],
      content: signpostContent(m.backupKey!, this.baseDk, signpostServers(m)) });
    for (const s of this.servers()) await this.bus.send(this.kp, s.key, { type: 'signpost_id', id: ev.id, event: ev });
    (this.bus as any).published?.push(ev);
    return ev;
  }

  /** F7, a new paper (§6.7.6, §4.3): approve `[paper K, redeal]`, repair the backup seat towards K
   *  with one server, wrap and sign the base under the redeal's release seed, then commit. Returns K
   *  (in real life, printed and read back before step 4). */
  async newPaper(approve: (list: Change[]) => Approval, o: { duringF7?: () => Promise<void>; heir?: string; holders?: FriendNode[] } = {}): Promise<KeyPair> {
    this.f7 = true;
    try { return await this.newPaperInner(approve, o); }
    finally { this.f7 = false; }
  }
  private async newPaperInner(approve: (list: Change[]) => Approval, o: { duringF7?: () => Promise<void>; heir?: string; holders?: FriendNode[] }): Promise<KeyPair> {
    const K = newKey();
    // Backup §4.1: an heir's envelope of K, its hash pinned in the approved paper change.
    const heir = o.heir ? makeHeir({ g: this.g, setId: K.pub, heirKey: o.heir, secret: K.sk, card: 'card', seats: this.m!.record.seats.servers }) : null;
    this.pendingHeir = heir;
    // Backup §1.1 step 5: the holder keys kept in the set, pinned by hash in the approved change.
    const holders = o.holders?.map((f) => bytesToHex(sha(hexToBytes(f.kp.pub)))).sort();
    const list: Change[] = [{ paper: { key: K.pub, replaces: this.m!.backupKey!, ...(heir ? { heir: heir.recordHash } : {}), ...(holders ? { holders } : {}) } }, { redeal: { dealer: this.kp.pub } }];
    const approval = approve(list);
    await this.submit(list, approval, { finish: async (dealt) => {
      const server = this.servers().find((x) => this.bus.alive(x.key))!;
      const helpers = [{ key: this.kp.pub, indices: [...this.state!.shares.keys()] }, { key: server.key, indices: server.shares }];
      const shares = new Map<number, bigint>();
      for (const b of this.m!.record.seats.backup) {
        const ws = await this.repairFor(helpers, b, K.pub, 'paper', { list: approvalListOf(list), approval });
        shares.set(b, repairShare(this.state!.C, ws.map((w) => unwrap(K.sk, w).body.sigma), b));
      }
      const repairedAt = [...this.state!.ids].sort();
      const base = baseItem(K, dealt.releaseSeed, shares, this.baseDk, repairedAt);
      shares.clear();
      await o.duringF7?.();                                  // the person prints and reads back; others go on
      // Backup §1.1 step 3: hand every friend its SLIP-39 piece (2 of 3) with the account card, live,
      // sealed to its pinned holder key; commit only once enough pieces are acknowledged (step 4).
      if (o.holders) {
        const pieces = backupPieces(K.sk);
        let acked = 0;
        for (const [k, f] of o.holders.entries()) {
          const a = await this.bus.send(this.kp, f.kp.pub, { type: 'piece', g: this.g, set: K.pub, piece: pieces[k], card: 'card' });
          if (a?.type === 'piece_ack' && schnorrVerify(a.sig, pieceAckDigest(this.g, K.pub, utf8ToBytes(pieces[k])), f.kp.pub)) acked++;
        }
        if (acked < 2) refuse('set_not_recoverable', 'fewer than two pieces acknowledged');
      }                                        // the device keeps K only until the read-back
      return { full: [{ paper: { key: K.pub, replaces: this.m!.backupKey!, inner: itemHash(base), state: repairedAt, ...(heir ? { heir: heir.recordHash } : {}), ...(holders ? { holders } : {}) } }, { redeal: dealt.redeal }], material: base };
    } });
    await this.reissueMissing();
    if (this.keptSecret) {
      // A lockless account keeps the new key's secret the same way, and every lockless device gets it.
      this.keptSecret = K;
      for (const d of [...this.m!.members.values()].filter((x) => x.kind === 'device' && x.key !== this.kp.pub && !x.lock))
        await this.bus.send(this.kp, d.key, { type: 'kept_new', secret: bytesToHex(K.sk) });
    }
    return K;
  }

  /** §6.7.6: for each redeal this device applied that the current paper's state lacks and that has no
   *  verified item for the current K, re-issue the item from the kept values; then destroy them. */
  async reissueMissing() {
    const m = this.m!, K = m.backupKey!;
    const pc = m.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === K);
    const paperState = new Set<string>(pc ? (pc.c.change as any).paper.state : []);
    const own = pc ? [...m.redeals.values()].find((x) => x.listHash === pc.listHash)?.r.id : undefined;
    for (const id of this.state!.ids) {
      if (paperState.has(id) || id === own || this.paperVerified.get(`${K}:${id}`)) { this.kept.delete(id); continue; }
      const v = this.kept.get(id), r = m.redeals.get(id)?.r;
      if (!v || !r) continue;                                     // nothing to re-issue from: a new paper (quiet dot)
      const item = reissueItem(this.g, r, K, v.release, v, this.kp);
      for (const s of this.servers()) await this.bus.send(this.kp, s.key, msg('paper_reissue', this.g, this.epochId, 'member', { item }));
      this.paperVerified.set(`${K}:${id}`, true);
      this.kept.delete(id);
    }
  }

  /** Account admin §3 "Destroy my key": sent to every server; this device destroys its copy only once
   *  two servers have answered `deleted`. */
  async deleteAccount(o: { paper?: KeyPair } = {}): Promise<number> {
    const body = msg('account_delete', this.g, this.epochId, 'member', {});
    const req = { ...body, approval: await this.approveRequest('account_delete', body, o.paper) };
    // Only a `deleted` that proves this very request counts (review 8 L6).
    let n = 0, first: any = null;
    for (const s of this.servers()) {
      const a = await this.bus.send(this.kp, s.key, req);
      if (verifyDeleted(this.m!, this.g, a) && a.request.id === req.id && a.host === s.host) { n++; first ??= a; }
    }
    if (n >= 2) {
      const endpoints = this.servers().map((s) => ({ key: s.key, host: s.host!, https: s.https }));
      this.wipe();
      this.deleted = { request: req, first, endpoints };
    }
    return n;
  }

  /** Approve a request that every server checks and no co-signer joins: by this device's lock, or by
   *  the paper, this device plus the backup key over a challenge from every server (core §6.2). */
  async approveRequest(type: string, body: any, paper?: KeyPair): Promise<any> {
    const w = what.request(type, body.id, body);
    if (!paper) return { lock: { member: this.kp.pub, assertion: this.lock!.assert(this.g, w) } };
    const challenges: { server: string; challenge: string }[] = [];
    // Labelled with the host of the seat asked, never with what the answer claims (review 8 M1).
    for (const s of this.servers()) {
      const ch = await this.bus.send(paper, s.key, msg('challenge', this.g, this.epochId, 'ask'));
      if (ch?.type === 'challenge' && typeof ch.challenge === 'string') challenges.push({ server: s.host!, challenge: ch.challenge });
    }
    return approvePaperRequest(this.g, w, this.kp, paper, challenges);
  }

  /** Helper module §3.2 "Resume helper": clears exactly the stops this device has seen, at every server. */
  async resumeHelper(ids: string[], o: { paper?: KeyPair } = {}): Promise<any[]> {
    const body = msg('helper_resume', this.g, this.epochId, 'member', { ids });
    const req = { ...body, approval: await this.approveRequest('helper_resume', body, o.paper) };
    const out: any[] = [];
    for (const s of this.servers()) out.push(await this.bus.send(this.kp, s.key, req));
    return out;
  }

  // --- Durable state (core §4.4's handover list): what a device keeps across a restart -----------
  /** Everything a `welcome` carries (member key and shares, state, record and changes, release seeds,
   *  material, base data key and data-key seeds, a kept backup secret), plus what this device holds
   *  between rounds: paper deltas kept for 30 days, deliveries waiting for their redeal, its push keys,
   *  notices and both watches. Never nonces, a round, a join, a repair or a heir setup in flight (§5.2). */
  snapshot(): string {
    // Wiped: nothing of the account; after a delete, only what Account admin §3 keeps.
    if (this.wiped) return JSON.stringify({ v: 1, name: this.name, wiped: true, deleted: this.deleted });
    const st = this.state;
    return JSON.stringify({ v: 1, name: this.name, role: this.role, kp: bytesToHex(this.kp.sk), lock: this.lock && (this.lock.stored?.() ?? { pub: this.lock.pub }),
      recEv: this.recEv, changes: this.changes, refused: this.refusedChanges, wiped: this.wiped,
      state: st && { ids: [...st.ids], shares: [...st.shares].map(([i, s]) => [i, scalarHex(s)]) },
      seeds: [...this.seeds], items: this.items, base: this.base, baseDk: this.baseDk, dkSeeds: this.dkSeeds,
      keptSecret: this.keptSecret && bytesToHex(this.keptSecret.sk),
      kept: [...this.kept].map(([k, x]) => [k, { ...x, d: x.d.map(scalarHex) }]), paperVerified: [...this.paperVerified],
      pendingDeltas: [...this.pendingDeltas], notices: this.notices,
      pushKeys: [...this.pushKeys].map(([u, k]) => [u, { ...k, sk: bytesToHex(k.sk), auth: bytesToHex(k.auth) }]),
      f1: this.#f1?.dump() ?? null, signWatch: this.signWatch.dump(), nip46: this.nip46.dump(), dkHistory: this.dataKeys.dump(), members: this.members.dump(), lists: [...this.#lists] });
  }
  /** A device restarted from storage, checked as core §4.4's handover step 2 says: the record and changes
   *  by §3.4, every share against the commitments, and the member key a current device holding exactly
   *  those indices. A wiped device restores as wiped. */
  static restore(bus: Transport, json: string, o: { lock?: (stored: any) => Lock | null } = {}): DeviceNode {
    const x = strictJson(json);
    if (x.v !== 1) refuse('malformed', 'storage version');
    if (x.wiped && !x.kp) { const w = new DeviceNode(bus, x.name, null); w.wiped = true; w.deleted = x.deleted ?? null; return w; }
    // A soft lock comes back from its key; any other lock the app reopens (`o.lock`).
    const lock = !x.lock ? null : o.lock ? o.lock(x.lock) : x.lock.soft ? softLock(x.lock.soft.rp, hexToBytes(x.lock.soft.sk)) : refuse('lock_unavailable', 'a hardware lock is reopened by the app');
    const d = new DeviceNode(bus, x.name, lock);
    d.kp = { sk: hexToBytes(x.kp), pub: pubOf(hexToBytes(x.kp)) }; d.role = x.role;
    x.seeds.forEach(([k, v]: [string, string]) => d.seeds.set(k, v));
    d.items = x.items; d.base = x.base; d.baseDk = x.baseDk; d.dkSeeds = x.dkSeeds;
    d.keptSecret = x.keptSecret ? { sk: hexToBytes(x.keptSecret), pub: pubOf(hexToBytes(x.keptSecret)) } : null;
    d.kept = new Map(x.kept.map(([k, v]: [string, any]) => [k, { ...v, d: v.d.map(scalarFrom) }]));
    d.paperVerified = new Map(x.paperVerified); d.pendingDeltas = new Map(x.pendingDeltas); d.notices = x.notices;
    d.pushKeys = new Map(x.pushKeys.map(([u, k]: [string, any]) => [u, { ...k, sk: hexToBytes(k.sk), auth: hexToBytes(k.auth) }]));
    d.signWatch.load(x.signWatch);
    d.nip46.load(x.nip46);
    d.dataKeys.load(x.dkHistory);
    d.members.load(x.members);
    d.#lists = new Map(x.lists ?? []);
    if (x.recEv && x.state) {
      const rec = checkEpochRecord(x.recEv, { g: x.recEv.pubkey });
      const m = computeMembership(rec, x.changes);
      const C = commitmentAt(commitmentFrom(rec.commitment), [...m.redeals.values()].filter((r) => x.state.ids.includes(r.r.id)).map((r) => r.r));
      const shares = new Map<number, bigint>(x.state.shares.map(([i, s]: [number, string]) => [i, scalarFrom(s)]));
      if (!x.wiped) {
        const me = m.members.get(d.kp.pub);
        const want = [...(me?.shares ?? [])].sort((a, b) => a - b).join(',');
        if (!me || me.kind !== d.role || m.removed.has(d.kp.pub) || [...shares.keys()].sort((a, b) => a - b).join(',') !== want) refuse('not_member', 'the stored key is not a current member holding exactly these indices');
        checkOwnShares(rec.g, shares, C, false);
      }
      d.recEv = x.recEv; d.rec = rec; d.changes = [...x.changes]; d.refusedChanges = x.refused; d.state = { ids: new Set(x.state.ids), C, shares };
      d.recompute();
      d.wiped = x.wiped;
      if (x.f1) d.f1().load(x.f1);
    }
    return d;
  }

  // --- the account's own encryption (core §5.5): ECDH with a co-signer, never the whole key ---------
  /** The x coordinate of `x·P` for a peer's x-only key `peer`, from one server's checked answer. */
  async ecdhX(peer: string): Promise<Uint8Array> {
    // A peer key that isn't a point is refused here, before any co-signer is asked (review 11 L5).
    if (typeof peer !== 'string' || !/^[0-9a-f]{64}$/.test(peer)) refuse('malformed', 'peer key');
    try { liftX(peer); } catch { refuse('malformed', 'peer key is not on the curve'); }
    const Q = '02' + peer;
    let last = 'no_server';
    for (const s of this.servers()) {
      if (!this.bus.alive(s.key)) continue;
      for (let tries = 0; tries < 2; tries++) {
      const req = ecdhRequest(this.ctx(), [...this.state!.shares.keys()], { key: s.key, indices: s.shares }, [Q]);
      const a = await this.bus.send(this.kp, s.key, req);
      if (a?.type === 'stale') { await this.fetch(); continue; }
      try { return hexToBytes(ecdhFinish(this.ctx(), req, this.me(), { key: s.key, indices: s.shares }, a)[0].slice(2)); }
      catch (e) { last = (e as KeykinError).code ?? 'ecdh'; break; }
      }
    }
    throw new KeykinError(last);
  }
  /** NIP-44 v2 as the account, with `peer`. */
  async nip44(peer: string, text: string, encrypt: boolean): Promise<string> {
    const ck = extract(sha256, await this.ecdhX(peer), utf8ToBytes('nip44-v2'));
    return encrypt ? nip44.v2.encrypt(text, ck) : nip44Open(text, ck);
  }
  /** NIP-04 as the account, with `peer` (AES-256-CBC under the shared x). */
  async nip04(peer: string, text: string, encrypt: boolean): Promise<string> {
    const key = await this.ecdhX(peer);
    if (encrypt) { const iv = randomBytes(16); return `${base64.encode(cbc(key, iv).encrypt(utf8ToBytes(text)))}?iv=${base64.encode(iv)}`; }
    const [ct, iv] = text.split('?iv=');
    if (!ct || !iv) refuse('malformed', 'nip04 payload');
    return utf8Strict(cbc(key, base64.decode(iv)).decrypt(base64.decode(ct)));
  }

  // --- for other protocols: the account's devices, and signing with this device's member key ------
  /** The account's devices and removals, for apps that check member-key signatures (core 14.19 §5.9). */
  members = new Members(this);
  /** The current device member keys (helpers, servers and the backup are not devices). */
  memberKeys(): string[] { return this.members.devices().keys.map((k) => k.key); }
  #afterState() { this.dataKeys.note(); this.members.update(); }
  /** Sign `message` under a registered `domain` with this device's member key (device/membersig.ts). */
  signAsMember(domain: string, message: Uint8Array): { sig: string; key: string } {
    if (this.wiped) refuse('wiped');
    return { sig: memberSign(this.kp.sk, domain, message), key: this.kp.pub };
  }

  /** The newest version of each list this device signed (Device policy §4): kind (and d) → created_at. */
  #lists = new Map<string, number>();
  latestList(key: string) { return this.#lists.get(key) ?? 0; }

  /** The data key (core §4.5), for libraries that encrypt the account's own data. */
  dataKeys = new DataKeys(this);
  /** NIP-46 sites this device is home to (Doors §3.3). */
  nip46 = new Nip46Home(this);

  /** Core §6.7.9's quiet Backup line: which servers haven't helped sign this week. */
  signWatch = new SignWatch();
  /** The hosts Backup shows "hasn't helped sign this week" for. */
  notHelping() { return this.servers().map((s) => s.host!).filter((h) => this.signWatch.line(h, this.now)); }

  /** §8.1: one gateway address per server and wake class, pinned to that server's VAPID key, each with
   *  its own RFC 8291 keys, so the addresses can't be linked across servers or accounts. */
  pushKeys = new Map<string, { sk: Uint8Array; auth: Uint8Array; vapid: string; cls: string }>();
  async registerPush(o: { gateway?: string } = {}): Promise<number> {
    let n = 0;
    for (const s of this.servers()) {
      const addresses = (['sign', 'ask', 'notice'] as const).map((cls) => {
        const sk = p256.utils.randomSecretKey(), auth = randomBytes(16), url = `${o.gateway ?? 'https://gw.test'}/${bytesToHex(randomBytes(16))}`;
        this.pushKeys.set(url, { sk, auth, vapid: s.vapid!, cls });
        return { cls, url, p256dh: b64u(p256.getPublicKey(sk, false)), auth: b64u(auth) };
      });
      const a = await this.bus.send(this.kp, s.key, msg('push_register', this.g, this.epochId, 'member', { addresses }));
      if (a?.type === 'ack') n++;
    }
    return n;
  }
  /** What reached this device's addresses: the gateway's VAPID check (§8.3), then RFC 8291 decryption
   *  and the host key's signature over the payload, from a seated server. */
  readPushes(): any[] {
    const hosts = new Set(this.servers().map((s) => s.host!));
    return (Array.isArray(this.bus.pushes) ? this.bus.pushes as PushOut[] : []).flatMap((p) => {
      const k = this.pushKeys.get(p.url);
      if (!k || checkVapid(p.authorization, p.url, k.vapid, this.now) !== null) return [];
      try { return [readPush(decryptPush(p.body, k.sk, k.auth), hosts)]; } catch { return []; }
    });
  }

  /** Core §6.7.7: this device's own view of which seated servers are dead, from what each answers. */
  #f1: F1Watch | null = null;
  f1(): F1Watch {
    if (!this.#f1) { this.#f1 = new F1Watch(this.g); for (const s of this.servers()) this.#f1.seat(s.host!, s.key, this.now); }
    return this.#f1;
  }
  /** Ask every seated server for the account's state and return the F1 card's seats. A `deleted` that
   *  verifies destroys this device's copy (Account admin §3) and returns null; one that doesn't, like
   *  "unknown account", counts as a denial. */
  /** Server profile §4.1: ask a seat's server for its current notice; only the live answer counts. */
  async askNotice(host: string) {
    const s = this.servers().find((x) => x.host === host);
    if (!s) return;
    const req = msg('notice_get', this.g, this.epochId, 'ask', {});
    this.f1().asked(host, req.id, this.now);
    const a = await this.bus.send(this.kp, s.key, req);
    if (a?.type === 'notice') this.f1().answer(a, s.key, this.now);
  }
  async checkServers(): Promise<{ seat: string; host: string; why: string }[] | null> {
    const w = this.f1();
    const seats = [...this.m!.seats.entries()].filter(([k, x]) => k.startsWith('server:') && x.holder).map(([seat, x]) => ({ seat, host: x.holder!.host!, key: x.holder!.key }));
    for (const s of seats) {
      w.seat(s.host, s.key, this.now);
      const a = await this.bus.send(this.kp, s.key, msg('state_get', this.g, this.epochId, 'ask'));
      if (a?.type === 'state') w.saw(s.host, 'serving', this.now);
      else if (a?.type === 'deleted') {
        if (verifyDeleted(this.m!, this.g, a)) { this.wipe(); return null; }
        w.saw(s.host, 'denied', this.now);
      } else if (a?.code === 'unknown_account') w.saw(s.host, 'denied', this.now);
      else w.saw(s.host, 'silent', this.now);
      if (a?.type === 'state') await this.askNotice(s.host);    // once a day in the catch-up round
    }
    return w.card(seats, this.now);
  }

  /** Run a repair for `participant` with helper members (this device and others), sealing every
   *  sigma to `seal_to`. Returns the sealed sigmas, for forwarding. */
  async repairFor(helpers: { key: string; indices: number[] }[], participant: number, seal_to: string, why: string, extra: object = {}): Promise<NostrEvent[]> {
    const st = stateOf(this.state!);
    const rid_ = rid();
    const start = { type: 'repair_start', participant, helpers, state: st, rid: rid_, why, seal_to, ...extra };
    const outs = new Map<string, Record<string, NostrEvent>>();
    for (const h of helpers) {
      const a = h.key === this.kp.pub ? this.repair.start(this.kp, this.state!.C, this.state!.shares, this.kp.pub, start, st) : await this.bus.send(this.kp, h.key, start);
      if (a?.type !== 'repair_delta') throw new KeykinError(a?.code ?? 'repair_refused', `${h.key.slice(0, 8)}: ${a?.detail ?? ''}`);
      outs.set(h.key, a.out);
    }
    const out: NostrEvent[] = [];
    for (const h of helpers) {
      const fin = { type: 'repair_finish', participant, rid: rid_, seal_to, deltas: helpers.filter((x) => x.key !== h.key).map((x) => outs.get(x.key)![h.key]) };
      const a = h.key === this.kp.pub ? this.repair.finish(this.kp, this.kp.pub, fin, st) : await this.bus.send(this.kp, h.key, fin);
      if (a?.type !== 'repair_sigma') throw new KeykinError(a?.code ?? 'repair_refused');
      out.push(a.wrap as NostrEvent);
    }
    return out;
  }

  async handle(from: string, body: any, sentAt: number): Promise<any> {
    const a = await this.handleMsg(from, body, sentAt);
    this.persist();
    return a;
  }
  private async handleMsg(from: string, body: any, sentAt: number): Promise<any> {
    try {
      switch (body.type) {
        case 'notice': if ('shutdown' in body && body.re === undefined && this.f1().pushed(body, this.now)) await this.askNotice(body.host); return { type: 'ack' };
        case 'join_hello': return this.inviter!.onHello(from, body, this.now).msg;
        case 'join_nonce': this.joiner!.onNonce(from, body); return { type: 'ack' };
        case 'welcome_offer': return this.joiner!.onOffer(from, body, this.now).msg;
        case 'repair_start': return this.co!.repairStart(from, body, this.now);
        case 'repair_finish': return this.co!.repairFinish(from, body);
        case 'change': this.takeChanges(body.events); return { type: 'ack' };
        case 'delta_push': this.takeDelivery(body.wrap); this.applyAll(); return { type: 'ack' };
        case 'kept_done': {
          // Only from a current device, and only once the named change registered a lock (§4.3 step 4).
          if (!this.m!.devices.has(from)) return { type: 'error', code: 'not_device' };
          const p = this.m!.accepted.find((x) => x.ev.id === body.change);
          const ok = p && ((p.type === 'lock') || (p.type === 'add' && (p.c.change as any).add.lock));
          if (!ok) return { type: 'error', code: 'no_lock_change' };
          this.keptSecret = null;
          return { type: 'ack' };
        }
        case 'kept_new': {
          // After an F7: the current backup key's secret, from a current device (§4.3 step 4).
          if (!this.m!.devices.has(from)) return { type: 'error', code: 'not_device' };
          const sk = hexToBytes(body.secret);
          if (pubOf(sk) !== this.m!.backupKey) return { type: 'error', code: 'not_current_backup' };
          this.keptSecret = { sk, pub: pubOf(sk) };
          return { type: 'ack' };
        }
        case 'need_seeds': {
          // §6.7.4: data-key and release seeds to a current device; release seeds only to a current
          // seat server; never to a helper, the backup or a removed key. Every answer is a notice
          // ("*Laptop* caught up", with Report lost, §1.1 item 8).
          const asker = this.m!.members.get(from);
          if (!asker || this.m!.removed.has(from) || !['device', 'server'].includes(asker.kind)) return { type: 'error', code: 'not_member' };
          const seeds = { release: [...this.seeds], ...(asker.kind === 'device' ? { dk: this.dkSeeds, base_dk: this.baseDk } : {}) };
          this.notices.push({ kind: 'need_seeds', member: from });
          return { type: 'seeds', wrap: wrap(this.kp.sk, from, { type: 'seeds', ...seeds }) };
        }
        default: return this.co!.handle(from, body, sentAt);
      }
    } catch (e) { return { type: 'error', re: body?.id, code: e instanceof KeykinError ? e.code : 'internal', detail: String(e) }; }
  }
}

/** The approval list carried in every change: redeals as placeholders, papers without inner/state. */
export function approvalListOf(list: Change[]): Change[] {
  return placeholderList(list);
}

// --- the paper holder --------------------------------------------------------------------

export class PaperHolder implements Node {
  kp: KeyPair; bus: Transport;
  g: string; epochId: string; serverHints: string[];
  shares: Map<number, bigint> | null = null; C: Commitment | null = null;
  r = rid();
  bundles = new Map<string, any>();
  constructor(bus: Transport, kp: KeyPair, g: string, epochId: string, serverHints: string[]) { this.kp = kp; this.bus = bus; this.g = g; this.epochId = epochId; this.serverHints = serverHints; }
  handle(): any { return { type: 'error', code: 'unsupported' }; }
  /** §6.5 steps 1–2 at each server. */
  async start(servers: string[]) {
    for (const s of servers) {
      const ch = await this.bus.send(this.kp, s, msg('challenge', this.g, this.epochId, 'ask'));
      if (ch?.type !== 'challenge') continue;
      await this.bus.send(this.kp, s, msg('release_request', this.g, this.epochId, 'member', { r: this.r, challenge: ch.challenge,
        sig: schnorrSign(detachedDigest('release_request', this.g, { r: this.r, challenge: ch.challenge }), this.kp.sk) }));
    }
  }
  /** §6.5 steps 3–4: collect releases, open the material, check against `P_b^S`. */
  async collect(servers: string[]) {
    for (const s of servers) {
      const a = await this.bus.send(this.kp, s, msg('release_request', this.g, this.epochId, 'member', { r: this.r }));
      if (a?.type === 'release') this.bundles.set(s, a);
    }
    if (this.bundles.size < 2) refuse('waited_missing');
    const bs = [...this.bundles.values()];
    const rec: EpochContent = checkEpochRecord(bs[0].record, { g: this.g });
    const changes = [...new Map(bs.flatMap((b) => b.changes).map((e: NostrEvent) => [e.id, e])).values()] as NostrEvent[];
    const m = computeMembership(rec, changes);
    // Each redeal's release seed is the one matching its pinned `rs`, whichever server sent it (§6.7.2).
    const seeds = new Map<string, string>();
    for (const [k, v] of bs.flatMap((b) => b.seeds) as [string, string][]) {
      const r = m.redeals.get(k)?.r;
      if (k === 'base' || (r && shaHex(hexToBytes(v)) === r.rs)) seeds.set(k, v);
    }
    const items = [...new Map(bs.flatMap((b) => b.items).map((it: Item) => [itemHash(it), it])).values()] as Item[];
    // The servers' state: the redeals the bundles' servers have applied (they agree, or the holder retries).
    const state = new Set<string>([...m.redeals.keys()].filter((id) => seeds.has(id) && !m.abandoned.has(id)));
    // The pin: the creation record's, or the committed paper change for this key (its base is wrapped
    // under its list's redeal's release seed, §6.7.2).
    const pc = m.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === this.kp.pub);
    const pin = pc ? (pc.c.change as any).paper.inner : rec.backup;
    const baseSeed = pc ? seeds.get([...m.redeals.values()].find((x) => x.listHash === pc.listHash)!.r.id)! : seeds.get('base')!;
    const base = bs.map((b) => b.base as Item).find((b) => itemHash(b) === pin)!;
    const o = openMaterial({ g: this.g, backup: this.kp, pin, base, baseSeed, items, seeds,
      C0: commitmentFrom(rec.commitment), redeals: [...m.redeals.values()].map((x) => x.r), state });
    this.shares = o.shares; this.C = o.C;
    return { rec, recEv: bs[0].record as NostrEvent, changes, m, waited: bs.map((b) => b.waited as Waited), state, dk: o.dk, dkSeeds: o.dkSeeds, seeds, items, base };
  }
  approve(list: Change[], waited: Waited[]) { return approveRecovery(this.g, approvalListOf(list), this.kp, { r: this.r }, waited); }
  /** A recovery round: backup (2) plus two servers, two-call form. */
  async cosign(ev: Unsigned, servers: MemberEntry[], state: Set<string>, extra: object = {}): Promise<NostrEvent> {
    return (await this.cosignAll([ev], servers, state, extra))[0];
  }
  async cosignAll(evs: Unsigned[], servers: MemberEntry[], state: Set<string>, extra: object = {}): Promise<NostrEvent[]> {
    const ev = evs.length === 1 ? evs[0] : evs;
    const ctx = { g: this.g, epochId: this.epochId, state: stateHash(state), C: this.C! };
    const t = new TwoCall(ctx, { key: this.kp.pub, indices: [...this.shares!.keys()], shares: this.shares! }, servers.map((s) => ({ key: s.key, indices: s.shares })), ev);
    for (const s of servers) t.took(s.key, await this.bus.send(this.kp, s.key, t.commitRequest()));
    const req = { ...t.signRequest(), ...extra };
    const parts = new Map<string, any>();
    for (const s of servers) parts.set(s.key, await this.bus.send(this.kp, s.key, req));
    return t.finishAll(parts);
  }
}

// --- a friend holding a recovery piece (Backup §3) ------------------------------------------

export class FriendNode implements Node {
  kp = newKey();                     // the dedicated holder key, never the friend's everyday nsec
  pieces = new Map<string, { g: string; piece: string; card: string }>();
  bus: Transport;
  constructor(bus: Transport) { this.bus = bus; }
  handle(from: string, body: any): any {
    if (body.type === 'piece') {
      this.pieces.set(body.set, { g: body.g, piece: body.piece, card: body.card });
      return { type: 'piece_ack', sig: schnorrSign(pieceAckDigest(body.g, body.set, utf8ToBytes(body.piece)), this.kp.sk) };
    }
    return { type: 'error', code: 'unsupported' };
  }
  /** Recovering (§3): seal the piece for that account to the key the new device shows, scanned in person. */
  async giveTo(newDeviceKey: KeyPair, set: string) {
    const p = this.pieces.get(set);
    if (!p) refuse('no_piece');
    return wrap(this.kp.sk, newDeviceKey.pub, { type: 'piece', set, piece: p!.piece, card: p!.card });
  }
}
