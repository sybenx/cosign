// Simulated members: servers, devices and the paper holder, talking only through the Bus.
// Each node keeps what Core says it keeps; the drivers (`sign`, `submit`, `invite`, …) are what an
// app would run. Nothing here is a second implementation of a rule: every check is in src/.

import { bytesToHex, randomBytes, hexToBytes, sha, refuse, KeykinError } from '../src/bytes.ts';
import { stateHash, pickSalt, detachedDigest, recoveryWaitId, seatedDigest, signpostD, signpostH } from '../src/codes.ts';
import * as nip44 from 'nostr-tools/nip44';
import { checkEpochRecord, checkOwnShares } from '../src/record.ts';
import { computeMembership, takenIndices, signpostCount, signpostServers, adopt, type Membership } from '../src/membership.ts';
import { CoSigner } from '../src/cosigner.ts';
import { OneCall, TwoCall, ListCall } from '../src/coordinator.ts';
import { deal as dealRedeal, applyRedeal, applicable, commitmentAt, stateOf, itemHash, type State, type Item, type Dealt } from '../src/redeal.ts';
import { signpostContent, acceptUpload, redealMissing, postListView, postListBackup, rerepairProof, verifyRerepair, needRepairAllowed, baseItem, openMaterial, type Upload } from '../src/upkeep.ts';
import { RepairHelper } from '../src/repair.ts';
import { repairShare } from '../src/frost.ts';
import { Inbox } from '../src/inbox.ts';
import { wrap, unwrap } from '../src/transport.ts';
import { Inviter, Joiner, parseCode } from '../src/join.ts';
import { approveRecovery, approveLock } from '../src/approval.ts';
import { commitmentFrom, scalarHex, scalarFrom, type Commitment } from '../src/curve.ts';
import { newKey, schnorrSign, type KeyPair, type NostrEvent, type Unsigned } from '../src/event.ts';
import { KIND_CHANGE, KIND_SIGNPOST, type Approval, type Change, type EpochContent, type MemberEntry, type Redeal, type Waited } from '../src/types.ts';
import type { SoftLock } from '../src/lock.ts';
import type { Transport, Node } from './bus.ts';

const rid = () => bytesToHex(randomBytes(16));
export const msg = (type: string, g: string, epoch: string, cls: string, extra: object = {}) => ({ v: 1, type, g, epoch, id: rid(), cls, ...extra });

// --- servers ------------------------------------------------------------------------------

export class ServerNode implements Node {
  kp = newKey(); host = newKey();
  co: CoSigner | null = null;
  rec: EpochContent | null = null; recEv: NostrEvent | null = null;
  uploads = new Map<string, Upload>();
  inbox = new Inbox();
  seeds = new Map<string, string>();
  items: Item[] = []; base: Item | null = null;
  answeredRepair = new Set<string>();
  retired = false;
  bus: Transport; name: string;
  constructor(bus: Transport, name: string) { this.bus = bus; this.name = name; }
  get now() { return this.bus.now; }
  get m() { return this.co!.m; }
  entry(idx: number): MemberEntry { return { key: this.kp.pub, kind: 'server', shares: [idx], host: this.host.pub, operator: 'op', own: false, https: `https://${this.name}.test`, relays: ['wss://r.test'] }; }

  /** A seat holder's welcome (§6.7.4): record, changes, state, release seeds, material, and the share if repaired already. */
  welcome(w: { recEv: NostrEvent; changes: NostrEvent[]; state: string[]; share?: [number, string]; signposts?: string[]; seeds: [string, string][]; items: Item[]; base: Item }) {
    this.recEv = w.recEv;
    this.rec = checkEpochRecord(w.recEv, { g: w.recEv.pubkey });
    const m = computeMembership(this.rec, w.changes);
    const C = commitmentAt(commitmentFrom(this.rec.commitment), [...m.redeals.values()].filter((x) => w.state.includes(x.r.id)).map((x) => x.r));
    const shares = new Map<number, bigint>(w.share ? [[w.share[0], scalarFrom(w.share[1])]] : []);
    if (w.share) checkOwnShares(this.rec.g, shares, C, false);
    this.co = new CoSigner({ me: this.kp, host: this.host, kind: 'server', now: () => this.now, record: this.rec, changes: [...w.changes],
      state: { ids: new Set(w.state), C, shares }, upkeep: (p, mm) => this.upkeep(p, mm),
      uploads: { get: (id) => this.uploads.get(id), liveSeatHolders: (view) => [...view.values()].filter((x) => x.kind === 'server' && !this.quietSince(x.key) && this.bus.alive(x.key)).length } });
    for (const id of w.signposts ?? []) this.co.noteSignpost(id);
    w.seeds.forEach(([k, v]) => this.seeds.set(k, v));
    this.items = [...w.items]; this.base = w.base;
  }

  async fetchCancels() {
    for (const s of [...this.m.members.values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub && !this.quietSince(x.key))) {
      const a = await this.bus.send(this.kp, s.key, msg('cancels_get', this.rec!.g, this.rec!.epoch.id, 'ask'), { timeoutMs: 2500 });
      if (a?.type === 'cancels') for (const c of a.cancels) try { this.co!.takeCancel(c); } catch { /* not valid here */ }
      else if (a?.code === 'unreachable') this.quiet.set(s.key, this.now);
    }
  }

  /** Upkeep duties beyond the library's: this server counts itself as holding the upload. */
  private upkeep(p: any, _m: Membership) {
    if (p.type !== 'redeal') return;
    this.uploads.get(p.c.change.redeal.id)?.held.add(this.kp.pub);
  }

  /** Before co-signing a change: fetch live peers (§6.7.3), and for a redeal collect `upload_held`. */
  private async beforeChangeCosign(evs: Unsigned[]) {
    await this.catchUp();
    for (const ev of evs) {
    let c: any; try { c = JSON.parse(ev.content); } catch { continue; }
    const r = c?.change?.redeal; const u = r && this.uploads.get(r.id);
    if (!u) continue;
    for (const s of [...postListView(this.m, c.list).values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub && !this.quietSince(x.key))) {
      const a = await this.bus.send(this.kp, s.key, { type: 'upload_status', redeal: r.id }, { timeoutMs: 2500 });
      if (a?.held) u.held.add(s.key);
    }
    }
  }

  /** Fetch the change set from every live peer (union) before acting (§3.2, §7.1). */
  async catchUp() {
    if (!this.co) return;
    for (const s of [...this.m.members.values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub)) {
      if (this.quietSince(s.key)) continue;
      const a = await this.bus.send(this.kp, s.key, msg('changes_get', this.rec!.g, this.rec!.epoch.id, 'ask'), { timeoutMs: 2500 });
      if (a?.type === 'changes') { this.quiet.delete(s.key); this.takeChanges(a.changes); }
      else if (a?.code === 'unreachable') this.quiet.set(s.key, this.now);
    }
  }
  /** Peers that have not answered: skipped for an hour (§6.3, §7.1), then tried again. */
  quiet = new Map<string, number>();
  quietSince(k: string) { const t = this.quiet.get(k); return t !== undefined && this.now - t < 3600; }

  takeChanges(evs: NostrEvent[]) {
    this.co!.addChanges(evs);
    const m = this.m;
    if (m.removed.has(this.kp.pub)) { this.retire(); return; }
    // Apply every redeal we can, oldest base first.
    for (let again = true; again;) {
      again = false;
      for (const { r } of m.redeals.values()) {
        if (applicable(this.co!.state, r, m.abandoned)) continue;
        const u = this.uploads.get(r.id);
        const mine = u?.items.find((it) => it.to === this.kp.pub);
        if (!mine) continue;                                   // a gap: closed by rerepair
        const body = unwrap(this.kp.sk, mine.wrap as NostrEvent).body;
        const deltas = new Map<number, bigint>(body.deltas.map(([i, d]: [number, string]) => [i, scalarFrom(d)]));
        if (!this.co!.state.shares.size) continue;           // not repaired yet: the repair sets the state
        const { state } = applyRedeal(m.g, this.co!.state, r, deltas, false, m.record.seats.backup, m.abandoned);
        this.co!.setState(state);
        if (body.release) this.seeds.set(r.id, body.release);
        if (u!.paperItem) this.items.push(u!.paperItem);
        // Release the inert upload: everyone else's items become deliveries.
        for (const it of u!.items) if (it.to !== this.kp.pub && m.members.has(it.to) && m.members.get(it.to)!.kind === 'device')
          try { this.inbox.deliver({ from: r.dealer, to: it.to, wrap: it.wrap as NostrEvent, kind: 'delivery', cls: 'member', at: this.now, isMember: (k) => m.members.has(k), isRemoved: (k) => m.removed.has(k), isBackup: (k) => k === m.backupKey }); } catch { /* full or removed */ }
        again = true;
      }
    }
  }

  /** After retirement, all a server keeps for the account (§6.7.5): the change that retired it, and
   *  the hashes of the keys allowed to fetch it (backup keys, devices, and peer servers). */
  forwarding: { events: NostrEvent[]; allowed: Set<string> } | null = null;
  retire() {
    if (this.retired) return;
    this.retired = true;
    const m = this.m;
    const mine = m.accepted.filter((p) => p.c.list.some((x: any) => x.seat?.replaces === this.kp.pub));
    const hashes = new Set(mine.map((p) => p.listHash));
    const events = m.accepted.filter((p) => hashes.has(p.listHash)).map((p) => p.ev);
    const allowed = new Set([...m.backupKeys, ...m.authority.devices, ...[...m.members.values()].filter((x) => x.kind === 'server').map((x) => x.key)].map((k) => bytesToHex(sha(hexToBytes(k)))));
    this.forwarding = { events, allowed };
    // Destroy everything else for the account.
    if (this.co) { this.co.setState({ ids: new Set(), C: this.co.state.C, shares: new Map() }); this.co.changes = []; }
    this.seeds.clear(); this.items = []; this.uploads.clear(); this.base = null; this.inbox = new Inbox();
  }

  async handle(from: string, body: any, sentAt: number): Promise<any> {
    try { return await this.dispatch(from, body, sentAt); }
    catch (e) { return { type: 'error', re: body?.id, code: e instanceof KeykinError ? e.code : 'internal', detail: String(e) }; }
  }
  private async dispatch(from: string, body: any, sentAt: number): Promise<any> {
    if (body.type === 'seat_welcome') { this.welcome(body.w); return { type: 'ack' }; }
    if (!this.co) return { type: 'error', code: 'unknown_account' };
    if (this.retired) {
      // A forwarding note, served to a request sealed by one of the allowed keys (§6.7.5 route 2).
      if ((body.type === 'forward_get' || body.type === 'changes_get') && this.forwarding!.allowed.has(bytesToHex(sha(hexToBytes(from)))))
        return { type: 'forward', changes: this.forwarding!.events };
      return { type: 'error', code: 'retired' };
    }
    const m = this.m;
    switch (body.type) {
      case 'change': {
        this.takeChanges(body.events);
        // A committed paper change's base item (F7 step 4) replaces the material base.
        if (body.material && this.m.accepted.some((p) => p.type === 'paper' && (p.c.change as any).paper.inner === itemHash(body.material) && (p.c.change as any).paper.key === this.m.backupKey)) this.base = body.material;
        return { type: 'ack' };
      }
      case 'changes_get': return { type: 'changes', record: this.recEv, changes: this.co.changes };
      case 'seated?': {
        // §6.7.5 route 1: if `H(key)` is the current backup key or a current device, a reply sealed to
        // that key, with the host signature outside the seal over SHA-256("keykin-seated/1" ‖ H ‖ challenge ‖ ct).
        const key = [m.backupKey, ...m.devices].find((k) => k && bytesToHex(sha(hexToBytes(k))) === body.h);
        if (!key) return { type: 'error', code: 'not_seated' };
        const servers = [...m.seats.values()].filter((x) => x.holder?.kind === 'server').map((x) => ({ host: x.holder!.host, https: x.holder!.https, relays: x.holder!.relays ?? [] }));
        const ct = nip44.v2.encrypt(JSON.stringify({ g: m.g, epoch: m.epochId, servers }), nip44.v2.utils.getConversationKey(this.host.sk, key));
        return { type: 'seated', ct, host: this.host.pub, sig: schnorrSign(seatedDigest(body.h, hexToBytes(body.challenge), new TextEncoder().encode(ct)), this.host.sk) };
      }
      case 'upload': {
        if (this.retired) refuse('retired');
        const u = acceptUpload(m, from, body, this.now, this.uploads.get(body.redeal));
        u.held.add(this.kp.pub);
        this.uploads.set(body.redeal, u);
        return { type: 'upload_held', redeal: body.redeal, server: this.host.pub };
      }
      case 'signpost_id':                                  // core 14.2 §6.7.10: a device delivers each new signpost id
        if (!m.devices.has(from)) refuse('not_device');
        if (!this.co.takeSignpost(body.event)) refuse('not_a_signpost');
        return { type: 'ack' };
      case 'repair_ok': {
        const owner = [...m.members.values()].find((x) => x.shares.includes(body.participant));
        if (owner?.key === from) this.co.repairSucceeded(from, body.participant);
        return { type: 'ack' };
      }
      case 'cancels_get': return { type: 'cancels', cancels: this.co.cancels };
      case 'upload_status': { const u = this.uploads.get(body.redeal); return { type: 'upload_status', held: !!u && this.now - u.at < 7 * 86400 }; }
      case 'deliver':
        this.inbox.deliver({ from, to: body.to, wrap: body.wrap, kind: 'delivery', cls: 'member', at: this.now, isMember: (k) => m.members.has(k), isRemoved: (k) => m.removed.has(k), isBackup: (k) => k === m.backupKey });
        return { type: 'ack' };
      case 'inbox_get': if (m.removed.has(from)) refuse('removed'); return { type: 'inbox', items: this.inbox.get(from, this.now) };
      case 'inbox_ack': this.inbox.ack(from, body.iids); return { type: 'ack' };
      case 'repair_start': return this.repairStart(from, body);
      case 'repair_finish': return this.co.repairFinish(from, body);
      case 'repair_sigma': {                                  // we are the participant (a seat being filled)
        const o = unwrap(this.kp.sk, body.wrap); void o; return { type: 'ack' };
      }
      case 'seat_fill': {                                      // the sigmas for our own seat, forwarded by a device
        const sig = (body.sigmas as NostrEvent[]).map((w) => unwrap(this.kp.sk, w).body);
        const idx = m.members.get(this.kp.pub)!.shares[0];
        const ids = new Set<string>(body.state);
        const C = commitmentAt(commitmentFrom(this.rec!.commitment), [...m.redeals.values()].filter((x) => ids.has(x.r.id)).map((x) => x.r));
        const s = repairShare(C, sig.map((x) => x.sigma), idx);
        this.co.setState({ ids, C, shares: new Map([[idx, s]]) });
        // The share checked: tell each helper, so its one `need_repair` answer is now used (§6.7.4).
        for (const w of body.sigmas as NostrEvent[]) await this.bus.send(this.kp, unwrap(this.kp.sk, w).from, { type: 'repair_ok', participant: idx });
        return { type: 'ack' };
      }
      default: {
        if (body.type === 'sign' && (body.event?.kind === KIND_CHANGE || Array.isArray(body.list_events)))
          await this.beforeChangeCosign(body.list_events ? body.list_events.map((x: any) => x.event) : [body.event]);
        // No waited statement or release before fetching peers' deliveries, so a missed cancel counts (§6.3).
        if (body.type === 'release_request' || body.type === 'hold' || (body.type === 'sign' && body.hold !== undefined)) {
          // Before a wait or a release: the change set from every peer (a removal it missed retires it),
          // and its peers' cancels (§6.3, §6.7.5).
          await this.catchUp();
          if (this.retired) return { type: 'error', code: 'retired' };
          await this.fetchCancels();
        }
        const a = this.co.handle(from, body, sentAt);
        if (a?.type === 'release') {
          // The release bundle (§6.5 step 3): seeds of this state, record, changes, material, statement.
          return { ...a, record: this.recEv, changes: this.co.changes, seeds: [...this.seeds], items: this.items, base: this.base };
        }
        return a;
      }
    }
  }

  private repairStart(from: string, body: any) {
    if (body.state !== stateOf(this.co!.state)) return { type: 'stale', ids: [...this.co!.state.ids].sort() };
    return this.co!.repairStart(from, body, this.now);
  }
}

// --- devices -----------------------------------------------------------------------------

export class DeviceNode implements Node {
  kp = newKey();
  lock: SoftLock | null;
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
  /** Security displays this device owes its person (§1.1 item 8). */
  notices: { kind: string; member: string }[] = [];
  /** A device's own destructive policy (Device policy module): here, always yes. */
  policy = (_e: Unsigned, _f: string) => true;
  bus: Transport; name: string;
  constructor(bus: Transport, name: string, lock: SoftLock | null) { this.bus = bus; this.name = name; this.lock = lock; }
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
  }
  recompute() {
    this.m = computeMembership(this.rec!, this.changes);
    this.co = new CoSigner({ me: this.kp, kind: 'device', now: () => this.now, record: this.rec!, changes: this.changes, state: this.state!, policy: (e, f) => this.policy(e, f) });
    if (this.m.removed.has(this.kp.pub)) this.wipe();
  }
  wipe() { this.wiped = true; this.state = { ids: new Set(), C: this.state!.C, shares: new Map() }; this.seeds.clear(); this.items = []; this.baseDk = ''; }
  refusedChanges: NostrEvent[] = [];
  takeChanges(evs: NostrEvent[]) {
    const r = adopt(this.rec!, this.changes, [...evs, ...this.refusedChanges], this.m?.authority.W);
    this.changes = r.changes; this.refusedChanges = r.refused.map((x) => x.ev);
    this.recompute();
  }

  // ---- driving ----
  /** Sign an event with the first live server that answers; `stale` brings us forward and retries. */
  async sign(ev: Partial<Unsigned>, extra: { approval?: Approval; hold?: string; list_events?: NostrEvent[]; material?: Item } = {}): Promise<NostrEvent> {
    const event: Unsigned = { pubkey: this.g, created_at: this.now, kind: 1, tags: [], content: '', ...ev };
    let lastErr = 'no_server';
    for (const s of this.servers()) {
      if (!this.bus.alive(s.key)) { lastErr = 'unreachable'; continue; }
      for (let tries = 0; tries < 2; tries++) {
        const r = new OneCall(this.ctx(), this.me(), { key: s.key, indices: s.shares }, event, extra);
        const a = await this.bus.send(this.kp, s.key, r.request);
        if (a?.type === 'stale') { r.abandon(); await this.fetch(); continue; }
        if (a?.type !== 'partial') { r.abandon(); lastErr = a?.code ?? 'no_answer'; this.lastDetail = a?.detail; break; }
        return r.finish(a);
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
      for (const it of a.items) this.takeDelivery(it.wrap);
      await this.bus.send(this.kp, s.key, msg('inbox_ack', this.g, this.epochId, 'ask', { iids: a.items.map((x: any) => x.iid) }));
    }
    this.applyAll();
  }
  pendingDeltas = new Map<string, any>();
  lastDetail: string | undefined;
  takeDelivery(w: NostrEvent) {
    const o = unwrap(this.kp.sk, w);
    if (o.body.type === 'delta') this.pendingDeltas.set(o.body.redeal, o.body);
  }
  /** Apply every redeal we hold a delta for (§6.7.1), checking our rebuilt commitment each time. */
  applyAll() {
    const m = this.m!;
    for (let again = true; again;) {
      again = false;
      for (const { r } of m.redeals.values()) {
        const d = this.pendingDeltas.get(r.id);
        if (!d || applicable(this.state!, r, m.abandoned)) continue;
        const deltas = new Map<number, bigint>(d.deltas.map(([i, x]: [number, string]) => [i, scalarFrom(x)]));
        const { state } = applyRedeal(m.g, this.state!, r, deltas, true, m.record.seats.backup, m.abandoned);
        this.state = state; this.pendingDeltas.delete(r.id);
        if (d.release) this.seeds.set(r.id, d.release);
        if (d.dk) this.dkSeeds.push(d.dk);
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
          ...(x.kind === 'device' ? { dk: dealt!.dkSeed, paper_ck: dealt!.paperCk } : {}) }) }));
      (dealt as any).uploadItems = items;
      const up = msg('upload', this.g, this.epochId, 'member', { list: approvalListOf(list), approval, redeal: dealt.redeal.id, items, paper_item: dealt.paperItem });
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
      if (mine) this.pendingDeltas.set(dealt.redeal.id, { type: 'delta', redeal: dealt.redeal.id, deltas: [...mine].map(([i, d]) => [i, scalarHex(d)]), release: dealt.releaseSeed, dk: dealt.dkSeed });
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
  async newPaper(approve: (list: Change[]) => Approval): Promise<KeyPair> {
    const K = newKey();
    const list: Change[] = [{ paper: { key: K.pub, replaces: this.m!.backupKey! } }, { redeal: { dealer: this.kp.pub } }];
    const approval = approve(list);
    await this.submit(list, approval, { finish: async (dealt) => {
      const server = this.servers().find((x) => this.bus.alive(x.key))!;
      const helpers = [{ key: this.kp.pub, indices: [...this.state!.shares.keys()] }, { key: server.key, indices: server.shares }];
      const shares = new Map<number, bigint>();
      for (const b of this.m!.record.seats.backup) {
        const ws = await this.repairFor(helpers, b, K.pub, 'paper', { list: approvalListOf(list), approval });
        shares.set(b, repairShare(this.state!.C, ws.map((w) => unwrap(K.sk, w).body.sigma), b));
      }
      const base = baseItem(K, dealt.releaseSeed, shares, this.baseDk, [...this.state!.ids]);
      shares.clear();                                        // the device keeps K only until the read-back
      return { full: [{ paper: { key: K.pub, replaces: this.m!.backupKey!, inner: itemHash(base), state: [...this.state!.ids].sort() } }, { redeal: dealt.redeal }], material: base };
    } });
    return K;
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
    try {
      switch (body.type) {
        case 'join_hello': return this.inviter!.onHello(from, body, this.now).msg;
        case 'join_nonce': this.joiner!.onNonce(from, body); return { type: 'ack' };
        case 'welcome_offer': return this.joiner!.onOffer(from, body, this.now).msg;
        case 'repair_start': return this.co!.repairStart(from, body, this.now);
        case 'repair_finish': return this.co!.repairFinish(from, body);
        case 'change': this.takeChanges(body.events); return { type: 'ack' };
        case 'delta_push': this.takeDelivery(body.wrap); this.applyAll(); return { type: 'ack' };
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
  return list.map((c) => ('redeal' in c ? { redeal: { dealer: (c.redeal as any).dealer } } : 'paper' in c ? { paper: { key: c.paper.key, replaces: c.paper.replaces } } : c));
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
    const seeds = new Map<string, string>(bs.flatMap((b) => b.seeds));
    const items = [...new Map(bs.flatMap((b) => b.items).map((it: Item) => [itemHash(it), it])).values()] as Item[];
    // The servers' state: the redeals the bundles' servers have applied (they agree, or the holder retries).
    const state = new Set<string>([...m.redeals.keys()].filter((id) => seeds.has(id)));
    // The pin: the creation record's, or the committed paper change for this key (its base is wrapped
    // under its list's redeal's release seed, §6.7.2).
    const pc = m.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === this.kp.pub);
    const pin = pc ? (pc.c.change as any).paper.inner : rec.backup;
    const baseSeed = pc ? seeds.get([...m.redeals.values()].find((x) => x.listHash === pc.listHash)!.r.id)! : seeds.get('base')!;
    const base = bs.map((b) => b.base as Item).find((b) => itemHash(b) === pin)!;
    const o = openMaterial({ g: this.g, backup: this.kp, pin, base, baseSeed, items, seeds,
      C0: commitmentFrom(rec.commitment), redeals: [...m.redeals.values()].map((x) => x.r), state });
    this.shares = o.shares; this.C = o.C;
    return { rec, recEv: bs[0].record as NostrEvent, changes, m, waited: bs.map((b) => b.waited as Waited), state, dk: o.dk, seeds, items, base };
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
export { sha, hexToBytes, recoveryWaitId, pickSalt, takenIndices, parseCode, baseItem };
