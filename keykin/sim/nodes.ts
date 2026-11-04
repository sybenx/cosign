// Simulated members: servers, devices and the paper holder, talking only through the Bus.
// Each node keeps what Core says it keeps; the drivers (`sign`, `submit`, `invite`, …) are what an
// app would run. Nothing here is a second implementation of a rule: every check is in src/.

import { bytesToHex, randomBytes, hexToBytes, sha, shaHex, jcsBytes, refuse, KeykinError, utf8ToBytes, b64u, strictJson } from '../src/bytes.ts';
import { stateHash, pickSalt, detachedDigest, recoveryWaitId, seatedDigest, signpostD, signpostH, what } from '../src/codes.ts';
import * as nip44 from 'nostr-tools/nip44';
import { checkEpochRecord, checkOwnShares } from '../src/record.ts';
import { computeMembership, takenIndices, signpostCount, signpostServers, adopt, type Membership } from '../src/membership.ts';
import { CoSigner } from '../src/cosigner.ts';
import { OneCall, TwoCall, ListCall } from '../src/coordinator.ts';
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
import { F1Watch } from '../src/f1.ts';
import { commitmentFrom, scalarHex, scalarFrom, type Commitment } from '../src/curve.ts';
import { newKey, pubOf, siteEvent, schnorrSign, schnorrVerify, type KeyPair, type NostrEvent, type Unsigned } from '../src/event.ts';
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
  /** Server profile §4: a rotating enrol secret, and the reply that names this seat's keys. */
  enrolSecret = randomBytes(32);
  enrollR: any = null;
  vapidSk: Uint8Array | null = null;
  enroll(g: string, now: number) {
    const r = enrollReply(this.host, this.enrolSecret, '2026-11', g, bytesToHex(randomBytes(16)), { https: `https://${this.name}.test`, relays: ['wss://r.test'], operator: this.host.pub, issued: now });
    this.kp = { sk: r.memberSk, pub: r.reply.member_key };
    this.enrollR = r.reply; this.vapidSk = r.vapidSk;
    return r.reply;
  }
  entry(idx: number): MemberEntry {
    return { key: this.kp.pub, kind: 'server', shares: [idx], host: this.host.pub, operator: this.enrollR?.operator ?? 'op', own: false,
      https: `https://${this.name}.test`, relays: ['wss://r.test'], ...(this.enrollR ? { vapid: this.enrollR.vapid, enroll: this.enrollR } : {}) };
  }

  /** A seat holder's welcome (§6.7.4): record, changes, state, release seeds, material, and the share if repaired already. */
  /** Account admin §3: after a delete, only SHA-256(g), the approved request, the changes that make its
   *  approver a device, and the epoch record (14.9); every later request gets a host-signed `deleted`. */
  tombstone: { h: string; request: any; changes: NostrEvent[]; recEv: NostrEvent } | null = null;
  deletedAnswer() {
    const t = this.tombstone!;
    return { type: 'deleted', request: t.request, changes: t.changes, record: t.recEv, host: this.host.pub,
      host_sig: schnorrSign(deletedDigest(this.rec?.g ?? t.request.g, t.request), this.host.sk) };
  }
  private async takeDelete(from: string, body: any) {
    let proof: { request: any; changes: NostrEvent[] };
    if (body.type === 'account_delete') proof = this.co!.checkDelete(from, body, this.now);
    else {
      // A peer's host-signed `deleted`, from a current seat holder, carrying the request.
      const peer = [...this.m.members.values()].find((x) => x.kind === 'server' && x.host === body.host);
      if (!peer || peer.key !== from || !schnorrVerify(body.host_sig, sha('keykin-deleted/1', hexToBytes(this.rec!.g), jcsBytes(body.request)), body.host)) refuse('bad_deleted');
      proof = this.co!.checkDelete(from, body.request, this.now, true);
    }
    const g = this.rec!.g;
    this.tombstone = { h: bytesToHex(sha(hexToBytes(g))), request: proof.request, changes: proof.changes, recEv: this.recEv! };
    const peers = [...this.m.members.values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub);
    // Destroy everything else: share, seeds, material, waits, push addresses, inbox.
    this.co!.setState({ ids: new Set(), C: this.co!.state.C, shares: new Map() });
    this.seeds.clear(); this.items = []; this.uploads.clear(); this.base = null; this.inbox = new Inbox();
    const ans = this.deletedAnswer();
    for (const p of peers) await this.bus.send(this.kp, p.key, { type: 'deleted', request: proof.request, changes: proof.changes, host: this.host.pub, host_sig: ans.host_sig });
    return ans;
  }

  // --- Durable state (core §2): everything a server must keep, and nothing it must not ----------
  /** What this server writes to storage: its seat keys, enrol secret and reply (§2 item 9); share, state,
   *  record and changes (1, 2); seeds and material (3); the co-signer's waits, answered ids, counters,
   *  stops, challenges and heir records (4, 6, 8); push addresses and inbox (5); inert uploads; a
   *  tombstone (10). Never nonces (§5.2), never a DKG in flight: a restart abandons both. */
  snapshot(): string {
    const hex = (b: Uint8Array | null) => (b ? bytesToHex(b) : null);
    const co = this.co;
    return JSON.stringify({ v: 1, name: this.name, kp: hex(this.kp.sk), host: hex(this.host.sk), enrolSecret: hex(this.enrolSecret), enrollR: this.enrollR, vapidSk: hex(this.vapidSk),
      recEv: this.recEv, tombstone: this.tombstone, retired: this.retired, provisional: this.provisional, welcomedAt: this.welcomedAt, passive: this.passive, lastActive: this.lastActive,
      co: co && { changes: co.changes, ids: [...co.state.ids], shares: [...co.state.shares].map(([i, s]) => [i, scalarHex(s)]), co: co.snapshot() },
      seeds: [...this.seeds], items: this.items, base: this.base, uploads: [...this.uploads].map(([k, u]) => [k, { ...u, held: [...u.held] }]),
      answeredRepair: [...this.answeredRepair], quiet: [...this.quiet], forwarding: this.forwarding && { events: this.forwarding.events, allowed: [...this.forwarding.allowed] },
      inbox: this.inbox.dump(), push: this.pushReg.dump() });
  }
  /** A server restarted from storage: the same keys and seat, its co-signer rebuilt from the record,
   *  changes and state, checked as a welcome is (§3.4), and every round that was in flight gone. */
  static restore(bus: Transport, json: string): ServerNode {
    const x = strictJson(json);
    if (x.v !== 1) refuse('malformed', 'storage version');
    const n = new ServerNode(bus, x.name);
    const key = (h: string) => ({ sk: hexToBytes(h), pub: pubOf(hexToBytes(h)) });
    n.kp = key(x.kp); n.host = key(x.host); n.enrolSecret = hexToBytes(x.enrolSecret); n.enrollR = x.enrollR; n.vapidSk = x.vapidSk ? hexToBytes(x.vapidSk) : null;
    n.tombstone = x.tombstone; n.retired = x.retired; n.provisional = x.provisional; n.welcomedAt = x.welcomedAt; n.passive = x.passive; n.lastActive = x.lastActive;
    x.seeds.forEach(([k, v]: [string, string]) => n.seeds.set(k, v));
    n.items = x.items; n.base = x.base;
    n.uploads = new Map(x.uploads.map(([k, u]: [string, any]) => [k, { ...u, held: new Set(u.held) }]));
    n.answeredRepair = new Set(x.answeredRepair); n.quiet = new Map(x.quiet);
    n.forwarding = x.forwarding && { events: x.forwarding.events, allowed: new Set(x.forwarding.allowed) };
    n.inbox.load(x.inbox); n.pushReg.load(x.push);
    if (x.recEv) {
      n.rec = checkEpochRecord(x.recEv, { g: x.recEv.pubkey }); n.recEv = x.recEv;
    }
    if (x.co) {
      const m = computeMembership(n.rec!, x.co.changes);
      const C = commitmentAt(commitmentFrom(n.rec!.commitment), [...m.redeals.values()].filter((r) => x.co.ids.includes(r.r.id)).map((r) => r.r));
      const shares = new Map<number, bigint>(x.co.shares.map(([i, s]: [number, string]) => [i, scalarFrom(s)]));
      if (shares.size) checkOwnShares(n.rec!.g, shares, C, false);
      n.co = new CoSigner({ me: n.kp, host: n.host, kind: 'server', now: () => n.now, record: n.rec!, changes: [...x.co.changes],
        state: { ids: new Set(x.co.ids), C, shares }, upkeep: (p, mm) => n.upkeep(p, mm),
        uploads: { get: (id) => n.uploads.get(id), liveSeatHolders: (view) => [...view.values()].filter((v) => v.kind === 'server' && !n.quietSince(v.key) && n.bus.alive(v.key)).length } });
      n.co.restore(x.co.co);
    }
    return n;
  }

  /** Account admin §1.1: creation by DKG. A throwaway DKG key (signed by the host key, destroyed when
   *  the DKG ends), this server's part of each round, then its enrol reply once `g` exists. The account
   *  is held provisionally until the device confirms it. */
  dkg: { key: KeyPair; owner: string; index?: number; secret?: string; secret2?: string; share?: bigint; g?: string; at: number } | null = null;
  provisional = false; welcomedAt = 0;
  private async creation(from: string, body: any): Promise<any> {
    switch (body.type) {
      case 'create': {
        if (this.co && !this.provisional) refuse('already_seated');
        if (this.dkg && this.dkg.owner !== from && this.now - this.dkg.at < 3600) refuse('busy');
        this.dkg = { key: newKey(), at: this.now, owner: from };
        return { type: 'create_ok', dkg_key: this.dkg.key.pub, host: this.host.pub, host_sig: schnorrSign(sha('keykin-dkg-key/1', hexToBytes(this.dkg.key.pub)), this.host.sk) };
      }
      case 'dkg_1': {
        if (!this.dkg || this.dkg.owner !== from) refuse('no_dkg');
        const r = dkg1(body.index, body.max, randomBytes(32));
        this.dkg!.index = body.index; this.dkg!.secret = r.secret;
        return { type: 'dkg_1', package: r.package };
      }
      case 'dkg_2': {
        if (!this.dkg || this.dkg.owner !== from) refuse('no_dkg');
        const others = new Map<number, string>(body.round1);
        const r = dkg2(this.dkg!.secret!, others);
        this.dkg!.secret = undefined; this.dkg!.secret2 = r.secret;
        // Packages for other servers are sealed to their throwaway DKG keys; the device can't read them.
        const out: [number, any][] = [...r.packages].map(([j, pk]) => {
          const to = body.dkg_keys[j];
          return [j, to ? { sealed: nip44.v2.encrypt(pk, nip44.v2.utils.getConversationKey(this.dkg!.key.sk, to)), from: this.dkg!.key.pub } : pk];
        });
        return { type: 'dkg_2', packages: out };
      }
      case 'dkg_3': {
        if (!this.dkg || this.dkg.owner !== from) refuse('no_dkg');
        const r1 = new Map<number, string>(body.round1);
        const r2 = new Map<number, string>(body.round2.map(([i, x]: [number, any]) => [i, typeof x === 'string' ? x : nip44.v2.decrypt(x.sealed, nip44.v2.utils.getConversationKey(this.dkg!.key.sk, x.from))]));
        const r = dkg3(this.dkg!.secret2!, r1, r2);
        this.dkg!.secret2 = undefined; this.dkg!.share = r.share; this.dkg!.g = r.g;
        return { type: 'dkg_3', g: r.g, points: [...r.points] };
      }
      case 'enroll': {
        // A seat's keys never change in place (Server profile §4): this one-account node enrols once.
        if (this.co || this.enrollR) refuse('already_seated');
        if (this.dkg && this.dkg.owner !== from) refuse('no_dkg');
        const old = this.kp.pub;
        const reply = this.enroll(body.g, this.now);
        this.bus.rekey?.(old, this);
        return { type: 'enroll_reply', reply };
      }
      case 'confirm': {
        // The device's confirmation, once every server adopted (Account admin §1.1 step 4).
        if (!this.co || !this.provisional || body.epoch !== this.rec!.epoch.id || !this.m.devices.has(from)) refuse('not_provisional');
        this.provisional = false; this.dkg = null;
        return { type: 'ack' };
      }
    }
    if (body.type === 'confirm_status') return { type: 'confirm_status', confirmed: !!this.co && !this.provisional && body.epoch === this.rec?.epoch.id };
    // A provisional account not confirmed within an hour is dropped, keeping no record, unless a peer
    // has seen the confirmation (Account admin §1.1 step 4).
    if (this.provisional && this.now - this.welcomedAt > 3600) {
      let seen = false;
      for (const p of [...this.m.members.values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub)) {
        const a = await this.bus.send(this.kp, p.key, { type: 'confirm_status', epoch: this.rec!.epoch.id }, { timeoutMs: 2500 });
        if (a?.confirmed) seen = true;
      }
      if (seen) this.provisional = false;
      else { this.co = null; this.rec = null; this.recEv = null; this.provisional = false; this.dkg = null; }
    }
    return undefined;
  }

  welcome(w: { recEv: NostrEvent; changes: NostrEvent[]; state: string[]; share?: [number, string]; provisional?: boolean; signposts?: string[]; seeds: [string, string][]; items: Item[]; base: Item }) {
    this.recEv = w.recEv;
    this.rec = checkEpochRecord(w.recEv, { g: w.recEv.pubkey });
    const m = computeMembership(this.rec, w.changes);
    const C = commitmentAt(commitmentFrom(this.rec.commitment), [...m.redeals.values()].filter((x) => w.state.includes(x.r.id)).map((x) => x.r));
    let shares = new Map<number, bigint>(w.share ? [[w.share[0], scalarFrom(w.share[1])]] : []);
    // A DKG creation: this server's own DKG share, for the epoch record's g, at its seat.
    if (!w.share && this.dkg?.share !== undefined && this.dkg.g === this.rec.g) shares = new Map([[this.dkg.index!, this.dkg.share]]);
    if (!w.share && shares.size) checkOwnShares(this.rec.g, shares, C, false);
    if (w.provisional && !shares.size) refuse('no_share', 'a DKG seat holds its own share before it adopts');
    if (w.provisional) { this.provisional = true; this.welcomedAt = this.now; }
    if (w.share) checkOwnShares(this.rec.g, shares, C, false);
    this.co = new CoSigner({ me: this.kp, host: this.host, kind: 'server', now: () => this.now, record: this.rec, changes: [...w.changes],
      state: { ids: new Set(w.state), C, shares }, upkeep: (p, mm) => this.upkeep(p, mm),
      uploads: { get: (id) => this.uploads.get(id), liveSeatHolders: (view) => [...view.values()].filter((x) => x.kind === 'server' && !this.quietSince(x.key) && this.bus.alive(x.key)).length } });
    for (const id of w.signposts ?? []) this.co.noteSignpost(id);
    // Helper stops are account state: carried in seat holders' welcomes (core §5.7).
    for (const [id, x] of (w as any).stops ?? []) this.co.stops.set(id, x);
    for (const [id, at] of (w as any).cleared ?? []) this.co.clearedStops.set(id, at);
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
  async catchUp(): Promise<boolean> {
    let confirmed = false;
    if (!this.co) return false;
    for (const s of [...this.m.members.values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub)) {
      if (this.quietSince(s.key)) continue;
      const a = await this.bus.send(this.kp, s.key, msg('changes_get', this.rec!.g, this.rec!.epoch.id, 'ask'), { timeoutMs: 2500 });
      if (a?.type === 'changes') { this.quiet.delete(s.key); this.takeChanges(a.changes); if (!this.retired && this.m.members.has(s.key)) confirmed = true; }
      else if (a?.code === 'unreachable') this.quiet.set(s.key, this.now);
    }
    return confirmed;
  }
  /** Peers that have not answered: skipped for an hour (§6.3, §7.1), then tried again. */
  quiet = new Map<string, number>();
  quietSince(k: string) { const t = this.quiet.get(k); return t !== undefined && this.now - t < 3600; }

  takeChanges(evs: NostrEvent[]) {
    this.co!.addChanges(evs);
    const m = this.m;
    if (m.removed.has(this.kp.pub)) { this.retire(); return; }
    // Backup §1.1 step 5: an heir record named by a co-signed paper change, with this server's piece.
    for (const u of this.uploads.values()) {
      if (!u.heirRecord) continue;
      const it = u.items.find((x) => x.type === 'heir_piece' && x.to === this.kp.pub);
      if (!it) continue;
      try { const b = unwrap(this.kp.sk, it.wrap as NostrEvent).body; this.co!.takeHeir(u.heirRecord as any, b.x, scalarFrom(b.piece)); } catch { /* not ours */ }
    }
    // Apply every redeal we can, oldest base first.
    for (let again = true; again;) {
      again = false;
      for (const { r } of m.redeals.values()) {
        if (applicable(this.co!.state, r, m.abandoned)) continue;
        const u = this.uploads.get(r.id);
        const mine = u?.items.find((it) => it.to === this.kp.pub);
        if (!mine) continue;                                   // a gap: closed by rerepair
        const o = unwrap(this.kp.sk, mine.wrap as NostrEvent), body = o.body;
        try { checkDelivery(r, o.from, body); } catch { continue; }
        const deltas = new Map<number, bigint>(body.deltas.map(([i, d]: [number, string]) => [i, scalarFrom(d)]));
        if (!this.co!.state.shares.size) continue;           // not repaired yet: the repair sets the state
        const { state } = applyRedeal(m.g, this.co!.state, r, deltas, false, m.record.seats.backup, m.abandoned);
        this.co!.setState(state);
        if (body.release) this.seeds.set(r.id, body.release);
        if (u!.paperItem) this.items.push(u!.paperItem);
        // Release the inert upload: everyone else's items become deliveries.
        for (const it of u!.items) if (it.type === 'delta' && it.to !== this.kp.pub && m.members.has(it.to) && ['device', 'helper'].includes(m.members.get(it.to)!.kind))
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
  passive = false;
  lastActive = 0;
  pushReg = new PushRegistry();
  /** §8.2: one Web Push to `member`'s address for `cls`, RFC 8291-encrypted, signed with this seat's VAPID key. */
  pushTo(member: string, cls: 'sign' | 'ask' | 'notice', id: string, wrap?: unknown) {
    const addr = this.pushReg.for(member, cls);
    if (!addr || !this.vapidSk) return false;
    this.bus.pushes?.push({ url: addr.url, authorization: vapidHeader(addr.url, this.vapidSk, this.now), body: encryptPush(pushPayload(this.host, cls, id, wrap), addr), at: this.now });
    return true;
  }
  private async dispatch(from: string, body: any, sentAt: number): Promise<any> {
    if (this.lastActive && this.now - this.lastActive > 7 * 86400) this.passive = true;
    this.lastActive = this.now;
    const pre = await this.creation(from, body);
    if (pre !== undefined) return pre;
    if (body.type === 'seat_welcome') {
      // Once per account, from a current device of the welcome's own view, and only if that view seats us (§6.7.4).
      const rec = checkEpochRecord(body.w.recEv, { g: body.w.recEv.pubkey });
      const view = computeMembership(rec, body.w.changes);
      if (!view.devices.has(from)) refuse('not_device');
      if (![...view.seats.values()].some((x) => x.holder?.key === this.kp.pub)) refuse('not_seated');
      if (this.co && !this.provisional && this.rec!.g === rec.g) refuse('exists');   // Account admin §1.2, only after the checks (review 5 B8)
      if (this.co && !this.provisional) refuse('already_welcomed');
      if (this.co && this.provisional && this.rec!.g !== rec.g) refuse('provisional_other', 'only a newer record for the same key replaces it');
      this.welcome(body.w); return { type: 'ack' };
    }
    if (this.tombstone) return this.deletedAnswer();
    if (!this.co) return { type: 'error', code: 'unknown_account' };
    if (body.type === 'account_delete' || body.type === 'deleted') return this.takeDelete(from, body);
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
      case 'paper_reissue': {
        const r = m.redeals.get(body.item?.redeal)?.r;
        if (!r || !m.devices.has(from) || body.item.by !== from) refuse('not_device');
        const e = checkReissue(r!, body.item, m.backupKey!, (k) => m.devices.has(k), m.record.seats.backup);
        if (e) refuse(e);
        // Every distinct valid one, at most one per device and redeal.
        if (!this.items.some((x) => x.kind === "reissue" && x.redeal === r!.id && x.by === from)) this.items.push(body.item);
        return { type: 'ack' };
      }
      case 'stop_relay': {
        // A peer passes on a stop (core §5.7); the stopping device must be current in this view.
        if (!m.members.has(from) || m.members.get(from)!.kind !== 'server') refuse('not_peer');
        try { this.co.takeStop(body.by, { stop: body.stop, by: body.by }, this.now); } catch { /* already, or not a device */ }
        return { type: 'ack' };
      }
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
      case 'inbox_get': if (m.removed.has(from)) refuse('removed');
        return { type: 'inbox', items: this.inbox.get(from, this.now), ...(m.devices.has(from) ? { stops: [...this.co.stops.keys()] } : {}) };
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
        if (body.type === 'helper_stop') {
          const a = this.co.handle(from, body, sentAt);
          if (a?.type === 'notice') for (const p of [...m.members.values()].filter((x) => x.kind === 'server' && x.key !== this.kp.pub))
            await this.bus.send(this.kp, p.key, { type: 'stop_relay', stop: body.stop, by: body.by }, { timeoutMs: 2500 });
          return a;
        }
        if (body.type === 'sign' && (body.event?.kind === KIND_CHANGE || Array.isArray(body.list_events)))
          await this.beforeChangeCosign(body.list_events ? body.list_events.map((x: any) => x.event) : [body.event]);
        // No waited statement or release before fetching peers' deliveries, so a missed cancel counts (§6.3).
        if (body.type === 'release_request' || body.type === 'hold' || body.type === 'heir_get' || (body.type === 'sign' && body.hold !== undefined)) {
          // Before a wait or a release: the change set from every peer (a removal it missed retires it),
          // and its peers' cancels (§6.3, §6.7.5).
          const confirmed = await this.catchUp();
          if (this.retired) return { type: 'error', code: 'retired' };
          // Passive after 7 days offline (§6.7.5): no waits or releases until a live peer that is itself
          // a current seat holder confirms, by its change set, that this server still holds its seat.
          if (this.passive && !confirmed) return { type: 'error', code: 'passive' };
          this.passive = false;
          await this.fetchCancels();
        }
        // §8.1: push addresses, per member, newest by the rumor's created_at; never copied to peers.
        if (body.type === 'push_register' || body.type === 'push_unregister') {
          const mem = this.m.members.get(from);
          if (!mem || this.m.removed.has(from)) refuse('not_member');
          if (mem!.kind !== 'device') refuse('helper_refused');
          if (body.type === 'push_unregister') this.pushReg.unregister(from);
          else this.pushReg.register(from, sentAt, body.addresses);
          return { type: 'ack', re: body.id };
        }
        const a = this.co.handle(from, body, sentAt);
        // §8.2: a wait notice goes as an `ask` push to every member, with the wait id.
        if (a?.type === 'notice' && a.kind === 'hold') for (const mem of this.m.members.keys()) this.pushTo(mem, 'ask', a.wait);
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
    this.co = new CoSigner({ me: this.kp, kind: this.role, now: () => this.now, record: this.rec!, changes: this.changes, state: this.state!, policy: (e, f) => this.policy(e, f) });
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
    // The site's event as §9.5 reads it: absent fields filled, its id, sig and extra fields dropped.
    const { id: _id, ...event } = siteEvent({ created_at: this.now, kind: 1, ...ev }, this.g);
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
      for (const it of a.items) try { this.takeDelivery(it.wrap); } catch { /* one bad item never wedges the rest */ }
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
        try { checkDelivery(r, d.from ?? r.dealer, d); } catch { this.pendingDeltas.delete(r.id); this.notices.push({ kind: 'bad_delivery', member: d.from }); continue; }
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
      const item = reissueItem(r, K, v.release, v, this.kp);
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
    let n = 0;
    for (const s of this.servers()) { const a = await this.bus.send(this.kp, s.key, req); if (a?.type === 'deleted') n++; }
    if (n >= 2) this.wipe();
    return n;
  }

  /** Approve a request that every server checks and no co-signer joins: by this device's lock, or by
   *  the paper, this device plus the backup key over a challenge from every server (core §6.2). */
  async approveRequest(type: string, body: any, paper?: KeyPair): Promise<any> {
    const w = what.request(type, body.id, body);
    if (!paper) return { lock: { member: this.kp.pub, assertion: this.lock!.assert(this.g, w) } };
    const challenges: { server: string; challenge: string }[] = [];
    for (const s of this.servers()) {
      const ch = await this.bus.send(paper, s.key, msg('challenge', this.g, this.epochId, 'ask'));
      if (ch?.type === 'challenge') challenges.push({ server: ch.server, challenge: ch.challenge });
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

  /** §8.1: one gateway address per server and wake class, pinned to that server's VAPID key, each with
   *  its own RFC 8291 keys, so the addresses can't be linked across servers or accounts. */
  pushKeys = new Map<string, { sk: Uint8Array; auth: Uint8Array; vapid: string; cls: string }>();
  async registerPush(): Promise<number> {
    let n = 0;
    for (const s of this.servers()) {
      const addresses = (['sign', 'ask', 'notice'] as const).map((cls) => {
        const sk = p256.utils.randomSecretKey(), auth = randomBytes(16), url = `https://gw.test/${bytesToHex(randomBytes(16))}`;
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
    return (this.bus.pushes ?? []).flatMap((p) => {
      const k = this.pushKeys.get(p.url);
      if (!k || checkVapid(p.authorization, p.url, k.vapid, this.now) !== null) return [];
      try { return [readPush(decryptPush(p.body, k.sk, k.auth), hosts)]; } catch { return []; }
    });
  }

  /** Core §6.7.7: this device's own view of which seated servers are dead, from what each answers. */
  #f1: F1Watch | null = null;
  f1(): F1Watch {
    if (!this.#f1) { this.#f1 = new F1Watch(this.g); for (const s of this.servers()) this.#f1.seat(s.host!, this.now); }
    return this.#f1;
  }
  /** Ask every seated server for the account's state and return the F1 card's seats. A `deleted` that
   *  verifies destroys this device's copy (Account admin §3) and returns null; one that doesn't, like
   *  "unknown account", counts as a denial. */
  async checkServers(): Promise<{ seat: string; host: string; why: string }[] | null> {
    const w = this.f1();
    const seats = [...this.m!.seats.entries()].filter(([k, x]) => k.startsWith('server:') && x.holder).map(([seat, x]) => ({ seat, host: x.holder!.host!, key: x.holder!.key }));
    for (const s of seats) {
      w.seat(s.host, this.now);
      const a = await this.bus.send(this.kp, s.key, msg('state_get', this.g, this.epochId, 'ask'));
      if (a?.type === 'state') w.saw(s.host, 'serving', this.now);
      else if (a?.type === 'deleted') {
        if (verifyDeleted(this.m!, this.g, a)) { this.wipe(); return null; }
        w.saw(s.host, 'denied', this.now);
      } else if (a?.code === 'unknown_account') w.saw(s.host, 'denied', this.now);
      else w.saw(s.host, 'silent', this.now);
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
    try {
      switch (body.type) {
        case 'notice': if ('shutdown' in body) this.f1().notice(body); return { type: 'ack' };
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
export { sha, hexToBytes, recoveryWaitId, pickSalt, takenIndices, parseCode, baseItem };

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
