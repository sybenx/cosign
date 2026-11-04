// A Keykin server (core §2, §5, §6.7; Server profile; Account admin §1, §3; Backup §4; Helper; core §8):
// one account's seat, written against a `Transport`, so the simulation's Bus, RelayNet over real relays
// and the server runtime (server/main.ts) all run the same code.

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
import { F1Watch, SignWatch, signNotice, signAnswer } from '../src/f1.ts';
import { commitmentFrom, scalarHex, scalarFrom, type Commitment } from '../src/curve.ts';
import { newKey, pubOf, siteEvent, schnorrSign, schnorrVerify, type KeyPair, type NostrEvent, type Unsigned } from '../src/event.ts';
import { KIND_CHANGE, KIND_SIGNPOST, type Approval, type Change, type EpochContent, type MemberEntry, type Redeal, type Waited } from '../src/types.ts';
import { softLock, type SoftLock } from '../src/lock.ts';
import { TRANSPORT_FAILED, type Transport, type Node } from '../runtime/net.ts';
import { msg, rid } from '../src/msg.ts';

/** A server seat's member entry, from its enrol reply (Server profile §4): what a device writes. */
export const entryFromReply = (reply: any, idx: number): MemberEntry => ({ key: reply.member_key, kind: 'server', shares: [idx], host: reply.host, operator: reply.operator,
  own: false, https: reply.https, relays: reply.relays, vapid: reply.vapid, enroll: reply });

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
  /** What this server's enrol replies say (Server profile §4). The simulation's defaults; the runtime
   *  sets the month's secret id and its own endpoints. */
  profile = { secretId: '2026-11', https: '', relays: ['wss://r.test'], operator: '' };
  enrollR: any = null;
  vapidSk: Uint8Array | null = null;
  enroll(g: string, now: number) {
    const p = this.profile;
    const r = enrollReply(this.host, this.enrolSecret, p.secretId, g, bytesToHex(randomBytes(16)), { https: p.https || `https://${this.name}.test`, relays: p.relays, operator: p.operator || this.host.pub, issued: now });
    this.kp = { sk: r.memberSk, pub: r.reply.member_key };
    this.enrollR = r.reply; this.vapidSk = r.vapidSk;
    return r.reply;
  }
  entry(idx: number): MemberEntry {
    return this.enrollR ? entryFromReply(this.enrollR, idx) : { key: this.kp.pub, kind: 'server', shares: [idx], host: this.host.pub, operator: 'op', own: false,
      https: `https://${this.name}.test`, relays: ['wss://r.test'] };
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
    // Destroy everything else (Account admin §3, core §2 item 10): the share and the co-signer with its
    // waits, heir records and pieces, stops and change set; seeds, material, uploads, push addresses,
    // notice, inbox (review 9 H1). Only the tombstone and this seat's keys remain.
    this.co!.setState({ ids: new Set(), C: this.co!.state.C, shares: new Map() });
    this.co = null;
    this.seeds.clear(); this.items = []; this.uploads.clear(); this.base = null; this.inbox = new Inbox();
    this.pushReg = new PushRegistry(); this.notice = null; this.quiet.clear(); this.forwarding = null; this.answeredRepair.clear();
    this.dkg = null; this.vapidSk = null; this.enrollR = null;
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
    // After a delete, only the tombstone and the keys that sign and receive its `deleted` answers.
    if (this.tombstone) return JSON.stringify({ v: 1, name: this.name, kp: hex(this.kp.sk), host: hex(this.host.sk), tombstone: this.tombstone });
    const co = this.co;
    return JSON.stringify({ v: 1, name: this.name, kp: hex(this.kp.sk), host: hex(this.host.sk), enrolSecret: this.enrollR ? null : hex(this.enrolSecret), profile: this.profile, enrollR: this.enrollR, vapidSk: hex(this.vapidSk),
      recEv: this.recEv, tombstone: this.tombstone, retired: this.retired, provisional: this.provisional, welcomedAt: this.welcomedAt, passive: this.passive, lastActive: this.lastActive,
      co: co && { changes: co.changes, ids: [...co.state.ids], shares: [...co.state.shares].map(([i, s]) => [i, scalarHex(s)]), co: co.snapshot() },
      seeds: [...this.seeds], items: this.items, base: this.base, uploads: [...this.uploads].map(([k, u]) => [k, { ...u, held: [...u.held] }]),
      answeredRepair: [...this.answeredRepair], quiet: [...this.quiet], forwarding: this.forwarding && { events: this.forwarding.events, allowed: [...this.forwarding.allowed] },
      inbox: this.inbox.dump(), push: this.pushReg.dump(), notice: this.notice });
  }
  /** A server restarted from storage: the same keys and seat, its co-signer rebuilt from the record,
   *  changes and state, checked as a welcome is (§3.4), and every round that was in flight gone. */
  static restore(bus: Transport, json: string): ServerNode {
    const x = strictJson(json);
    if (x.v !== 1) refuse('malformed', 'storage version');
    const n = new ServerNode(bus, x.name);
    const key = (h: string) => ({ sk: hexToBytes(h), pub: pubOf(hexToBytes(h)) });
    n.kp = key(x.kp); n.host = key(x.host); n.enrolSecret = x.enrolSecret ? hexToBytes(x.enrolSecret) : new Uint8Array(32); if (x.profile) n.profile = x.profile; n.enrollR = x.enrollR; n.vapidSk = x.vapidSk ? hexToBytes(x.vapidSk) : null;
    n.tombstone = x.tombstone ?? null;
    if (n.tombstone) return n;
    n.retired = x.retired; n.provisional = x.provisional; n.welcomedAt = x.welcomedAt; n.passive = x.passive; n.lastActive = x.lastActive;
    x.seeds.forEach(([k, v]: [string, string]) => n.seeds.set(k, v));
    n.items = x.items; n.base = x.base;
    n.uploads = new Map(x.uploads.map(([k, u]: [string, any]) => [k, { ...u, held: new Set(u.held) }]));
    n.answeredRepair = new Set(x.answeredRepair); n.quiet = new Map(x.quiet);
    n.forwarding = x.forwarding && { events: x.forwarding.events, allowed: new Set(x.forwarding.allowed) };
    n.inbox.load(x.inbox); n.pushReg.load(x.push); n.notice = x.notice ?? null;
    if (x.recEv) {
      n.rec = checkEpochRecord(x.recEv, { g: x.recEv.pubkey }); n.recEv = x.recEv;
    }
    if (x.co) {
      const m = computeMembership(n.rec!, x.co.changes);
      const C = commitmentAt(commitmentFrom(n.rec!.commitment), [...m.redeals.values()].filter((r) => x.co.ids.includes(r.r.id)).map((r) => r.r));
      const shares = new Map<number, bigint>(x.co.shares.map(([i, s]: [number, string]) => [i, scalarFrom(s)]));
      if (shares.size) checkOwnShares(n.rec!.g, shares, C, false);
      // The seat key a current server holding exactly these indices, as a device's restore checks (review 9 L7).
      if (!n.retired) {
        const me = m.members.get(n.kp.pub), want = [...(me?.shares ?? [])].sort((a, b) => a - b).join(',');
        if (!me || me.kind !== 'server' || m.removed.has(n.kp.pub) || [...shares.keys()].sort((a, b) => a - b).join(',') !== want) refuse('not_member', 'the stored seat key is not a current server holding exactly these indices');
      }
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
  /** Server profile §5: this seat's latest shutdown notice for the account (`null` cancels). */
  notice: { shutdown: number | null; seq: number } | null = null;
  async announceShutdown(at: number | null) {
    const seq = Math.max(this.now, (this.notice?.seq ?? 0) + 1);
    this.notice = { shutdown: at, seq };
    const n = signNotice(this.rec!.g, this.host, { ...this.notice, member: this.kp.pub });
    for (const mem of this.m.members.values()) if (mem.kind === 'device' && !this.m.removed.has(mem.key)) await this.bus.send(this.kp, mem.key, n);
  }
  /** §8.2: one Web Push to `member`'s address for `cls`, RFC 8291-encrypted, signed with this seat's VAPID key. */
  pushTo(member: string, cls: 'sign' | 'ask' | 'notice', id: string, wrap?: unknown) {
    // A removed member's addresses are dropped (core §8.1, review 9 L2).
    if (this.co && this.m.removed.has(member)) { this.pushReg.unregister(member); return false; }
    const addr = this.pushReg.for(member, cls);
    if (!addr || !this.vapidSk) return false;
    // A push that fails never replaces the answer it follows (review 9 M2).
    try {
      this.bus.pushes?.push({ url: addr.url, authorization: vapidHeader(addr.url, this.vapidSk, this.now), body: encryptPush(pushPayload(this.host, cls, id, wrap), addr), at: this.now });
      return true;
    } catch { return false; }
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
        // Server profile §4.1: the live answer, only to a verified current member.
        if (body.type === 'notice_get') {
          if (!this.m.members.has(from) || this.m.removed.has(from)) refuse('not_member');
          return signAnswer(this.rec!.g, this.host, { shutdown: this.notice?.shutdown ?? null, seq: this.notice?.seq ?? 0, member: this.kp.pub }, body.id);
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

