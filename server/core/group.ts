// One membership in one group: this server's share of someone's key, and the signer
// their sites talk to. No I/O of its own: everything outside (relays, files, the clock,
// push) goes through the `Io` its host hands it, so the same code runs in one process
// for many people (../server.ts) or, later, in a Worker (../HOSTS.md).
//
// Sites connect with a one-time ticket your phone hands them over QRST (or, for a site
// that only knows NIP-46, by your phone scanning its nostrconnect:// code), then ask
// for signatures over relays. Almost everything signs at once, with the other server. A
// change that would destroy something (most of your follows, your profile, your relay
// list…) waits for your phone instead. Server A answers sites; server B answers only
// while A has been silent for 30 s.

import { cbc } from '@noble/ciphers/aes.js';
import { getEventHash, finalizeEvent, verifyEvent, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as F from '../frost.ts';
import * as Sig from '../sign.ts';
import { sealParts, openFrom, Parts, normRelay, KIND_MEMBER, KIND_NIP46 } from './seal.ts';
import { ARCHIVED, assess, keyOf, kindName, type Ev } from '../policy.ts';
import { Archive } from '../archive.ts';
import { History, type Entry } from '../history.ts';
import type { Io, Loaded } from './io.ts';
import { DkgRun, type DkgPlan, type DkgResult } from '../dkg.ts';
import { RefreshRun, type RefreshPlan, type RefreshResult } from '../refresh.ts';
import { W } from '../wasm.ts';
import { nip19 } from 'nostr-tools';

// --- State -------------------------------------------------------------------

/** A member: one of the two servers, your phone, or another device of yours (a tablet, a second phone, the extension). */
export interface Member { idx: number; name: string; role: 'server' | 'phone' | 'device' | 'backup'; pk: string | null; sharePub: string; push?: string | null; removed?: number;
  /** Who reported it lost (a member idx), and whether it answered "This wasn't me". */
  removedBy?: number; contested?: number;
  /** A server with no NIP-46 signer key (a public Worker, say): it never answers sites. */
  noSites?: boolean;
  /** In a weighted key a member holds several shares (a device 3, a server 1). `idx`/`sharePub` are the first. */
  shares?: { idx: number; sharePub: string }[];
  /**
   * Learned from another server's list and nothing else (when, in seconds). Such a member
   * may hold shares and sign, but it is not treated as one of the user's devices until it
   * has proved it holds them, because a server that can write the member list could
   * otherwise write itself in as a device and act as one (COSIGN.md §4.4).
   */
  viaServer?: number;
  /** When this server added it (a member added before this field is treated as long-standing). */
  since?: number }
/**
 * A grant. `parent` is set for one a connected site added under itself (the browser
 * extension adds one per website it signs for); `via` names what connected it.
 */
export interface Site { pk: string; origin: string; added: number; lastUsed: number; revoked?: number; relays?: string[]; parent?: string; via?: string }
export interface Ticket { t: string; origin: string; expires: number; used?: boolean }
export interface Change { id: string; key: string; kind: number; at: number; text: string; by: string; held?: boolean; undone?: boolean }

/** Start serving one group from what its host loaded. Nothing happens until `start()`. */
export function openGroup(loaded: Loaded, io: Io) {
  const S = loaded.state;
  S.sites ??= []; S.tickets ??= []; S.changes ??= [];
  const save = () => io.save.state(S);
  const archive = new Archive(loaded.archive, byKey => io.save.archive(byKey), io.trustedNow);
  const history = new History(loaded.history, loaded.saved, io.save);

  const members: Member[] = S.group.members;
  const me = members.find(m => m.idx === S.self.idx)!;
  /** This server's own shares (one, for a server). None yet in a weighted group whose key your phone hasn't made with us. */
  let myShares: Sig.Share[] = S.self.shares ?? [{ idx: S.self.idx, secret: S.self.share }];
  let myIdxs = myShares.map(s => s.idx);
  const sharesOf = (m: Member) => m.shares?.map(s => s.idx) ?? [m.idx];
  const ownerOf = (idx: number) => members.find(m => sharesOf(m).includes(idx));
  const sameSet = (a: number[], b: number[]) => [...a].sort((x, y) => x - y).join() === [...b].sort((x, y) => x - y).join();
  /** The group's other server, if it has one (a key made with one shared server has none). */
  const other = () => members.find(m => m.role === 'server' && m.idx !== me.idx && !m.removed);
  /** Every other server in the group: what one learns, they all should. */
  const others = () => members.filter(m => m.role === 'server' && m.idx !== me.idx && !m.removed && m.pk);
  /** The phone your server's code added first: pairing only. Everything else is any device. */
  const phone = () => members.find(m => m.role === 'phone')!;
  const isDevice = (m?: Member) => !!m && (m.role === 'phone' || m.role === 'device') && !m.removed;
  /**
   * May act for the user in a way that cannot be taken back: removing a device, handing out
   * pieces, taking the account out, cancelling a wait or a recovery. A member this server
   * only ever heard about from another server's list may not, until it has proved it holds
   * the shares that list claims (`viaServer`, cleared in `attempt`). Otherwise one
   * dishonest server could write itself in as a device and have every other server report
   * the user's real devices lost. Everything else a device does — signing, grants, mail,
   * taking part in a refresh — is unaffected, so nothing a real new device needs is
   * delayed: it does those at the server that added it, and this one catches up.
   */
  const mayAct = (m?: Member) => isDevice(m) && !m!.viaServer;
  /** Your devices that can sign: the phone, and any added since. */
  const devices = () => members.filter(m => isDevice(m) && m.pk);
  const byPk = (pk: string) => members.find(m => m.pk === pk);
  let groupX: string = S.group.groupX; // null until a weighted key is made
  const site = (pk: string) => (S.sites as Site[]).find(s => s.pk === pk);
  const now = () => Math.floor(io.now() / 1000);

  const startedAt = io.now();
  const lastSeen = new Map<number, number>();
  const seen = (idx: number) => lastSeen.get(idx) ?? 0;
  // Pings go out every 10 s; three missed means gone.
  const online = (m: Member) => m.idx === me.idx || io.now() - seen(m.idx) < 30_000;

  const activity: { ts: number; text: string }[] = [];
  // How often this server helped sign today: a count for its page, nothing about what.
  let signed = { day: new Date().toDateString(), n: 0 };
  const countSigned = () => { const d = new Date().toDateString(); if (signed.day !== d) signed = { day: d, n: 0 }; signed.n++; };
  const note = (text: string) => {
    activity.unshift({ ts: io.now(), text });
    activity.length = Math.min(activity.length, 40);
    io.note(text);
  };

  // --- Relays ------------------------------------------------------------------

  const send = (toPk: string | null | undefined, msg: object) => { if (toPk) for (const e of sealParts(S.self.sk, toPk, msg)) io.publish(e); };
  const parts = new Parts();
  const toOther = (msg: object) => { for (const o of others()) send(o.pk, msg); };
  const toDevices = (msg: object) => { for (const d of devices()) send(d.pk, msg); };

  const pending = new Map<string, { resolve: (v: any) => void; timer: NodeJS.Timeout; giveUp?: () => void; again?: NodeJS.Timeout }>();
  const rid = () => F.bytesToHex(F.randomBytes(8));
  /** Ask a member, and keep asking (freshly wrapped) until it answers or time runs out. */
  function ask(toPk: string, msg: any, ms: number): Promise<any> {
    return new Promise(resolve => {
      const again = setInterval(() => send(toPk, msg), 4000);
      const giveUp = () => { clearInterval(again); pending.delete(msg.id); resolve({ ok: false, reason: 'no answer' }); };
      const timer = setTimeout(giveUp, ms);
      pending.set(msg.id, { resolve: v => { clearInterval(again); resolve(v); }, timer, giveUp, again });
      send(toPk, msg);
    });
  }

  /** Stop asking: another partner already answered. */
  function cancelAsk(id: string) {
    const p = pending.get(id);
    if (!p) return;
    clearTimeout(p.timer); if (p.again) clearInterval(p.again);
    pending.delete(id);
    p.resolve({ ok: false, reason: 'not needed' });
  }

  interface Attempt { m: Member; signed?: Event; reason?: string }

  /** The phone is asking you about this one: give it the full minute. */
  function waitLonger(id: string) {
    const p = pending.get(id);
    if (!p?.giveUp) return;
    clearTimeout(p.timer); clearInterval(p.again);
    p.timer = setTimeout(p.giveUp, 60_000);
  }

  // A request asked again gets the same answer: never a second partial with new nonces.
  const given = new Map<string, { at: number; msg: object }>();
  function answerOnce(to: Member, id: string, make: () => object | undefined) {
    const k = `${to.pk}:${id}`;
    const prior = given.get(k);
    if (prior) return send(to.pk, prior.msg);
    const msg = make();
    if (!msg) return;
    given.set(k, { at: io.now(), msg });
    send(to.pk, msg);
  }

  // Anyone can write to this group's keys: so many messages a minute, and the rest dropped.
  const PER_MINUTE = Number(process.env.COSIGN_GROUP_PER_MINUTE ?? 600);
  let windowStart = 0, inWindow = 0, saidBusy = false;

  function onEvent(e: Event) {
    const age = now() - e.created_at;
    if (age > 120) return;
    if (io.now() - windowStart > 60_000) { windowStart = io.now(); inWindow = 0; saidBusy = false; }
    if (++inWindow > PER_MINUTE) { if (!saidBusy) { saidBusy = true; note(`more than ${PER_MINUTE} messages this minute: dropping the rest`); } return; }
    if (e.kind === KIND_MEMBER) {
      const msg = parts.take(e.pubkey, openFrom(S.self.sk, e));
      // Relays replay recent "ephemeral" events to a new subscription; a request that
      // old has been given up on by whoever sent it.
      if (msg && (msg.type === 'sign_req' || msg.type === 'ecdh_req') && age > 30) return;
      if (msg) onMember(msg, e.pubkey).catch(err => console.error(err));
    } else if (e.kind === KIND_NIP46) {
      // Same for sites: after a restart, relays replay requests this server already
      // answered before it went down, and it no longer remembers them.
      if (age > 30) return;
      onSiteRequest(e).catch(err => console.error(err));
    }
  }

  // --- Members -----------------------------------------------------------------

  async function onMember(msg: any, fromPk: string) {
    const from = byPk(fromPk);
    if (from) {
      const wasOnline = online(from);
      lastSeen.set(from.idx, io.now());
      // The other server just came back: bring it up to date.
      if (!wasOnline && from.role === 'server') syncTo();
    }

    if ((msg.type === 'sign_res' || msg.type === 'ecdh_res') && pending.has(msg.id)) {
      const p = pending.get(msg.id)!; clearTimeout(p.timer); pending.delete(msg.id);
      return p.resolve({ ...msg, from });
    }
    if (msg.type === 'pair_hello') return onPairHello(msg, fromPk);
    if (msg.type === 'pair_ack') return onPairAck(msg, fromPk);
    if (msg.type === 'joined') return onJoined(msg, fromPk); // a new device, not a member until this lands
    // This server joining a key that exists (enroll how:'repair'): the pieces of its share.
    if (S.joining && from && (msg.type === 'welcome' || msg.type === 'sigma')) return onJoinPiece(msg, from);
    // Making the key: your phone isn't a member yet, so these come before that check.
    if (msg.type === 'dkg1' || msg.type === 'dkg2') return dkg?.take(msg, fromPk);
    if (msg.type === 'dkg_start') return onDkgStart(msg, from);
    if (!from) return;
    deliverMail(from);
    // Nothing from a member taken out (a device reported lost, an old paper): it must get
    // nothing more from this server, not even a piece of a decryption. Removal is final;
    // a device removed by mistake is added again by one of yours, or the paper.
    if (from.removed) return;

    const fromPhone = isDevice(from); // any of your devices
    switch (msg.type) {
      case 'ping': return;
      case 'asking': { if (fromPhone) waitLonger(String(msg.id)); return; }
      case 'sign_req': return answerOnce(from, msg.id, () => onSignReq(msg, from));
      // An app on your phone asked it to sign (Android signer): the phone runs the round.
      case 'cosign_req': return answerOnce(from, msg.id, () => onCosignReq(msg, from));
      case 'phone_signed': { if (fromPhone) onPhoneSigned(msg); return; }
      case 'app_grant': { if (fromPhone) grantApp(msg); return; }
      case 'add_device': { if (mayAct(from)) addDevice(msg, from).catch(err => send(from.pk, { type: 'add_failed', id: msg.id, reason: err.message })); return; }
      case 'repair_delta': { if (fromPhone) onRepairDelta(msg, from); return; }
      case 'members': { if (!fromPhone) mergeMembers(msg.members ?? []); return; }
      case 'remove_member': { if (mayAct(from)) onRemove(msg, from); return; }
      case 'take_out': { if (mayAct(from)) onTakeOut(msg, from); return; }
      case 'forget': { if (mayAct(from)) onForget(msg, from); return; }
      case 'guard_cancel': { if (mayAct(from)) cancelGuard(msg, from); return; }
      case 'refresh_request': {
        if (!fromPhone || !msg.plan) return;
        // A periodic one needs no lock: it takes nobody out, and only runs once the key has sat long enough.
        if (msg.plan.periodic === true) { if (periodicDue()) startRefresh(msg.plan as RefreshPlan, from); else note(`refused a periodic refresh from ${from.name}: the last was too recent`); return; }
        if (msg.lock === true) startRefresh(msg.plan as RefreshPlan, from);
        return;
      }
      case 'sign_check': { if (fromPhone) send(from.pk, onSignCheck(msg)); return; }
      case 'refresh_commit': { if (fromPhone) commitPending(Number(msg.epoch), from, msg.id); return; }
      case 'refresh_committed': { if (from.role === 'server') commitPending(Number(msg.epoch), from, msg.id); return; }
      case 'refresh_part': { refresh?.take(msg, fromPk); return; }
      case 'backup_piece': { const a = adding.get(String(msg.id)); if (a?.backup && (a.by.idx === from.idx || a.extras.some(x => x.idx === from.idx))) backupPiece(a, String(msg.id), { from: from.pk!, content: String(msg.content), epoch: S.epoch ?? 0 }); return; }
      case 'repair_help': { if (from.role === 'server') onRepairHelp(msg, from); return; }
      case 'repair_help_deltas': { if (from.role === 'server') onHelpDeltas(msg, from); return; }
      case 'repair_finish': { if (from.role === 'server') onRepairFinish(msg, from); return; }
      case 'backup_store': { if (fromPhone && S.backup && keepPart({ from: from.pk!, content: String(msg.content), epoch: Number(msg.epoch) })) { save(); toOther({ type: 'backup_sync', backup: S.backup }); } return; }
      case 'backup_sync': { if (from.role === 'server') mergeBackup(msg.backup); return; }
      case 'backup_get': { if (from.role === 'backup') sendBackup(from); return; }
      case 'recover': { if (from.role === 'backup') startRecovery(msg, from); return; }
      case 'recover_finish': { if (from.role === 'backup') finishRecovery(from); return; }
      case 'cancel_recovery': { if (mayAct(from) && msg.lock === true) cancelRecovery(from); return; }
      case 'mail_for': { if (fromPhone) holdMail(String(msg.to), { from: from.pk!, content: String(msg.content), epoch: Number(msg.epoch) }); return; }
      case 'refreshed': { if (fromPhone) { S.mail ??= {}; S.mail[from.pk!] = (S.mail[from.pk!] ?? []).filter((x: any) => x.epoch > Number(msg.epoch)); save(); } return; }
      case 'cancel_batch': { // Undo on a deletion in its 10 s
        const b = fromPhone ? batchById(String(msg.batch)) : undefined;
        if (b) { b.cancelled = true; clearTimeout(b.timer); const site = [...batches].find(([, x]) => x === b)?.[0]; if (site) void closeBatch(site, b); }
        return;
      }
      case 'repost': { if (fromPhone) repost(String(msg.id)).catch(err => toDevices({ type: 'undo_failed', id: msg.id, reason: err.message })); return; }
      case 'site_summary': { if (fromPhone) toDevices({ type: 'site_summary', pk: msg.pk, ...siteSummary(String(msg.pk)) }); return; }
      case 'undo_site': { if (fromPhone) undoSite(String(msg.pk)).catch(err => { note(`couldn't undo ${msg.pk}: ${err.message}`); toDevices({ type: 'undo_failed', id: msg.pk, reason: err.message }); }); return; }
      case 'batch_decision': { if (fromPhone) decisions.get(String(msg.batch))?.(msg.approve === true); return; }
      case 'remove_future': { if (fromPhone) removeFuture(String(msg.id)).catch(err => { note(`couldn't remove it: ${err.message}`); toDevices({ type: 'undo_failed', id: msg.id, reason: err.message }); }); return; }
      case 'ecdh_req': return answerOnce(from, msg.id, () => onEcdhReq(msg, from));

      case 'member': { // the server that added the phone says who it is
        if (fromPhone) return;
        phone().pk = msg.pk;
        if (typeof msg.name === 'string' && msg.name) phone().name = msg.name.slice(0, 40);
        save(); note('learned your phone from ' + from.name); return;
      }
      case 'push': { // where to send "approval needed"
        if (!fromPhone) return;
        from.push = msg.endpoint || null; save(); toOther({ type: 'push_relay', idx: from.idx, endpoint: msg.endpoint }); return;
      }
      case 'push_relay': { const d = members.find(m => m.idx === (msg.idx ?? phone().idx)); if (!fromPhone && d) { d.push = msg.endpoint || null; save(); } return; }
      case 'ticket': { // the phone is about to hand this to a site
        if (!(S.tickets as Ticket[]).some(t => t.t === msg.t)) {
          S.tickets.push({ t: String(msg.t), origin: String(msg.origin ?? 'a site'), expires: Number(msg.expires) });
          S.tickets = (S.tickets as Ticket[]).filter(t => t.expires > now() - 3600);
          save();
          if (fromPhone) toOther({ type: 'ticket', t: msg.t, origin: msg.origin, expires: msg.expires });
        }
        return;
      }
      case 'nostrconnect': { if (fromPhone) connectByUri(String(msg.uri), String(msg.origin ?? 'an app')).catch(err => console.error(err)); return; }
      case 'revoke': return revoke(String(msg.pk), fromPhone ? 'on your phone' : `on ${from.name}`, !fromPhone);
      case 'undo': { if (fromPhone) undo(String(msg.id)).catch(err => { note(`undo failed: ${err.message}`); toDevices({ type: 'undo_failed', id: msg.id, reason: err.message }); }); return; }
      case 'state_req': { if (fromPhone) pushState(); return; }
      case 'signed': { // the other server signed something worth keeping
        if (fromPhone) return;
        archive.record(msg.event);
        if (msg.change) addChange(msg.change, true);
        return;
      }
      case 'sync': { if (!fromPhone) mergeSync(msg); return; }
      case 'forget': { if (!fromPhone) { archive.forget(String(msg.id)); pushState(); } return; }
      case 'logged': { if (!fromPhone && msg.entry?.event) history.add(msg.entry); return; }
      case 'saved': { if (!fromPhone) for (const e of msg.events ?? []) history.save(e); return; }
    }
  }

  // --- Sites -------------------------------------------------------------------
  //
  // A site talks NIP-46 to the shared signer key, over relays. A request may arrive more
  // than once (the site re-sends until it hears back, and relays repeat things), so
  // answers are kept for a while and sent again to a repeat, freshly wrapped: strfry
  // refuses an event id it has already seen, even an ephemeral one.

  // The first server answers sites; another steps in once it has been gone 30 s.
  const firstServer = () => members.filter(m => m.role === 'server' && !m.removed && !m.noSites).sort((a, b) => a.idx - b.idx)[0];
  const coordinating = () => !!S.signer && !!firstServer() && (firstServer().idx === me.idx || (io.now() - startedAt > 30_000 && !online(firstServer())));
  const answers = new Map<string, { at: number; body: string; scheme: 'nip44' | 'nip04' }>();
  const working = new Set<string>();

  function reply(clientPk: string, scheme: 'nip44' | 'nip04', body: string) {
    const sk = F.hexToBytes(S.signer.sk);
    const content = scheme === 'nip44' ? nip44.v2.encrypt(body, nip44.v2.utils.getConversationKey(sk, clientPk)) : nip04.encrypt(sk, clientPk, body);
    io.publish(finalizeEvent({ kind: KIND_NIP46, created_at: now(), tags: [['p', clientPk]], content }, sk));
  }

  async function onSiteRequest(e: Event) {
    if (!S.signer || !groupX || !coordinating()) return; // no signer key (it serves no sites), or no key yet
    const sk = F.hexToBytes(S.signer.sk);
    let scheme: 'nip44' | 'nip04' = 'nip44', req: any;
    try { req = JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(sk, e.pubkey))); }
    catch { try { scheme = 'nip04'; req = JSON.parse(nip04.decrypt(sk, e.pubkey, e.content)); } catch { return; } }
    if (!req?.id || !req.method) return;
    io.debug?.(`site ${e.pubkey.slice(0, 6)} asked ${req.method} (${req.id})`);

    const k = `${e.pubkey}:${req.id}`;
    const cached = answers.get(k);
    if (cached) return reply(e.pubkey, cached.scheme, cached.body);
    if (working.has(k)) return;
    working.add(k);
    const answer = (body: object) => {
      const text = JSON.stringify({ id: req.id, ...body });
      answers.set(k, { at: io.now(), body: text, scheme });
      working.delete(k);
      reply(e.pubkey, scheme, text);
      // Most sites send a request once and never again, so a lost answer would leave them
      // hanging. Say it twice; a site takes the first and ignores the other.
      setTimeout(() => reply(e.pubkey, scheme, text), 3000);
    };

    try {
      const s = site(e.pubkey);
      if (req.method === 'connect') {
        if (s?.revoked) return answer({ error: 'revoked: Access for this site was removed. Connect it again from your phone.' });
        if (s) return answer({ result: 'ack' });
        const ticket = (S.tickets as Ticket[]).find(t => t.t === req.params?.[1]);
        if (!ticket || ticket.used || ticket.expires < now()) return answer({ error: 'bad-ticket: This ticket is not valid. Scan the code again with your phone.' });
        ticket.used = true;
        S.sites.push({ pk: e.pubkey, origin: ticket.origin, added: now(), lastUsed: now() } satisfies Site);
        save(); syncTo(); pushState();
        note(`${siteName(ticket.origin)} connected`);
        return answer({ result: 'ack' });
      }
      if (req.method === 'ping') return answer({ result: 'pong' });
      // Signing out of a site is removing it.
      if (req.method === 'logout') { if (s && !s.revoked) revoke(s.pk, 'by signing out'); return answer({ result: 'ack' }); }
      // Errors start with a stable code ("revoked: …") so a site can act on them without reading English.
      if (!s) return answer({ error: 'not-connected: Not connected. Scan this site’s code with your phone.' });
      if (s.revoked) return answer({ error: 'revoked: Access for this site was removed on your phone.' });
      s.lastUsed = now();

      switch (req.method) {
        case 'get_public_key': return answer({ result: groupX });
        case 'cosign_add_site': return answer(addChild(s, req.params ?? []));
        // Move the site onto the relays your servers already use: the ones known to carry this.
        case 'switch_relays': return answer({ result: JSON.stringify(S.group.relays) });
        case 'get_relays': return answer({ result: JSON.stringify(Object.fromEntries(S.group.relays.map((r: string) => [r, { read: true, write: true }]))) });
        case 'sign_event': return answer({ result: JSON.stringify(await frostSign(JSON.parse(req.params[0]), s.origin, { site: s.pk })) });
        // Not for sites that connect by code (NIP-46): every such site shares one signer key,
        // so any of them could ask to read every message. Messages go through the Cosign
        // app or extension, which ask your device, until each site has a key of its own.
        case 'nip44_encrypt': case 'nip44_decrypt': case 'nip04_encrypt': case 'nip04_decrypt':
          return answer({ error: 'unsupported: Use your sign-in app for messages.' });
        default: return answer({ error: `unsupported method ${req.method}` });
      }
    } catch (err: any) {
      answer({ error: err?.message ?? String(err) });
    }
  }

  // nostrconnect: the site showed a nostrconnect:// code and your phone scanned it. Both
  // servers take the site on and listen on its relays; whichever is answering sites tells
  // it who to talk to by sending its secret back, from the signer key.
  async function connectByUri(uri: string, origin: string) {
    let u: URL;
    try { u = new URL(uri); } catch { return; }
    const client = (u.host || u.pathname.replace(/^\/+/, '')).toLowerCase();
    const relays = [...new Set(u.searchParams.getAll('relay').filter(r => /^wss?:\/\//.test(r)).map(normRelay))].slice(0, 4);
    const secret = u.searchParams.get('secret');
    if (u.protocol !== 'nostrconnect:' || !/^[0-9a-f]{64}$/.test(client) || !relays.length || !secret) return note('ignored a damaged nostrconnect code');
    if (!S.signer) return note('ignored a nostrconnect code: this group has no signer key');
    const s = site(client);
    if (!s || s.revoked) { // the phone repeats itself until it hears back; only the first counts
      if (!s) S.sites.push({ pk: client, origin, added: now(), lastUsed: now(), relays } satisfies Site);
      else { delete s.revoked; s.relays = relays; } // scanned again: that's you letting it back in
      note(`${origin} connected${s ? ' again' : ''}, by nostrconnect`);
      save(); syncTo();
    }
    pushState();
    await io.listen(relays);
    if (!coordinating()) return;
    // Twice, in case a relay drops the first; the site takes whichever arrives.
    const answer = () => reply(client, 'nip44', JSON.stringify({ id: rid(), result: secret }));
    answer(); setTimeout(answer, 4000);
    toDevices({ type: 'connected', pk: client, origin });
  }

  /**
   * A connected site (the extension) gives one website a grant of its own, under itself:
   * listed on your phone inside that website's entry, removed with it or on its own.
   */
  function addChild(parent: Site, params: unknown[]): object {
    const [pk, origin, via] = params.map(p => String(p ?? ''));
    if (parent.parent) return { error: 'not-allowed: Only a site you connected with your phone can add others.' };
    if (!/^[0-9a-f]{64}$/.test(pk) || !origin) return { error: 'bad-request: cosign_add_site takes [pubkey, origin, via].' };
    const have = site(pk);
    if (have?.revoked) return { error: 'revoked: Access for this site was removed on your phone.' };
    if (have) return have.parent === parent.pk ? { result: 'ack' } : { error: 'not-allowed: That key already belongs to another site.' };
    S.sites.push({ pk, origin: origin.slice(0, 200), added: now(), lastUsed: now(), parent: parent.pk, via: (via || parent.origin).slice(0, 80) } satisfies Site);
    save(); syncTo(); pushState();
    note(`${origin} connected, through ${via || parent.origin}`);
    return { result: 'ack' };
  }

  // A browser extension can only claim an http(s) origin in its code, so it uses one like
  // https://chrome-on-mac.extension. Show that as "Chrome on Mac (browser extension)".
  const WORDS: Record<string, string> = { iphone: 'iPhone', ipad: 'iPad', macbook: 'MacBook', macos: 'macOS', ios: 'iOS', pc: 'PC', on: 'on', in: 'in', for: 'for' };
  function siteName(origin: string) {
    const m = /^https?:\/\/([a-z0-9-]+)\.extension\/?$/i.exec(origin);
    if (!m) return origin;
    const name = m[1].toLowerCase().split('-').filter(Boolean).map(w => WORDS[w] ?? w[0].toUpperCase() + w.slice(1)).join(' ');
    return `${name} (browser extension)`;
  }

  function revoke(pk: string, where: string, quiet = false) {
    const s = site(pk);
    if (!s || s.revoked) return;
    s.revoked = now();
    // Removing the extension removes every site it added.
    for (const c of S.sites as Site[]) if (c.parent === pk && !c.revoked) c.revoked = s.revoked;
    save();
    if (!quiet) toOther({ type: 'revoke', pk });
    pushState();
    note(`removed ${s.origin} ${where}`);
  }

  // --- Signing -----------------------------------------------------------------

  /**
   * Your phone signs the other half, quietly. If it doesn't answer in 3 s and the backup
   * server is there, the backup does. Something destructive goes only to the phone, which
   * asks you.
   */
  async function frostSign(unsigned: any, by: string, opts: { undo?: string; site?: string } = {}): Promise<Event> {
    const ev = {
      pubkey: groupX, kind: Number(unsigned.kind), created_at: Number(unsigned.created_at ?? now()),
      tags: unsigned.tags ?? [], content: unsigned.content ?? '',
    };
    if (forgetting()) throw new Error('This server is removing its pieces of your account.');
    const id = getEventHash(ev);
    const prev = archive.latest(keyOf(ev));
    const judged = assess(ev, prev);
    if (judged.refuse) { note(`refused ${kindName(ev.kind)} for ${by}: ${judged.refuse}`); throw new Error(`refused: ${judged.refuse}`); }
    // A deletion can't be taken back: keep what it deletes, give you a moment to stop it,
    // and ask once for a batch of them.
    let batch: string | undefined;
    if (ev.kind === 5 && !opts.undo) {
      await saveTargets(ev);
      const touchesList = ev.tags.some((t: string[]) => t[0] === 'a' || (t[0] === 'k' && ARCHIVED.has(Number(t[1]))));
      const b = await deletionWindow(opts.site || by, by, ev, touchesList);
      if (b.approved) batch = b.id;
    }
    const hold = judged.hold; // an approved batch still goes to the phone, which won't ask twice
    // Only partners that make the threshold with us: in a weighted key, not the other server.
    const enough = (m: Member) => new Set([...myIdxs, ...sharesOf(m)]).size >= S.group.threshold;
    const order = partners((hold ? devices() : [...devices(), ...others()]).filter(enough));
    const tried: string[] = [];
    const done = (r: Attempt) => {
      note(`signed ${kindName(ev.kind)} for ${by} with ${r.m.name}${hold && !opts.undo ? ' — you approved' : ''}`);
      keep(r.signed!, judged.change ?? hold, by, !!hold && !opts.undo, opts.site ?? '', prev);
      return r.signed!;
    };

    /** One round with one partner: its commitment and partial, then ours, then the signature. */
    async function attempt(m: Member, wait: number, reqId = rid()): Promise<Attempt> {
      // Every share of ours and of the partner's: together they must reach the threshold.
      const participants = [...myIdxs, ...sharesOf(m)].sort((a, b) => a - b);
      if (participants.length < S.group.threshold) return { m, reason: `not enough shares with ${m.name}` };
      const mine = Sig.commitAll(S.group, myShares); // fresh every round; used only once we have a valid partner
      const res = await ask(m.pk!, { type: 'sign_req', id: reqId, event: ev, msg: id, participants, commits: mine.commits, commit: mine.commits[0], frost: 2, app: by, hold: hold ?? null, undo: opts.undo ?? null, batch: batch ?? null }, wait);
      if (!res.ok) return { m, reason: String(res.reason) };
      // A partner with one share may answer the earlier way: one commit, one z.
      const theirs: Sig.Commit[] = res.commits ?? (res.commit ? [res.commit] : []);
      const theirZs: [number, string][] = res.zs ?? (res.commit ? [[res.commit.idx, res.z]] : []);
      if (!sameSet(theirs.map(c => c.idx), sharesOf(m)) || !sameSet(theirZs.map(z => z[0]), sharesOf(m))) return { m, reason: 'bad partial' };
      const commits = [...mine.commits, ...theirs];
      // FROST (RFC 9591) only: the earlier hand-rolled math is no longer taken.
      if (Sig.schemeOfAll(S.group, id, commits, theirZs) !== 2) return { m, reason: 'bad partial' };
      // It signed with the shares the list says it holds, which nothing but the real member
      // can do: whatever another server told us, it is one of the user's from here on.
      if (m.viaServer) { delete m.viaServer; save(); }
      const scheme = 2 as const;
      const zs = Sig.partialAll(scheme, S.group, myShares, mine.nonces, id, commits);
      countSigned();
      return { m, signed: { ...ev, id, sig: Sig.combine(scheme, S.group, id, commits, [...zs, ...theirZs]) } as Event };
    }

    // Everyday, with your phone and your other server both awake: ask both at once, each in
    // a round of its own. The first good answer signs; the other round is dropped, its
    // nonces never used. Only for events every member judges the same way whatever lists
    // it has seen (notes, reactions, DMs…): a list change goes to the phone first, since
    // its own copy of your lists is what catches a server that has the wrong one. Nothing
    // held, undone or batched races either.
    const sameForAll = !ARCHIVED.has(ev.kind) && ev.kind !== 5 && ev.kind !== 62;
    if (sameForAll && !hold && !opts.undo && !batch && order.length >= 2 && online(order[0]) && online(order[1])) {
      const ids = [rid(), rid()];
      const runs = order.slice(0, 2).map((m, i) => attempt(m, isDevice(m) ? 10_000 : 8_000, ids[i]));
      const first = await new Promise<Attempt | null>(resolve => {
        let left = runs.length;
        for (const r of runs) void r.then(a => { if (a.signed) resolve(a); else { tried.push(`${a.m.name}: ${a.reason}`); if (--left === 0) resolve(null); } });
      });
      ids.forEach(cancelAsk);
      if (first) { io.debug?.(`${first.m.name} answered first`); return done(first); }
    } else for (const [i, m] of order.entries()) {
      const isPhone = isDevice(m);
      const asking = isPhone && !!hold && !opts.undo && !batch; // an approved batch: the phone already said yes
      const wait = isPhone ? phoneWait(asking, order.slice(i + 1)) : online(m) ? 8_000 : 3_000; // a silent server gets a last quick try
      if (isPhone && (asking || (wait > 3_000 && !online(m)))) pushPhone();
      const a = await attempt(m, wait);
      if (a.signed) return done(a);
      tried.push(`${m.name}: ${a.reason}`);
      if (isPhone && a.reason!.includes('declined')) break; // your no stands: nobody else gets asked
    }
    const declined = tried.some(t => t.includes('declined'));
    note(`did not sign ${kindName(ev.kind)} for ${by}: ${tried.join('; ') || 'nobody to ask'}`);
    throw new Error(declined ? 'You declined this on your phone.'
      : hold ? `Waiting for your phone timed out: ${hold}.`
      : tried.length && tried.every(t => t.endsWith('no answer'))
        ? (other()?.pk && enough(other()!) ? 'Neither your phone nor your backup server answered. Is your sign-in app open?' : 'Your phone didn’t answer. Is your sign-in app open?')
      : `Couldn't sign: ${tried.join('; ') || 'nobody to ask'}`);
  }

  // --- Deletions ---------------------------------------------------------------------
  //
  // Nostr can't take a deletion back, so: keep a copy of what's being deleted (from the
  // history, or the relays), hold each site's deletions for 10 s with Undo on your phone,
  // and if together they delete 5 or more, or touch a list, ask once for all of them.

  const WINDOW = 10_000;
  interface Batch { id: string; by: string; requests: number; targets: number; held: boolean; cancelled: boolean;
    until: number; done: Promise<{ id: string; approved: boolean }>; settle: (v: { id: string; approved: boolean } | Error) => void; timer?: NodeJS.Timeout }
  const batches = new Map<string, Batch>();
  const batchById = (id: string) => [...batches.values()].find(b => b.id === id);
  const decisions = new Map<string, (approve: boolean) => void>();

  async function saveTargets(ev: Ev) {
    const ids = ev.tags.filter(t => t[0] === 'e').map(t => t[1]);
    for (const t of ev.tags.filter(t => t[0] === 'a')) { const [k, , d] = t[1].split(':'); const e = archive.latest(Number(k) >= 30000 ? `${k}:${d ?? ''}` : k); if (e) history.save(e); }
    const missing: string[] = [];
    for (const id of ids) { const e = history.event(id); if (e) history.save(e); else missing.push(id); }
    if (missing.length) {
      try {
        for (const e of await io.query([...S.group.relays, ...ourWriteRelays()], { ids: missing }, 4000)) if (e.pubkey === groupX && verifyEvent(e)) history.save(e);
      } catch { /* keep what we have */ }
    }
    const copies = ids.map(id => history.savedCopy(id)).filter(Boolean);
    if (copies.length) toOther({ type: 'saved', events: copies });
  }

  function deletionWindow(site: string, by: string, ev: Ev, held: boolean): Promise<{ id: string; approved: boolean }> {
    let b = batches.get(site);
    if (!b) {
      let settle!: Batch['settle'];
      const done = new Promise<{ id: string; approved: boolean }>((res, rej) => { settle = v => (v instanceof Error ? rej(v) : res(v)); });
      b = { id: rid(), by, requests: 0, targets: 0, held: false, cancelled: false, until: io.now() + WINDOW, done, settle };
      batches.set(site, b);
      const batch = b;
      b.timer = setTimeout(() => void closeBatch(site, batch), WINDOW);
    }
    b.requests++;
    b.targets += ev.tags.filter(t => t[0] === 'e' || t[0] === 'a').length;
    b.held ||= held;
    toDevices({ type: 'deleting', batch: b.id, by, count: b.targets, until: b.until });
    return b.done;
  }

  async function closeBatch(site: string, b: Batch) {
    if (batches.get(site) === b) batches.delete(site);
    toDevices({ type: 'deleting_done', batch: b.id });
    if (b.cancelled) return b.settle(new Error('You stopped this deletion on your phone.'));
    if (b.targets < 5 && !b.held) return b.settle({ id: b.id, approved: false });
    const text = `Delete ${b.targets} event${b.targets === 1 ? '' : 's'} for ${b.by}${b.held ? ', including one of your lists' : ''}`;
    pushPhone();
    const ok = await new Promise<boolean>(resolve => {
      const t = setTimeout(() => { decisions.delete(b.id); resolve(false); }, 60_000);
      decisions.set(b.id, approve => { clearTimeout(t); decisions.delete(b.id); resolve(approve); });
      const askNow = () => { if (decisions.has(b.id)) toDevices({ type: 'approve_batch', batch: b.id, text, by: b.by, expires: io.now() + 55_000 }); };
      askNow(); setTimeout(askNow, 4000);
    });
    note(`${ok ? 'you approved' : 'you declined'}: ${text}`);
    b.settle(ok ? { id: b.id, approved: true } : new Error('You declined this on your phone.'));
  }

  /** Who to ask, in order; anyone who's been silent goes last. */
  const partners = (want: Member[]) => want.filter(m => m.pk).sort((a, b) => Number(online(b)) - Number(online(a)));

  /** How long to give the phone: a quick try if someone else can step in, else long enough to wake it. */
  const phoneWait = (asking: boolean, after: Member[]) => asking ? 60_000 : after.some(online) ? 3_000 : 15_000;

  /** Archive what was signed, note the change, and tell the other server and the phone. */
  function keep(signed: Event, text: string | undefined, by: string, held: boolean, site = '', prev?: Event | Ev) {
    // Everything goes in the history, so a site's work can be undone however much of it there is.
    const entry: Entry = { at: now(), site, by, event: signed, ...(ARCHIVED.has(signed.kind) && prev ? { prev } : {}) };
    if (history.add(entry)) { toOther({ type: 'logged', entry }); toDevices({ type: 'logged', entry }); }
    if (!ARCHIVED.has(signed.kind) && !held) return;
    archive.record(signed);
    const change: Change | undefined = text ? { id: signed.id, key: keyOf(signed), kind: signed.kind, at: signed.created_at, text, by, held } : undefined;
    if (change) addChange(change, false);
    toOther({ type: 'signed', event: signed, change });
    // The phone judges for itself too, against the latest version it has seen signed.
    if (ARCHIVED.has(signed.kind)) toDevices({ type: 'signed', event: signed });
  }

  function addChange(c: Change, quiet: boolean) {
    if ((S.changes as Change[]).some(x => x.id === c.id)) return;
    S.changes.unshift(c);
    S.changes.sort((a: Change, b: Change) => b.at - a.at);
    S.changes.length = Math.min(S.changes.length, 60);
    save();
    if (!quiet) pushState();
  }

  // As the co-signer: check the event is what it claims to be, and judge it ourselves.
  function onSignReq(msg: any, from: Member): object {
    const respond = (r: object) => ({ type: 'sign_res', id: msg.id, ...r });
    if (forgetting()) return respond({ ok: false, reason: 'this server is removing its pieces of the account' });
    const ev = msg.event;
    const participants: number[] = msg.participants;
    if (from.role !== 'server') return respond({ ok: false, reason: 'only servers coordinate' });
    if (!Array.isArray(participants) || !sameSet(participants, [...sharesOf(from), ...myIdxs])) return respond({ ok: false, reason: 'bad participants' });
    if (ev.pubkey !== groupX || getEventHash(ev) !== msg.msg) return respond({ ok: false, reason: 'event does not match the message' });
    // Our own archive, not the coordinator's word: a compromised server can't talk us
    // into co-signing something destructive without the phone.
    const { hold, refuse } = assess(ev, archive.latest(keyOf(ev)));
    if (refuse) { note(`refused to co-sign for ${from.name}: ${refuse}`); return respond({ ok: false, reason: `refused: ${refuse}` }); }
    if (hold && !participants.some(i => isDevice(ownerOf(i)))) {
      note(`refused to co-sign for ${from.name}: ${hold} needs your phone`);
      return respond({ ok: false, reason: `${hold} needs your phone` });
    }
    if (msg.frost !== 2) return respond({ ok: false, reason: 'update Cosign: only FROST (RFC 9591) rounds are taken' });
    return respond(cosign(msg, 2));
  }

  /** Our commitments and partials for a round someone else runs, over its commitments and ours. */
  function cosign(msg: any, scheme: Sig.Scheme) {
    countSigned();
    const theirs: Sig.Commit[] = msg.commits ?? [msg.commit];
    const mine = Sig.commitAll(S.group, myShares);
    const zs = Sig.partialAll(scheme, S.group, myShares, mine.nonces, msg.msg, [...theirs, ...mine.commits]);
    // The first ones again the earlier way, for a coordinator that predates several shares.
    return { ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] };
  }

  function onEcdhReq(msg: any, from: Member): object {
    const respond = (r: object) => ({ type: 'ecdh_res', id: msg.id, ...r });
    if (forgetting()) return respond({ ok: false, reason: 'this server is removing its pieces of the account' });
    // Only one of your devices, or another server running the round for one: never the
    // paper, which with this server's piece could read every message at once, with no
    // wait and nobody told. And the shares taking part must be enough to sign.
    if (!isDevice(from) && from.role !== 'server') return respond({ ok: false, reason: 'not allowed' });
    if (!Array.isArray(msg.participants) || !sameSet(msg.participants, [...sharesOf(from), ...myIdxs])) return respond({ ok: false, reason: 'bad request' });
    if (msg.participants.length < S.group.threshold) return respond({ ok: false, reason: 'bad request' });
    // The phone asks on behalf of an app it has let read your messages; that app must still have access.
    if (isDevice(from) && !liveGrant(msg.grant)) return respond({ ok: false, reason: 'revoked: that app no longer has access' });
    const points = myShares.map(s => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants: msg.participants, peerX: msg.peerX }));
    return respond({ ok: true, points, point: points[0] });
  }

  // --- Apps on your phone (Android signer, NIP-55) ------------------------------------
  //
  // The app asks your phone; the phone runs the round and asks this server for the other
  // half, as a site would ask a server. This server still judges every event against its
  // own archive: something destructive needs the phone to say you approved it there.

  const liveGrant = (pk: unknown) => { const s = site(String(pk)); return s && !s.revoked ? s : undefined; };

  function grantApp(msg: any) {
    const pk = String(msg.pk ?? '');
    if (!/^[0-9a-f]{64}$/.test(pk)) return;
    const s = site(pk);
    if (s && !s.revoked) {
      // The same grant, under a new name: an app renamed itself (Cosign became Marble).
      // Only your own device ever says so — this is `fromPhone` — so it is simply taken.
      const now = String(msg.origin ?? '').slice(0, 80);
      if (now && now !== s.origin) { note(`${s.origin} is called ${now} now`); s.origin = now; save(); syncTo(); }
      return pushState();
    }
    // `via`: which of your devices it's on (the extension says "Chrome on Mac").
    const named = typeof msg.via === 'string' && msg.via.trim() ? msg.via.trim().slice(0, 40) : null;
    const via = named ?? 'App on this phone';
    if (s) delete s.revoked; // connected again on the phone
    else S.sites.push({ pk, origin: String(msg.origin ?? 'An app').slice(0, 80), added: now(), lastUsed: now(), via } satisfies Site);
    save(); syncTo(); pushState();
    note(`${msg.origin} connected, ${named ? 'on ' + named : 'as an app on your phone'}`);
  }

  function onCosignReq(msg: any, from: Member): object {
    const respond = (r: object) => ({ type: 'cosign_res', id: msg.id, ...r });
    if (forgetting()) return respond({ ok: false, reason: 'this server is removing its pieces of the account' });
    const ev = msg.event;
    if (!isDevice(from)) return respond({ ok: false, reason: 'only your devices do this' });
    const participants: number[] = msg.participants ?? [];
    if (!Array.isArray(participants) || !sameSet(participants, [...sharesOf(from), ...myIdxs])) return respond({ ok: false, reason: 'bad participants' });
    if (ev?.pubkey !== groupX || getEventHash(ev) !== msg.msg) return respond({ ok: false, reason: 'event does not match the message' });
    const grant = liveGrant(msg.grant);
    if (!grant) return respond({ ok: false, reason: 'revoked: that app no longer has access' });
    const { hold, refuse } = assess(ev, archive.latest(keyOf(ev)));
    if (refuse) return respond({ ok: false, reason: `refused: ${refuse}` });
    if (hold && !msg.approved) return respond({ ok: false, reason: `needs-approval: ${hold}` });
    grant.lastUsed = now();
    return respond(cosign(msg, 2));
  }

  /** The phone finished a round for an app: keep it like anything else signed here. */
  function onPhoneSigned(msg: any) {
    const ev = msg.event as Event;
    if (!ev || ev.pubkey !== groupX || !verifyEvent(ev)) return;
    const prev = archive.latest(keyOf(ev));
    const judged = assess(ev, prev);
    const app = liveGrant(msg.grant)?.origin ?? 'an app on your phone';
    note(`your phone signed ${kindName(ev.kind)} for ${app}${msg.approved ? ' — you approved' : ''}`);
    keep(ev, judged.change ?? judged.hold, app, !!msg.approved && !!judged.hold, String(msg.grant ?? ''), prev);
  }

  // Shared secrets for encrypting on your behalf. Memory only, ten minutes.
  const ecdhCache = new Map<string, { x: Uint8Array; at: number }>();
  async function frostEcdh(peerX: string): Promise<Uint8Array> {
    if (forgetting()) throw new Error('This server is removing its pieces of your account.');
    const hit = ecdhCache.get(peerX);
    if (hit && io.now() - hit.at < 600_000) return hit.x;
    const tried: string[] = [];
    const order = partners([...devices(), ...others()]);
    for (const [i, m] of order.entries()) {
      const participants = [...myIdxs, ...sharesOf(m)].sort((a, b) => a - b);
      if (participants.length < S.group.threshold) { tried.push(`${m.name}: not enough shares`); continue; }
      const res = await ask(m.pk!, { type: 'ecdh_req', id: rid(), peerX, participants }, isDevice(m) ? phoneWait(false, order.slice(i + 1)) : 6_000);
      if (!res.ok) { tried.push(`${m.name}: ${res.reason}`); continue; }
      const x = F.ecdhCombine([...myShares.map(s => F.ecdhPartial({ idx: s.idx, secret: s.secret, participants, peerX })), ...(res.points ?? [res.point])]);
      ecdhCache.set(peerX, { x, at: io.now() });
      return x;
    }
    throw new Error('no member answered: ' + tried.join('; '));
  }
  const groupNip44Key = async (peerX: string) => extract(sha256, await frostEcdh(peerX), utf8ToBytes('nip44-v2'));
  async function groupNip04(peerX: string, text: string, decrypt: boolean) {
    const key = await frostEcdh(peerX);
    const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
    const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    if (decrypt) {
      const [ct, iv] = text.split('?iv=');
      return new TextDecoder().decode(cbc(key, unb64(iv)).decrypt(unb64(ct)));
    }
    const iv = F.randomBytes(16);
    return b64(cbc(key, iv).encrypt(new TextEncoder().encode(text))) + '?iv=' + b64(iv);
  }

  // --- Undo --------------------------------------------------------------------
  //
  // Sign the version before this change again, with a fresh timestamp, and publish it.
  // The phone asked for it, so if it needs the phone, the phone co-signs without asking.

  async function undo(changeId: string) {
    const change = (S.changes as Change[]).find(c => c.id === changeId);
    const target = archive.find(changeId);
    if (!change || !target) throw new Error('nothing to undo');
    // The version kept just after it (newest first), which may share its second.
    const versions = archive.history(keyOf(target));
    const before = versions.slice(versions.findIndex(e => e.id === target.id) + 1).find(e => e.created_at <= target.created_at);
    if (!before) throw new Error('there is no earlier version to go back to');
    const signed = await frostSign({ kind: before.kind, tags: before.tags, content: before.content, created_at: now() }, 'Undo on your phone', { undo: changeId });
    change.undone = true; save();
    await publishOut(signed);
    pushState();
    toOther({ type: 'sync', changes: S.changes });
    note(`undid "${change.text}"`);
  }

  // --- Versions dated in the future ----------------------------------------------------
  //
  // Nothing here signs one, but one may already be out there (signed before Cosign, or
  // by a key that leaked). On any relay that took it, it beats every change you make.
  // Deleting it by its id works whatever date it claims.

  const flagged = new Set<string>();
  function checkFuture() {
    for (const e of archive.future()) {
      if (flagged.has(e.id!)) continue;
      flagged.add(e.id!);
      toOther({ type: 'sync', archive: [e] }); // so both servers warn the phone, not just this one
      note(`found your ${kindName(e.kind)} dated ${new Date(e.created_at * 1000).toISOString().slice(0, 10)} on relays: it blocks every change`);
    }
    if (archive.future().length) pushState();
  }

  async function removeFuture(id: string) {
    const target = archive.future().find(e => e.id === id);
    if (!target) throw new Error('nothing dated in the future with that id');
    const deletion = await frostSign({ kind: 5, created_at: now(), content: 'Dated in the future by mistake', tags: [['e', id], ['k', String(target.kind)]] }, 'Your phone', { undo: id });
    await publishOut(deletion);
    archive.forget(id);
    toOther({ type: 'forget', id });
    pushState();
    note(`removed the ${kindName(target.kind)} dated in the future`);
  }

  // --- Undo everything a site did ----------------------------------------------------
  //
  // From the history: put every list it changed back to the version before its first
  // change, and delete everything else it signed (one deletion per 500 events). The
  // copies stay in the history. Your phone confirmed it, so it co-signs without asking.

  const kept = (k: number) => !(k === 5 || k === 62 || (k >= 20000 && k < 30000) || k === 22242 || k === 27235 || k === 24242);
  /** Everything one grant did, with whatever it added under itself (the extension's websites). */
  function siteEntries(pk: string): Entry[] {
    const pks = new Set([pk, ...(S.sites as Site[]).filter(c => c.parent === pk).map(c => c.pk)]);
    return [...pks].flatMap(p => history.bySite(p));
  }

  function siteSummary(pk: string) {
    const entries = siteEntries(pk);
    const counts: Record<string, number> = {};
    for (const e of entries) counts[kindName(e.event.kind)] = (counts[kindName(e.event.kind)] ?? 0) + 1;
    const lists = [...new Set(entries.filter(e => ARCHIVED.has(e.event.kind)).map(e => kindName(e.event.kind)))];
    const deletable = entries.filter(e => !ARCHIVED.has(e.event.kind) && kept(e.event.kind)).length;
    return { origin: site(pk)?.origin ?? 'that site', total: entries.length, counts, lists, deletable };
  }

  async function undoSite(pk: string) {
    const s = site(pk);
    if (!s) throw new Error('no such site');
    const entries = siteEntries(pk).sort((a, b) => a.at - b.at);
    revoke(pk, 'to undo it');
    const tag = `site:${pk}`;
    let restored = 0, deleted = 0;
    // Lists: back to the version before this site's first change to each one.
    const firstByKey = new Map<string, Entry>();
    for (const e of entries) if (ARCHIVED.has(e.event.kind) && !firstByKey.has(keyOf(e.event))) firstByKey.set(keyOf(e.event), e);
    for (const [key, first] of firstByKey) {
      const before = first.prev;
      if (!before && first.event.kind === 0) continue; // there was no profile before it: nothing to go back to
      const d = first.event.tags.find(t => t[0] === 'd');
      const signed = await frostSign({ kind: first.event.kind, content: before?.content ?? '', tags: before?.tags ?? (d ? [d] : []), created_at: now() }, 'Undo on your phone', { undo: tag });
      await publishOut(signed);
      restored++;
      void key;
    }
    // Everything else: deleted, 500 at a time.
    const others = entries.filter(e => !ARCHIVED.has(e.event.kind) && kept(e.event.kind)).map(e => e.event);
    for (let i = 0; i < others.length; i += 500) {
      const chunk = others.slice(i, i + 500);
      const kinds = [...new Set(chunk.map(e => String(e.kind)))];
      const deletion = await frostSign({ kind: 5, content: `Undoing what ${s.origin} did`, created_at: now(), tags: [...chunk.map(e => ['e', e.id!]), ...kinds.map(k => ['k', k])] }, 'Undo on your phone', { undo: tag });
      await publishOut(deletion);
      deleted += chunk.length;
    }
    note(`undid ${s.origin}: ${restored} list${restored === 1 ? '' : 's'} put back, ${deleted} event${deleted === 1 ? '' : 's'} deleted (copies kept)`);
    toDevices({ type: 'undone_site', pk, origin: s.origin, restored, deleted });
    pushState();
  }

  /** Post a deleted event again, from its kept copy: same words, a new event (Nostr can't undelete). */
  async function repost(id: string) {
    const copy = history.savedCopy(id);
    if (!copy) throw new Error('no copy of that one');
    const signed = await frostSign({ kind: copy.kind, content: copy.content, tags: copy.tags, created_at: now() }, 'Posted again on your phone', { undo: `repost:${id}` });
    await publishOut(signed);
    reposted.add(id);
    note(`posted a deleted ${kindName(copy.kind)} again`);
    pushState();
  }
  const reposted = new Set<string>();

  const ourWriteRelays = () => (archive.latest('10002')?.tags ?? []).filter(t => t[0] === 'r' && t[2] !== 'read').map(t => t[1]);

  /** Your relays: the write relays in your archived relay list, plus the group's. */
  async function publishOut(e: Event) {
    await io.publishOut([...new Set([...ourWriteRelays(), ...S.group.relays])], e);
  }

  // --- Keeping the two servers and the phone in step ------------------------------

  function syncTo() {
    toOther({ type: 'sync', sites: S.sites, tickets: S.tickets, changes: S.changes, archive: archive.all() });
  }

  function mergeSync(msg: any) {
    let dirty = false;
    for (const s of (msg.sites ?? []) as Site[]) {
      const mine = site(s.pk);
      if (!mine) { S.sites.push(s); dirty = true; if (s.relays && !s.revoked) void io.listen(s.relays); continue; }
      if (s.revoked && !mine.revoked) { mine.revoked = s.revoked; dirty = true; }
      if (s.lastUsed > mine.lastUsed) { mine.lastUsed = s.lastUsed; dirty = true; }
    }
    for (const t of (msg.tickets ?? []) as Ticket[]) {
      const mine = (S.tickets as Ticket[]).find(x => x.t === t.t);
      if (!mine) { S.tickets.push(t); dirty = true; } else if (t.used && !mine.used) { mine.used = true; dirty = true; }
    }
    for (const e of msg.archive ?? []) archive.record(e);
    checkFuture();
    for (const c of (msg.changes ?? []) as Change[]) {
      const mine = (S.changes as Change[]).find(x => x.id === c.id);
      if (!mine) addChange(c, true); else if (c.undone && !mine.undone) { mine.undone = true; dirty = true; }
    }
    if (dirty) save();
    pushState();
  }

  function pushState() {
    toDevices({
      type: 'state',
      sites: (S.sites as Site[]).filter(s => !s.revoked).map(s => ({ pk: s.pk, origin: siteName(s.origin), added: s.added, lastUsed: s.lastUsed, parent: s.parent ?? null, via: s.via ?? null })),
      changes: (S.changes as Change[]).slice(0, 30),
      // Deleted, with a copy kept: the newest 20, for "Post again".
      deleted: history.allSaved().filter(e => !ARCHIVED.has(e.kind) && !reposted.has(e.id!)).sort((a, b) => b.created_at - a.created_at).slice(0, 20)
        .map(e => ({ id: e.id, kind: kindName(e.kind), at: e.created_at, text: e.content.slice(0, 140) })),
      future: archive.future().map(e => ({ id: e.id, kind: e.kind, at: e.created_at, text: `Your ${kindName(e.kind)} has a version dated ${new Date(e.created_at * 1000).toISOString().slice(0, 10)}. On relays that took it, it blocks every change you make.` })),
    });
  }

  /** Wake your devices through ntfy. The message says only that something is waiting. */
  function pushPhone() {
    for (const d of devices()) {
      if (!d.push) continue;
      io.push(d.push)
        .catch(err => note(`push to ${d.name} failed: ${err.message}`));
    }
  }

  // --- Adding a device ------------------------------------------------------------------
  //
  // One of your devices vouches for a new one (it scanned the new one's code and you
  // unlocked it). That device and this server make the newcomer's share by repair: each
  // splits its weighted part of f(k) into deltas, they trade one, and each seals its sum
  // (a sigma) to the newcomer, who adds the two. Neither helper ever has the new share.

  interface Adding {
    ks: number[]; helpers: number[]; pk: string; name: string; by: Member; local: Map<string, string[]>; at: number; backup?: boolean; grow?: boolean; asServer?: boolean; relays?: string[]; pieces?: Piece[];
    /** Other servers helping when the vouching device and this server hold fewer than the threshold between them. */
    extras: Member[]; fromExtras: Map<string, [number, number, number, string][]>; toExtras: Map<string, [number, number, number, string][]>; toBy: [number, number, number, string][];
  }
  /** Another server's repair this server is helping with: its deltas to its own shares, kept until the rest arrive. */
  const helping = new Map<string, { ks: number[]; local: Map<string, string[]>; pk: string; backup: boolean; coordinator: string; at: number }>();
  const adding = new Map<string, Adding>();
  /** Deltas waiting to be summed, by new share and the helper share they're for. */
  const slot = (k: number, j: number) => `${k}:${j}`;

  async function addDevice(msg: any, by: Member, waited = false) {
    const pk = String(msg.pk ?? '');
    if (!/^[0-9a-f]{64}$/.test(pk)) throw new Error('that code is damaged');
    // A paper backup is 2 points and a server is 1, and either, handed to a key the asking
    // device keeps, is the threshold with that device's own 3 — the whole key, from one
    // device, for good. So these two wait: every device is told and woken, any one of them
    // can stop it, and **no piece is made until the wait ends**, because a wait that only
    // delays trust is no use once the pieces are out. A device is not held this way: it is
    // the everyday action, and it is what §7.1's lock is for.
    if ((msg.backup === true || msg.server === true) && !waited) {
      const had = guardById(msg.id);
      if (had && !active(had)) throw new Error(had.cancelled ? 'that was stopped from one of your devices' : 'that was already done');
      const g = startGuard('add', msg, by, { wait: ADD_WAIT, target: undefined });
      if (!had) {
        S.pendingAdds = { ...(S.pendingAdds ?? {}), [g.id]: { msg, by: by.idx } };
        for (const id of Object.keys(S.pendingAdds).slice(0, -10)) delete S.pendingAdds[id];
        save();
        note(`${by.name} asked to add ${msg.backup === true ? 'a paper backup' : 'a server'}; any of your devices can stop it before ${new Date(g.until * 1000).toISOString()}`);
      }
      send(by.pk, { type: 'guard', ...guardView(g) });
      return;
    }
    // `grow`: a device with too few shares to sign with one server (restored from a 2-share
    // paper) asks for a device's full 3, made by repair like any new device's, under its own key.
    const grow = msg.grow === true && pk === by.pk;
    if (!grow && members.some(m => m.pk === pk && !m.removed)) throw new Error('that device is already one of yours');
    // One device vouching is instant only with its own lock, asked for right then.
    if (msg.lock !== true) throw new Error('adding a device needs this phone’s lock');
    // The new device gets as many shares as the one vouching for it (3 in a weighted key).
    // A paper backup gets 2, or 3 while there's only one server (COSIGN.md §3). A server
    // being added (`server`, enrolled on its host to wait for this) gets 1, at the index
    // the device gave both.
    const backup = msg.backup === true;
    const asServer = msg.server === true;
    const next = Math.max(...members.flatMap(sharesOf)) + 1;
    // A paper is always 2: with a server it can bring the account back (2 + 1 + 1 of a
    // second server), never alone, nor with one server. So it needs two servers first.
    if (backup && members.filter(m => m.role === 'server' && !m.removed).length < 2) throw new Error('add a second server first: a paper backup needs two');
    const count = backup ? 2 : grow ? 3 : asServer ? 1 : sharesOf(by).length;
    // A paper must never be enough to sign alone, or with one server (keys made before weighted ones have threshold 2).
    if (backup && count + 1 >= S.group.threshold) throw new Error('this account is too old for a paper backup: its paper could sign with one server');
    const ks = asServer && Number.isInteger(msg.k) && msg.k >= next ? [msg.k as number] : Array.from({ length: count }, (_, i) => next + i);
    // The vouching device and this server, and if that's short of the threshold (a device
    // restored from a 2-share paper, say), other servers too.
    const extras: Member[] = [];
    let held = sharesOf(by).length + myIdxs.length;
    for (const srv of partners(members.filter(m => m.role === 'server' && !m.removed && m.idx !== me.idx))) {
      if (held >= S.group.threshold) break;
      extras.push(srv); held += sharesOf(srv).length;
    }
    if (held < S.group.threshold) throw new Error('not enough shares to vouch with');
    const helpers = [...sharesOf(by), ...myIdxs, ...extras.flatMap(sharesOf)].sort((a, b) => a - b);
    // Each of our shares splits its part of f(k) into a delta per helper share: ours stay
    // here, the vouching device's go to it.
    const local = new Map<string, string[]>();
    const toBy: [number, number, number, string][] = [];
    const toExtras = new Map<string, [number, number, number, string][]>();
    for (const k of ks) for (const s of myShares) {
      for (const [j, d] of Sig.repairStep1(S.group, s.idx, s.secret, helpers, k)) {
        const x = extras.find(e => sharesOf(e).includes(j));
        if (myIdxs.includes(j)) local.set(slot(k, j), [...local.get(slot(k, j)) ?? [], d]);
        else if (x) toExtras.set(x.pk!, [...toExtras.get(x.pk!) ?? [], [k, s.idx, j, d]]);
        else toBy.push([k, s.idx, j, d]);
      }
    }
    const a: Adding = { ks, helpers, pk, name: String(msg.name ?? (backup ? 'Paper backup' : asServer ? 'A server' : 'A device')).slice(0, 40), by, local, at: io.now(), backup, grow, asServer, extras, fromExtras: new Map(), toExtras, toBy };
    adding.set(String(msg.id), a);
    const relays = (msg.relays ?? []).filter((r: unknown) => typeof r === 'string' && /^wss?:\/\//.test(r)).slice(0, 4);
    if (asServer) a.relays = relays;
    if (relays.length) await io.listen(relays);
    note(`${by.name} is adding ${msg.name ?? 'a device'}${extras.length ? `, with ${extras.map(e => e.name).join(', ')}` : ''}`);
    // The other servers first: the device needs their deltas along with ours.
    if (extras.length) for (const x of extras) send(x.pk, { type: 'repair_help', id: msg.id, ks, helpers, pk, backup });
    else askDevice(String(msg.id), a);
  }

  function askDevice(id: string, a: Adding) {
    const deltas = [...a.toBy, ...[...a.fromExtras.values()].flat().filter(t => sharesOf(a.by).includes(t[2]))];
    // `k`/`delta`: the earlier one-share form, for an app not updated yet.
    const one = a.ks.length === 1 && myShares.length === 1 && !a.extras.length ? { k: a.ks[0], delta: deltas[0][3] } : {};
    send(a.by.pk, { type: 'repair', id, ks: a.ks, helpers: a.helpers, deltas, pk: a.pk, ...one });
  }

  /** Another server's deltas for a repair this server is running. */
  function onHelpDeltas(msg: any, from: Member) {
    const a = adding.get(String(msg.id));
    if (!a || !a.extras.some(x => x.idx === from.idx) || a.fromExtras.has(from.pk!)) return;
    a.fromExtras.set(from.pk!, (msg.deltas ?? []).filter((t: any) => sharesOf(from).includes(t[1])));
    if (a.fromExtras.size === a.extras.length) askDevice(String(msg.id), a);
  }

  /** Helping another server add a device: our deltas for every helper share, ours kept. */
  function onRepairHelp(msg: any, from: Member) {
    const ks: number[] = msg.ks, helpers: number[] = msg.helpers, pk = String(msg.pk ?? '');
    if (!Array.isArray(ks) || !Array.isArray(helpers) || !myIdxs.every(i => helpers.includes(i)) || !/^[0-9a-f]{64}$/.test(pk)) return;
    const local = new Map<string, string[]>();
    const out: [number, number, number, string][] = [];
    for (const k of ks) for (const s of myShares) for (const [j, d] of Sig.repairStep1(S.group, s.idx, s.secret, helpers, k)) {
      if (myIdxs.includes(j)) local.set(slot(k, j), [...local.get(slot(k, j)) ?? [], d]); else out.push([k, s.idx, j, d]);
    }
    helping.set(String(msg.id), { ks, local, pk, backup: msg.backup === true, coordinator: from.pk!, at: io.now() });
    send(from.pk, { type: 'repair_help_deltas', id: msg.id, deltas: out });
  }

  /** The rest of our deltas: our sigmas, to the new device (or sealed to the paper, via the server running it). */
  function onRepairFinish(msg: any, from: Member) {
    const h = helping.get(String(msg.id));
    if (!h || h.coordinator !== from.pk || io.now() - h.at > 120_000) return;
    helping.delete(String(msg.id));
    const theirs: [number, number, number, string][] = msg.deltas ?? [];
    const sigmas = h.ks.flatMap(k => myIdxs.map(j => [k, j, Sig.repairStep2([...h.local.get(slot(k, j)) ?? [], ...theirs.filter(t => t[0] === k && t[2] === j).map(t => String(t[3]))])] as [number, number, string]));
    if (h.backup) send(from.pk, { type: 'backup_piece', id: msg.id, content: sealTo(h.pk, { sigmas }) });
    else send(h.pk, { type: 'sigma', id: msg.id, sigmas });
  }

  function onRepairDelta(msg: any, from: Member) {
    const a = adding.get(String(msg.id));
    if (!a || a.by.idx !== from.idx || io.now() - a.at > 120_000) return;
    const theirs: [number, number, number, string][] = msg.deltas ?? [[a.ks[0], from.idx, myIdxs[0], String(msg.delta)]];
    const fromX = [...a.fromExtras.values()].flat();
    // The other servers get the device's deltas and ours for their shares, and finish their part.
    for (const x of a.extras) send(x.pk, { type: 'repair_finish', id: msg.id, deltas: [
      ...theirs.filter(t => sharesOf(x).includes(t[2]) && sharesOf(from).includes(t[1])), ...(a.toExtras.get(x.pk!) ?? []),
      ...fromX.filter(t => sharesOf(x).includes(t[2])),
    ] });
    const sigmas: [number, number, string][] = [];
    for (const k of a.ks) for (const j of myIdxs) {
      const ds = [...a.local.get(slot(k, j)) ?? [], ...theirs.filter(t => t[0] === k && t[2] === j && sharesOf(from).includes(t[1])).map(t => String(t[3])),
        ...fromX.filter(t => t[0] === k && t[2] === j).map(t => String(t[3]))];
      if (ds.length !== a.helpers.length) return note(`${a.name}: pieces missing; not added`);
      sigmas.push([k, j, Sig.repairStep2(ds)]);
    }
    if (a.backup) return backupPiece(a, String(msg.id), { from: me.pk!, content: sealTo(a.pk, { sigmas }), epoch: S.epoch ?? 0 });
    const one = sigmas.length === 1 ? { k: a.ks[0], sigma: sigmas[0][2] } : {};
    send(a.pk, {
      type: 'welcome', id: msg.id, ks: a.ks, helpers: a.helpers, sigmas, name: a.name, signer: S.signer?.pk ?? null, epoch: S.epoch ?? 0, ...one,
      group: { groupX, npub: S.group.npub, threshold: S.group.threshold, relays: S.group.relays, members: publicMembers() },
    });
  }

  /** The newcomer has its shares and checked them against the group: it's a member now. */
  function onJoined(msg: any, fromPk: string) {
    const a = adding.get(String(msg.id));
    if (!a || a.pk !== fromPk) return;
    adding.delete(String(msg.id));
    const theirs = new Map<number, string>(msg.sharePubs ?? [[a.ks[0], msg.sharePub]]);
    const shares = a.ks.map(k => ({ idx: k, sharePub: Sig.sharePubAt(S.group, k) }));
    if (shares.some(s => theirs.get(s.idx) !== s.sharePub)) return note(`${a.name} didn't end up with the right shares; not added`);
    if (a.grow) {
      // Its new shares replace the few it had; a refresh it asks for next makes the old ones useless.
      Object.assign(a.by, { sharePub: shares[0].sharePub, shares });
      save();
      toOther({ type: 'members', members });
      toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 });
      return note(`${a.by.name} has a device's full shares now`);
    }
    members.push({ idx: a.ks[0], name: a.name, role: a.asServer ? 'server' : 'device', pk: a.pk, sharePub: shares[0].sharePub, push: null, since: now(), ...(shares.length > 1 ? { shares } : {}) });
    // A new server may be reachable only where it listens (a Worker is its own relay): keep listening there.
    if (a.asServer && a.relays?.length) { S.group.relays = [...new Set([...S.group.relays, ...a.relays])].slice(0, 8); void io.listen(a.relays); }
    // A paper made when there was one server holds 3: with this one it would reach 4 on its
    // own. It's retired (it gets nothing more from any server), and your devices are asked
    // for a new one (2), and to refresh so its shares stop counting.
    if (a.asServer) for (const b of members) if (b.role === 'backup' && !b.removed && sharesOf(b).length >= 3) {
      b.removed = now();
      if (S.backup?.pk === b.pk) S.backup = null;
      toDevices({ type: 'paper_retired', reason: 'second-server' });
      note('your paper backup was made with one server: retired now that there are two. Make a new one.');
    }
    lastSeen.set(a.ks[0], io.now());
    save();
    toOther({ type: 'members', members });
    toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 });
    // Every other device is told in so many words, and woken for it. Adding a device is
    // instant on one device's lock (§7.1), so the one thing the user's other devices can do
    // is hear about it while it still matters: a device they didn't add is the start of
    // everything else, and reporting it lost is one tap.
    toDevices({ type: 'added', name: a.name, by: a.by.name, role: a.asServer ? 'server' : 'device', idx: a.ks[0] });
    for (const d of devices()) if (d.push && d.idx !== a.by.idx && d.idx !== a.ks[0]) void io.push(d.push);
    note(`${a.name} joined, vouched for by ${a.by.name}`);
  }

  const publicMembers = () => members.filter(m => !m.removed).map(m => ({ idx: m.idx, name: m.name, role: m.role, pk: m.pk, sharePub: m.sharePub, ...(m.shares ? { shares: m.shares } : {}) }));

  /** The other server's member list: take anything new, and every removal. */
  function mergeMembers(list: Member[]) {
    let dirty = false;
    for (const m of list) {
      const mine = members.find(x => x.idx === m.idx);
      // Taken, because the other server may be the only one that saw a new device added —
      // but marked, because this server has no evidence of its own that it is a device.
      if (!mine) { members.push({ ...m, push: m.push ?? null, viaServer: now() }); dirty = true; continue; }
      if (m.removed && !mine.removed) { mine.removed = m.removed; dirty = true; }
      if (!mine.pk && m.pk) { mine.pk = m.pk; dirty = true; }
      // A paper backup that became the phone it restored (after the wait, at the other server).
      if (mine.role === 'backup' && m.role === 'device' && !m.removed) {
        // The paper reached every server and each ran the same wait, so a server that saw
        // this very recovery has evidence of its own and takes it as its own. One that
        // never saw it is only repeating what it was told.
        const ours = S.recovery?.pk === m.pk;
        Object.assign(mine, { role: 'device', pk: m.pk, name: m.name, ...(ours ? {} : { viaServer: now() }) });
        if (ours) { S.recovery = null; S.backup = null; }
        dirty = true;
      }
      if (m.noSites && !mine.noSites) { mine.noSites = true; dirty = true; }
      // A device that grew its shares (after a paper recovery), at the other server.
      // Only a change of which shares it holds: points move by refresh, which each server works out itself.
      if (m.shares && !m.removed && mine.role !== 'server' && !sameSet(m.shares.map(x => x.idx), sharesOf(mine))) { Object.assign(mine, { shares: m.shares, sharePub: m.sharePub }); dirty = true; }
    }
    if (dirty) { save(); toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 }); }
  }

  // --- Adding your phone --------------------------------------------------------

  let offeredTo: string | null = null;
  const pairingUri = () => S.pairing
    ? `cosign:pair?pk=${me.pk}&t=${S.pairing.token}&${S.group.relays.map((r: string) => 'r=' + encodeURIComponent(r)).join('&')}`
    : null;

  /** What the joining device calls itself ("Chrome on Mac"), if it said. */
  let offeredName: string | null = null;

  function onPairHello(msg: any, fromPk: string) {
    if (!S.pairing || msg.token !== S.pairing.token) return;
    offeredName = typeof msg.name === 'string' && msg.name.trim() ? msg.name.trim().slice(0, 40) : null;
    if (S.pairing.weighted) return offerWeighted(fromPk);
    offeredTo = fromPk;
    send(fromPk, {
      type: 'pair_offer', token: S.pairing.token, idx: S.pairing.idx, share: S.pairing.share,
      signer: S.signer.pk,
      group: { groupX, npub: S.group.npub, threshold: S.group.threshold, relays: S.group.relays,
        members: members.filter(m => !m.removed).map(m => ({ idx: m.idx, name: m.name, role: m.role, pk: isDevice(m) ? null : m.pk, sharePub: m.sharePub })) },
    });
    note('a phone scanned the code');
  }

  function onPairAck(msg: any, fromPk: string) {
    // A member a web page dealt (core/enroll.ts claim): whoever has the token is that device.
    if (S.pairing?.claim && msg.token === S.pairing.token && !byPk(fromPk)) offeredTo = fromPk;
    if (!S.pairing || fromPk !== offeredTo || msg.token !== S.pairing.token) return;
    if (S.pairing.weighted) {
      // The phone may finish making the key before we do; take its word once we have.
      if (!groupX) { earlyAck = msg; return; }
      if (msg.groupX !== groupX) return note('your phone made a different key; not added');
    }
    const p = S.pairing.claim ? members.find(m => m.idx === S.pairing.idx)! : phone();
    p.pk = fromPk;
    if (offeredName) p.name = offeredName;
    if (S.pairing.claim && typeof msg.name === 'string' && msg.name.trim()) p.name = msg.name.trim().slice(0, 40);
    S.pairing = null; // the phone has its share; this server no longer does
    save();
    lastSeen.set(p.idx, io.now());
    toOther({ type: 'member', idx: p.idx, pk: fromPk, name: p.name });
    note('your phone joined');
  }

  // A weighted group starts with no key at all: your phone (3 shares) and both servers
  // (1 each) make it together when the phone scans the code, and nobody ever holds it
  // (dkg.ts). This server runs the plan and tells the other one to join in.

  let dkg: DkgRun | null = null;
  let earlyAck: any = null;
  let startTimer: NodeJS.Timeout | undefined;

  function offerWeighted(fromPk: string) {
    if (groupX) return; // made already; waiting for the phone's ack
    if (!dkg || offeredTo !== fromPk) {
      dkg?.stop(); clearInterval(startTimer);
      offeredTo = fromPk;
      const plan: DkgPlan = {
        session: F.bytesToHex(F.randomBytes(16)), threshold: S.group.threshold,
        holders: members.filter(m => !m.removed).flatMap(m => sharesOf(m).map(idx => ({ idx, pk: (m.idx === phone().idx ? fromPk : m.pk)! }))),
      };
      dkg = new DkgRun(plan, me.pk!, send, onDkgDone);
      dkg.start();
      // Keep telling the other server until we're done: its packages are what we wait for.
      const tell = () => { if (dkg?.done) clearInterval(startTimer); else toOther({ type: 'dkg_start', plan }); };
      tell(); startTimer = setInterval(tell, 4000);
      note('a phone scanned the code; making your key');
    }
    send(fromPk, {
      type: 'pair_offer', token: S.pairing.token, weighted: true, plan: dkg.plan, signer: S.signer?.pk ?? null,
      group: { threshold: S.group.threshold, relays: S.group.relays, members: publicMembers().map(m => ({ ...m, pk: isDevice(m as Member) ? null : m.pk })) },
    });
  }

  /** The other server started making the key with your phone. */
  function onDkgStart(msg: any, from?: Member) {
    if (groupX || from?.role !== 'server') return;
    const plan = msg.plan as DkgPlan;
    if (dkg?.plan.session === plan?.session) return;
    // It must give us exactly our shares, and the threshold we were set up with.
    if (plan.threshold !== S.group.threshold || !sameSet(plan.holders.filter(h => h.pk === me.pk).map(h => h.idx), sharesOf(me))) return;
    dkg?.stop();
    dkg = new DkgRun(plan, me.pk!, send, onDkgDone);
    dkg.start();
    note(`making your key with ${from.name} and your phone`);
  }

  function onDkgDone(r: DkgResult) {
    for (const m of members) {
      const pts = sharesOf(m).map(idx => ({ idx, sharePub: r.members.find(x => x.idx === idx)!.sharePub }));
      m.sharePub = pts[0].sharePub;
      if (m.shares) m.shares = pts;
    }
    delete S.dkg;
    S.group.groupX = groupX = r.groupX;
    S.group.npub = nip19.npubEncode(r.groupX);
    S.self.shares = myShares = r.shares;
    myIdxs = myShares.map(s => s.idx);
    delete S.self.share;
    save();
    note(`your key was made: ${S.group.npub}`);
    if (earlyAck) { const a = earlyAck; earlyAck = null; onPairAck(a, offeredTo!); }
    setTimeout(() => void fetchArchive(), 1000);
  }

  // --- A device reported lost (COSIGN.md §7.2), and the refresh after it (§7.3) -------------
  //
  // One of your devices, with its own lock, reports another: from that moment no member
  // takes part in a round with it. The same message carries a refresh plan the reporting
  // device made, with it and a server as dealers; every remaining member moves to a new
  // epoch of the same key (refresh.ts), and the lost device's pieces stop combining.
  // A member that's offline gets its parts later, from the servers (mail).

  let refresh: RefreshRun | null = null;
  const pointOf = (idx: number) => members.flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]).find(p => p.idx === idx)?.sharePub;

  function onRemove(msg: any, by: Member) {
    const target = members.find(m => m.idx === Number(msg.idx));
    const fail = (reason: string) => send(by.pk, { type: 'remove_failed', id: msg.id, reason });
    if (!target || target.role === 'server') return fail('that isn’t one of your devices');
    if (!target.removed) {
      const why = mayStart(msg, by);
      if (why) return fail(why);
      // At once, and for good: a lost device mustn't take part in anything more.
      target.removed = now(); target.removedBy = by.idx;
      startGuard('remove', msg, by, { target: target.idx, wait: 0 });
      send(target.pk, { type: 'removed', by: by.name });
      toOther({ type: 'members', members });
      toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 });
      note(`${by.name} reported ${target.name} lost: it can't take part in anything now`);
    }
    if (msg.plan) startRefresh(msg.plan as RefreshPlan, by);
  }

  /** The plan must be the next epoch, dealt by the device that sent it and a server, over every remaining share. */
  function startRefresh(plan: RefreshPlan, by: Member) {
    if (refresh?.plan.epoch === plan?.epoch || Number(plan?.epoch) <= (S.epoch ?? 0)) return; // a repeat, or done already
    const want = members.filter(m => !m.removed).flatMap(m => sharesOf(m).map(idx => ({ idx, pk: m.pk })));
    const ok = plan && plan.epoch === (S.epoch ?? 0) + 1 && plan.threshold === S.group.threshold && Array.isArray(plan.dealers) && Array.isArray(plan.holders)
      && plan.dealers.includes(by.pk!) && plan.dealers.some(d => members.some(m => m.pk === d && m.role === 'server' && !m.removed))
      && plan.holders.length === want.length && want.every(w => plan.holders.some(h => h.idx === w.idx && h.pk === w.pk))
      && Array.isArray(plan.points) && want.every(w => plan.points.some(([i, p]) => i === w.idx && p === pointOf(w.idx)));
    if (!ok) return note(`refused a refresh from ${by.name}: its plan doesn't match the members`);
    if (plan.periodic === true && S.pending) return note('a periodic refresh is already waiting for its check');
    refresh?.stop();
    refresh = new RefreshRun(plan, me.pk!, myShares, send, plan.periodic === true ? onPending : onRefreshed);
    // Devices that aren't here now get the plan and our part when they're next seen; the
    // paper's part is kept, sealed to it, for whenever it's used (COSIGN.md §8.2).
    for (const [pk, part] of refresh.outgoing()) if (S.backup && pk === S.backup.pk) {
      keepPart({ from: me.pk!, content: sealTo(pk, part), epoch: plan.epoch });
      save(); toOther({ type: 'backup_sync', backup: S.backup });
    } else if (devices().some(d => d.pk === pk)) {
      holdMail(pk, { from: me.pk!, msg: { type: 'refresh_plan', plan }, epoch: plan.epoch });
      holdMail(pk, { from: me.pk!, msg: part, epoch: plan.epoch });
    }
    refresh.start();
    note(`refreshing your key (epoch ${plan.epoch})`);
  }

  // --- Silent periodic refresh (COSIGN.md §7.7) -------------------------------------------
  //
  // About every 30 days a device online asks for one (no lock: it takes nobody out). The
  // new shares are held as pending: signing goes on with the current ones until a device
  // has signed a check message with each server on the new ones and says commit. Each
  // server then swaps, and tells the others, who commit too. Pending that nobody commits
  // within 48 h is dropped, and the next attempt starts over. Nothing has a deadline on
  // the user: a committed epoch is only ever replaced by the next commit.

  const MIN_AGE = Number(process.env.COSIGN_REFRESH_MIN_AGE ?? 25 * 86400);
  const PENDING_DROP = Number(process.env.COSIGN_PENDING_DROP ?? 48 * 3600);
  S.epochAt ??= now();
  const periodicDue = () => !S.pending && !(refresh && !refresh.done) && now() - S.epochAt >= MIN_AGE;
  const checkMessage = (epoch: number) => F.bytesToHex(sha256(utf8ToBytes(`cosign-refresh:${groupX}:${epoch}`)));

  function onPending(r: RefreshResult) {
    S.pending = { epoch: r.epoch, id: refresh?.plan.id ?? null, shares: r.shares, points: r.points, dealers: refresh?.plan.dealers ?? [], at: now() };
    save();
    toDevices({ type: 'refresh_pending', epoch: r.epoch, id: S.pending.id });
    note(`your key's next epoch (${r.epoch}) is ready, waiting for your device's check`);
  }

  /** The group with the pending epoch's points, for the check round. */
  function pendingGroup(): Sig.Group {
    const at = new Map<number, string>(S.pending.points);
    return { groupX, threshold: S.group.threshold, members: members.filter(m => !m.removed).map(m => ({
      idx: m.idx, sharePub: at.get(sharesOf(m)[0]) ?? m.sharePub,
      ...(m.shares ? { shares: m.shares.map(x => ({ idx: x.idx, sharePub: at.get(x.idx) ?? x.sharePub })) } : {}),
    })) };
  }

  /** A device's check on the pending epoch: only the check message is ever signed with pending shares. */
  function onSignCheck(msg: any): object {
    const respond = (r: object) => ({ type: 'sign_check_res', id: msg.id, ...r });
    const p = S.pending;
    if (!p || Number(msg.epoch) !== p.epoch) return respond({ ok: false, reason: 'nothing pending for that epoch' });
    if (msg.msg !== checkMessage(p.epoch)) return respond({ ok: false, reason: 'only the check message' });
    const g = pendingGroup();
    const mine = Sig.commitAll(g, p.shares);
    const zs = Sig.partialAll(2, g, p.shares, mine.nonces, msg.msg, [...(msg.commits ?? []), ...mine.commits]);
    return respond({ ok: true, commits: mine.commits, zs });
  }

  /** Swap to the pending epoch (a device's commit, or another server's), once; tell the others. */
  function commitPending(epoch: number, by: Member, id?: unknown) {
    if (S.epoch === epoch && !S.pending) { if (isDevice(by)) send(by.pk, { type: 'refresh_committed', epoch, id: S.committedId ?? null }); return; }
    const p = S.pending;
    if (!p || p.epoch !== epoch || (id != null && p.id != null && id !== p.id)) return;
    delete S.pending;
    S.committedId = p.id;
    onRefreshed({ epoch: p.epoch, shares: p.shares, points: p.points }, p.dealers);
    const said = { type: 'refresh_committed', epoch, id: p.id };
    toOther(said);
    for (const d of devices()) { send(d.pk, said); holdMail(d.pk!, { from: me.pk!, msg: said, epoch }); }
    note(`your key moved to epoch ${epoch} (periodic), committed by ${by.name}`);
  }

  /** Each tick: pending that nobody committed in time is dropped; everyone stays where they were. */
  function dropStalePending() {
    if (S.pending && now() - S.pending.at > PENDING_DROP) { note(`dropped the uncommitted epoch ${S.pending.epoch}`); delete S.pending; refresh = null; save(); }
  }

  function onRefreshed(r: RefreshResult, dealersOf?: string[]) {
    const at = new Map(r.points);
    for (const m of members) {
      if (m.removed || !sharesOf(m).every(i => at.has(i))) continue;
      const pts = sharesOf(m).map(idx => ({ idx, sharePub: at.get(idx)! }));
      m.sharePub = pts[0].sharePub;
      if (m.shares) m.shares = pts;
    }
    S.self.shares = myShares = r.shares;
    myIdxs = myShares.map(s => s.idx);
    delete S.self.share;
    S.epoch = r.epoch;
    S.epochAt = now();
    // The paper's parts for this epoch are its dealers' only: drop any from a refresh that was started and never ran.
    const dealers = dealersOf ?? refresh?.plan.dealers;
    if (S.backup && dealers) {
      S.backup.dealers = { ...S.backup.dealers, [r.epoch]: dealers };
      S.backup.parts = S.backup.parts.filter((p: Piece) => p.epoch !== r.epoch || dealers.includes(p.from));
      toOther({ type: 'backup_sync', backup: S.backup });
    }
    save();
    toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 });
    note(`your key moved to epoch ${r.epoch}: the lost device's pieces no longer combine with anything`);
  }

  // --- Guarded actions (COSIGN.md §7.2) -------------------------------------------------
  //
  // Everything that takes something away goes through here, so the guards can't drift
  // apart: reporting a device lost ('remove', at once), taking the account out ('take_out':
  // this server's share to the device that asked, after WAIT; or, with the paper,
  // announced before the phone shows the key) and removing the servers' pieces ('forget':
  // this server stops at once, and deletes them for real after WAIT). Each needs the lock
  // of a live device. Every device is told (and woken), and a waiting one can be
  // cancelled by any of them, with its lock. Devices send each to every server, with one id.

  interface Guard {
    id: string; kind: 'remove' | 'take_out' | 'forget' | 'add'; by: number; byName: string; target?: number;
    at: number; until: number; paper?: boolean;
    cancelled?: number; cancelledBy?: string; done?: number;
  }
  S.guards ??= [];
  const guards = () => S.guards as Guard[];
  const guardById = (id: unknown) => guards().find(g => g.id === String(id));
  const active = (g: Guard) => !g.done && !g.cancelled;
  /** Why `by` can't start one now, or null. */
  function mayStart(msg: any, by: Member): string | null {
    if (msg.lock !== true) return 'this needs your device’s lock';
    if (!isDevice(by)) return 'this device can’t do that now';
    if (!/^[0-9a-f]{8,64}$/.test(String(msg.id ?? ''))) return 'damaged request';
    return null;
  }
  const guardView = (g: Guard) => ({
    id: g.id, kind: g.kind, by: g.byName, target: g.target != null ? members.find(m => m.idx === g.target)?.name ?? null : null,
    at: g.at, until: g.until, paper: !!g.paper,
    state: g.done ? 'done' : g.cancelled ? 'cancelled' : 'waiting',
  });
  /** Every device hears of every change to one, and is woken for a new one. */
  function tellGuard(g: Guard, wake = false) {
    toDevices({ type: 'guard', ...guardView(g) });
    if (wake) for (const d of devices()) if (d.push && d.idx !== g.by) void io.push(d.push);
  }
  function startGuard(kind: Guard['kind'], msg: any, by: Member, o: { target?: number; wait: number; paper?: boolean }): Guard {
    const old = guardById(msg.id);
    if (old) return old; // the same request again, or by way of another server
    const g: Guard = { id: String(msg.id), kind, by: by.idx, byName: by.name, at: now(), until: now() + o.wait, ...(o.target != null ? { target: o.target } : {}), ...(o.paper ? { paper: true } : {}) };
    if (o.wait === 0) g.done = now();
    guards().push(g);
    S.guards = guards().slice(-30);
    save();
    tellGuard(g, true);
    return g;
  }

  /** "Take my account out of Cosign". With the paper the device needs nothing from us but to be heard. */
  function onTakeOut(msg: any, by: Member) {
    const why = mayStart(msg, by);
    if (why) return send(by.pk, { type: 'take_out_failed', id: msg.id, reason: why });
    const g = startGuard('take_out', msg, by, msg.paper === true ? { wait: 0, paper: true } : { wait: WAIT });
    if (g.by !== by.idx) return;
    if (g.paper) {
      // Bound to this request: the device shows the key only after a server has said so.
      send(by.pk, { type: 'noted', id: g.id, kind: 'take_out' });
      note(`${by.name} took your account out of Cosign, with your paper backup`);
    } else {
      send(by.pk, { type: 'guard', ...guardView(g) });
      note(`${by.name} asked to take your account out of Cosign; any of your devices can stop it before ${new Date(g.until * 1000).toISOString()}`);
    }
  }

  /** "Remove my servers' pieces": stop now, delete for real after the wait. */
  function onForget(msg: any, by: Member) {
    const why = mayStart(msg, by);
    if (why) return send(by.pk, { type: 'forget_failed', id: msg.id, reason: why });
    const g = startGuard('forget', msg, by, { wait: WAIT });
    send(by.pk, { type: 'guard', ...guardView(g) });
    note(`${by.name} asked to remove this server's pieces of your account: stopped now, deleted after ${new Date(g.until * 1000).toISOString()} unless a device cancels`);
  }

  /** Stopped while its pieces wait to be deleted: no signing, no decrypting. */
  const forgetting = () => guards().some(g => g.kind === 'forget' && !g.cancelled);

  function cancelGuard(msg: any, from: Member) {
    const g = guardById(msg.id);
    if (!g || msg.lock !== true || !active(g)) return;
    g.cancelled = now(); g.cancelledBy = from.name;
    save();
    tellGuard(g);
    if (g.kind === 'add') { delete (S.pendingAdds ?? {})[g.id]; save(); }
    note(`${from.name} stopped ${g.kind === 'take_out' ? 'taking your account out' : g.kind === 'add' ? 'adding that' : 'removing your servers’ pieces'}`);
  }

  /** Each tick: a wait that ran out and wasn't cancelled completes. */
  function finishGuards() {
    for (const g of guards()) {
      if (!active(g) || now() < g.until) continue;
      const by = members.find(m => m.idx === g.by);
      if (g.kind === 'take_out') {
        if (!by || !isDevice(by)) continue;
        g.done = now(); save();
        send(by.pk, { type: 'released', id: g.id, shares: myShares, group: { groupX, threshold: S.group.threshold, members: publicMembers() } });
        tellGuard(g);
        note(`released this server's share to ${by.name}: your account is out of Cosign there`);
      } else if (g.kind === 'add') {
        const held = (S.pendingAdds ?? {})[g.id];
        const asker = held ? members.find(m => m.idx === held.by) : undefined;
        g.done = now();
        delete (S.pendingAdds ?? {})[g.id];
        save();
        tellGuard(g);
        if (!asker || !mayAct(asker)) { note(`the add ${g.id} was let go: ${asker ? asker.name + ' can’t act for you now' : 'whoever asked is gone'}`); continue; }
        note(`the wait ended: adding ${held.msg.backup === true ? 'a paper backup' : 'a server'} for ${asker.name}`);
        void addDevice(held.msg, asker, true).catch(err => {
          note(`couldn’t add it after the wait: ${err.message}`);
          send(asker.pk, { type: 'add_failed', id: g.id, reason: err.message });
        });
      } else if (g.kind === 'forget') {
        g.done = now(); save();
        tellGuard(g);
        note(`deleting this server's pieces of your account, as ${g.byName} asked`);
        void io.forget?.();
      }
    }
  }

  // Mail: what a member that wasn't here missed, kept on the servers until it's back.
  // Sealed by its sender (`content`, NIP-44 to the member) or sent by this server (`msg`).
  function holdMail(to: string, item: { from: string; content?: string; msg?: object; epoch: number }) {
    S.mail ??= {};
    const box = (S.mail[to] ??= []);
    if (box.length < 50) box.push({ ...item, at: now() });
    save();
  }
  const mailSent = new Map<string, number>();
  function deliverMail(m: Member) {
    const box = m.pk ? S.mail?.[m.pk] : null;
    if (!box?.length || io.now() - (mailSent.get(m.pk!) ?? 0) < 30_000) return;
    mailSent.set(m.pk!, io.now());
    S.mail[m.pk!] = box.filter((x: any) => now() - x.at < 30 * 86400);
    for (const x of S.mail[m.pk!]) send(m.pk, x.msg && x.from === me.pk ? x.msg : { type: 'mail', from: x.from, content: x.content });
  }

  // --- Joining a key that exists, as a server (enroll how:'repair') ---------------------------

  const joinSigmas: [number, number, string][] = [];
  let joinWelcome: any = null;
  function onJoinPiece(msg: any, from: Member) {
    if (msg.type === 'welcome' && from.role === 'server') joinWelcome = { ...msg, from: from.pk };
    joinSigmas.push(...(msg.sigmas ?? []));
    const w = joinWelcome;
    const k = S.joining.k;
    if (!w || !(w.ks ?? []).includes(k)) return;
    const mine = joinSigmas.filter(x => x[0] === k).map(x => x[2]);
    if (mine.length < (w.helpers?.length ?? 99)) return;
    let secret: string;
    try { secret = W.repairStep3(JSON.stringify({ groupX, threshold: S.group.threshold, members: Sig.sharePoints(S.group).filter(p => p.sharePub) }), mine, k); }
    catch (e: any) { return note(`couldn't make this server's share: ${e.message}`); }
    const pub = W.sharePub(secret);
    me.sharePub = pub;
    S.self.shares = myShares = [{ idx: k, secret }];
    myIdxs = [k];
    delete S.joining;
    save();
    send(w.from, { type: 'joined', id: w.id, sharePubs: [[k, pub]], sharePub: pub });
    note(`joined ${S.group.npub} as a server`);
    // Once the others have us, tell them we don't answer sites (if we don't).
    setTimeout(() => toOther({ type: 'members', members }), 4000);
  }

  // --- The paper backup (COSIGN.md §8) ---------------------------------------------------
  //
  // A key printed on paper, with share indices of its own in the member list, whose
  // shares nobody online holds. Making it is a repair like adding a device, except that
  // each helper seals its pieces (sigmas) to the paper's key and every server keeps them,
  // and each refresh's part for the paper is kept the same way. Restoring: a new phone
  // reads the paper, fetches the pieces, adds them up, and asks to recover; after a wait
  // every server enforces and any device can cancel, the paper's shares are that phone's.

  interface Piece { from: string; content: string; epoch: number }
  /** How long recovery waits. Three days; shorter for tests. */
  const WAIT = Number(process.env.COSIGN_RECOVERY_WAIT ?? 3 * 86400);
  /**
   * How long a paper backup or a new server waits before its pieces are made (COSIGN.md
   * §7.4). Short: it is there so every device hears of it and any one of them can stop it,
   * not to make the user wait for something they asked for.
   */
  const ADD_WAIT = Number(process.env.COSIGN_ADD_WAIT ?? 3600);
  // The host's age-out (stale()), in seconds: only for accounts that never finished being set up.
  const UNFINISHED_AFTER = Number(process.env.COSIGN_UNFINISHED_AFTER ?? 86400);
  const sealTo = (pk: string, body: object) => nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(F.hexToBytes(S.self.sk), pk));

  /** A helper's pieces for a paper being made: ours and the vouching device's. With both, it's a member. */
  function backupPiece(a: Adding, id: string, p: Piece) {
    a.pieces ??= [];
    if (!a.pieces.some(x => x.from === p.from)) a.pieces.push(p);
    if (a.pieces.length < 2 + a.extras.length) return;
    adding.delete(id);
    // A new paper replaces the old one.
    for (const m of members) if (m.role === 'backup' && !m.removed) m.removed = now();
    const shares = a.ks.map(k => ({ idx: k, sharePub: Sig.sharePubAt(S.group, k) }));
    members.push({ idx: a.ks[0], name: a.name, role: 'backup', pk: a.pk, sharePub: shares[0].sharePub, push: null, shares });
    // The points as they are now: the pieces add up to shares of this epoch, and later refreshes' parts move them on.
    const points = members.filter(m => !m.removed).flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]).map(p => [p.idx, p.sharePub]);
    S.backup = { pk: a.pk, ks: a.ks, epoch: S.epoch ?? 0, helpers: a.helpers, points, pieces: a.pieces, parts: [] };
    save();
    toOther({ type: 'members', members });
    toOther({ type: 'backup_sync', backup: S.backup });
    toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 });
    send(a.by.pk, { type: 'backup_made', id, pieces: a.pieces });
    note(`${a.by.name} made a paper backup (${a.ks.length} shares)`);
  }

  /**
   * Keep one refresh's part for the paper (one per dealer and epoch, the latest), but only
   * for a refresh still to come or the one just done by its own dealers: a part from a
   * refresh that never ran would make the paper's shares wrong.
   */
  function keepPart(p: Piece & { epoch: number }): boolean {
    const b = S.backup;
    const e = S.epoch ?? 0;
    if (!b || !(p.epoch >= e) || p.epoch < 1) return false;
    if (p.epoch === e && !(b.dealers?.[e] ?? []).includes(p.from)) return false;
    b.parts = b.parts.filter((x: Piece) => !(x.from === p.from && x.epoch === p.epoch));
    b.parts.push(p);
    return true;
  }
  /** The parts that count: every epoch reached since the paper was made, from that epoch's dealers. */
  const usableParts = () => (S.backup?.parts ?? []).filter((p: Piece) => p.epoch <= (S.epoch ?? 0) && (!S.backup.dealers?.[p.epoch] || S.backup.dealers[p.epoch].includes(p.from)));

  function mergeBackup(b: any) {
    if (!b?.pk) return;
    if (!S.backup || S.backup.pk !== b.pk) S.backup = { ...b, pieces: [], parts: [] };
    for (const p of b.pieces ?? []) if (!S.backup.pieces.some((x: Piece) => x.from === p.from)) S.backup.pieces.push(p);
    S.backup.dealers = { ...b.dealers, ...S.backup.dealers };
    for (const p of b.parts ?? []) if (!S.backup.parts.some((x: Piece) => x.from === p.from && x.epoch === p.epoch)) S.backup.parts.push(p);
    save();
  }

  /** To the paper's own key: everything needed to rebuild its shares, all sealed to it. */
  function sendBackup(b: Member) {
    if (!S.backup || S.backup.pk !== b.pk) return;
    send(b.pk, {
      type: 'backup', ...S.backup, parts: usableParts(), epochNow: S.epoch ?? 0, recovery: S.recovery ?? null, signer: S.signer?.pk ?? null,
      group: { groupX, npub: S.group.npub, threshold: S.group.threshold, relays: S.group.relays, members: publicMembers() },
    });
  }

  function startRecovery(msg: any, b: Member) {
    const pk = String(msg.pk ?? '');
    if (!/^[0-9a-f]{64}$/.test(pk) || members.some(m => m.pk === pk)) return;
    if (!S.recovery || S.recovery.pk !== pk) {
      S.recovery = { pk, name: String(msg.name ?? 'A new phone').slice(0, 40), at: now(), until: now() + WAIT };
      save();
      toDevices({ type: 'recovery', name: S.recovery.name, until: S.recovery.until });
      for (const d of devices()) if (d.push) void io.push(d.push);
      note(`your paper backup is being used for ${S.recovery.name}; any of your devices can cancel it before ${new Date(S.recovery.until * 1000).toISOString()}`);
    }
    send(b.pk, { type: 'recovering', until: S.recovery.until });
  }

  /** The wait is over at this server: the paper's shares are that phone's now. */
  function finishRecovery(b: Member) {
    const r = S.recovery;
    if (!r || now() < r.until) return send(b.pk, { type: 'recovering', until: r?.until ?? null });
    Object.assign(b, { role: 'device', pk: r.pk, name: r.name });
    S.recovery = null; S.backup = null;
    lastSeen.set(b.idx, io.now());
    save();
    toOther({ type: 'members', members });
    toDevices({ type: 'members', members: publicMembers(), epoch: S.epoch ?? 0 });
    send(r.pk, { type: 'recovered', idx: b.idx });
    note(`${r.name} is one of your devices now, from your paper backup. Make a new paper backup, and report your old phone lost if you've lost it.`);
  }

  function cancelRecovery(by: Member) {
    if (!S.recovery) return;
    const r = S.recovery;
    S.recovery = null; save();
    toDevices({ type: 'recovery_cancelled', by: by.name });
    if (S.backup) send(S.backup.pk, { type: 'recovery_cancelled', by: by.name });
    note(`${by.name} cancelled using your paper backup for ${r.name}`);
  }

  // --- Liveness ----------------------------------------------------------------

  const pingAll = () => { for (const m of members) if (m.pk && m.idx !== me.idx) send(m.pk, { type: 'ping', idx: me.idx, ts: io.now() }); };

  // Pick up what's already published under your key, so the first change is judged
  // against something.
  let archivedAt = 0;
  async function fetchArchive() {
    archivedAt = io.now();
    if (!groupX) return;
    try {
      const events = await io.query([...S.group.relays, 'wss://relay.damus.io'], { authors: [groupX], kinds: [...ARCHIVED] }, 6000);
      let n = 0;
      for (const e of events) if (archive.record(e)) n++;
      if (n) note(`archived ${n} version${n === 1 ? '' : 's'} already on relays`);
      checkFuture();
    } catch { /* relays come and go */ }
  }

  /** Once, when the host starts serving this group. */
  function start() {
    // Without a signer key this server never answers sites; the others must know not to wait for it.
    if (!S.signer && !me.noSites) { me.noSites = true; save(); if (!S.joining) setTimeout(() => toOther({ type: 'members', members }), 4000); }
    // Enrolled to make a key that doesn't exist yet (core/enroll.ts): run the plan with the others.
    if (S.dkg && !groupX) { dkg = new DkgRun(S.dkg, me.pk!, send, onDkgDone); dkg.start(); }
    // Sites that came by nostrconnect may be listening on relays of their own.
    void io.listen((S.sites as Site[]).filter(s => !s.revoked).flatMap(s => s.relays ?? []), 0);
    setTimeout(pingAll, 2000);
    setTimeout(() => void fetchArchive(), 3000);
    setTimeout(syncTo, 4000);
    note('started');
  }

  /** Every 10 s, from the host: pings, forgetting old answers, and the archive every 15 min. */
  function tick() {
    pingAll();
    finishGuards();
    dropStalePending();
    for (const [k, v] of given) if (io.now() - v.at > 120_000) given.delete(k);
    for (const [k, v] of answers) if (io.now() - v.at > 180_000) answers.delete(k);
    if (io.now() - archivedAt > 15 * 60_000) void fetchArchive();
  }

  // --- Status page -------------------------------------------------------------

  const ago = (t: number) => { const s = now() - t; return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
  const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
  function status() {
    return {
      me: me.name, started: startedAt, npub: S.group.npub, coordinating: coordinating(), signedToday: signed.day === new Date().toDateString() ? signed.n : 0,
      members: members.map(m => ({ name: esc(m.name), online: !!m.pk && online(m), paired: !!m.pk, self: m.idx === me.idx })),
      pairing: !!S.pairing,
      sites: (S.sites as Site[]).filter(s => !s.revoked).sort((a, b) => b.lastUsed - a.lastUsed)
        .map(s => ({ pk: s.pk, origin: esc(siteName(s.origin)), via: esc(s.via ?? (s.parent ? 'Connected' : 'Connected by code')), lastUsed: ago(s.lastUsed) })),
      changes: (S.changes as Change[]).slice(0, 15).map(c => ({ text: esc(c.text), by: esc(c.by), when: ago(c.at), held: !!c.held, undone: !!c.undone })),
      activity: activity.map(a => ({ ts: a.ts, text: esc(a.text) })),
    };
  }

  /** The relays this group's traffic goes to: its own, and any a site or a new device listens on. */
  const relays = () => [...new Set([...S.group.relays, ...(S.sites as Site[]).filter(s => !s.revoked).flatMap(s => s.relays ?? [])].map(normRelay))];

  return {
    /** This membership's key: member messages for it are addressed here. */
    pk: me.pk!,
    /** The key sites talk NIP-46 to, if this group has one. */
    signerPk: (S.signer?.pk ?? null) as string | null,
    name: me.name,
    /** The group's key (read when asked: a key made by DKG arrives after start). */
    get groupX() { return groupX; },
    state: S,
    relays, start, tick, onEvent, status, pairingUri,
    /**
     * Why a host should let this account go, or null: only one a stranger enrolled that
     * never finished being set up (a day on). A finished account is never let go for
     * being idle: someone away for a month must find it as they left it.
     */
    stale(): string | null {
      if (!S.enrolled) return null;
      const finished = !!groupX && !S.dkg && !S.joining && devices().length > 0;
      return !finished && now() - S.enrolled.at > UNFINISHED_AFTER ? 'it never finished being set up' : null;
    },
    /** Delete everything for it here, for real (io.forget). */
    forget: () => io.forget?.(),
    /**
     * Whoever runs this server stopped serving this account: its devices are told, so the
     * app can say so and offer another server, and then everything here goes. Nothing is
     * held back — a server can always stop; the account still has its other servers (and
     * its paper backup), and the page says so before anyone presses it.
     */
    leave: () => {
      toDevices({ type: 'server_left', pk: me.pk, name: me.name });
      note('whoever runs this server stopped serving this account; deleting its pieces');
      setTimeout(() => void io.forget?.(), 2000);
    },
    revoke: (pk: string, where: string) => revoke(pk, where),
  };
}

export type Group = ReturnType<typeof openGroup>;
