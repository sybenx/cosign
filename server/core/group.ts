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

import { createCipheriv, createDecipheriv, randomBytes as nodeRandom } from 'node:crypto';
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
import { nip19 } from 'nostr-tools';

// --- State -------------------------------------------------------------------

/** A member: one of the two servers, your phone, or another device of yours (a tablet, a second phone, the extension). */
export interface Member { idx: number; name: string; role: 'server' | 'phone' | 'device'; pk: string | null; sharePub: string; push?: string | null; removed?: number;
  /** Who reported it lost (a member idx), and whether it answered "This wasn't me". */
  removedBy?: number; contested?: number;
  /** In a weighted key a member holds several shares (a device 3, a server 1). `idx`/`sharePub` are the first. */
  shares?: { idx: number; sharePub: string }[] }
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
  const others = () => { const o = other(); return o ? [o] : []; };
  /** The phone your server's code added first: pairing only. Everything else is any device. */
  const phone = () => members.find(m => m.role === 'phone')!;
  const isDevice = (m?: Member) => !!m && (m.role === 'phone' || m.role === 'device') && !m.removed;
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
  const note = (text: string) => {
    activity.unshift({ ts: io.now(), text });
    activity.length = Math.min(activity.length, 40);
    io.note(text);
  };

  // --- Relays ------------------------------------------------------------------

  const send = (toPk: string | null | undefined, msg: object) => { if (toPk) for (const e of sealParts(S.self.sk, toPk, msg)) io.publish(e); };
  const parts = new Parts();
  const toOther = (msg: object) => send(other()?.pk, msg);
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

  function onEvent(e: Event) {
    const age = now() - e.created_at;
    if (age > 120) return;
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
    // Making the key: your phone isn't a member yet, so these come before that check.
    if (msg.type === 'dkg1' || msg.type === 'dkg2') return dkg?.take(msg, fromPk);
    if (msg.type === 'dkg_start') return onDkgStart(msg, from);
    if (!from) return;
    deliverMail(from);
    // A device reported lost can still say it wasn't.
    if (from.removed && msg.type === 'not_me') return onNotMe(msg, from);

    const fromPhone = isDevice(from); // any of your devices
    switch (msg.type) {
      case 'ping': return;
      case 'asking': { if (fromPhone) waitLonger(String(msg.id)); return; }
      case 'sign_req': return answerOnce(from, msg.id, () => onSignReq(msg, from));
      // An app on your phone asked it to sign (Android signer): the phone runs the round.
      case 'cosign_req': return answerOnce(from, msg.id, () => onCosignReq(msg, from));
      case 'phone_signed': { if (fromPhone) onPhoneSigned(msg); return; }
      case 'app_grant': { if (fromPhone) grantApp(msg); return; }
      case 'add_device': { if (fromPhone) addDevice(msg, from).catch(err => send(from.pk, { type: 'add_failed', id: msg.id, reason: err.message })); return; }
      case 'repair_delta': { if (fromPhone) onRepairDelta(msg, from); return; }
      case 'members': { if (!fromPhone) mergeMembers(msg.members ?? []); return; }
      case 'remove_member': { if (fromPhone) onRemove(msg, from); return; }
      case 'refresh_part': { refresh?.take(msg, fromPk); return; }
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
  const firstServer = () => members.filter(m => m.role === 'server' && !m.removed).sort((a, b) => a.idx - b.idx)[0];
  const coordinating = () => firstServer().idx === me.idx || (io.now() - startedAt > 30_000 && !online(firstServer()));
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
        case 'nip44_encrypt': return answer({ result: nip44.v2.encrypt(req.params[1], await groupNip44Key(req.params[0])) });
        case 'nip44_decrypt': return answer({ result: nip44.v2.decrypt(req.params[1], await groupNip44Key(req.params[0])) });
        case 'nip04_encrypt': return answer({ result: await groupNip04(req.params[0], req.params[1], false) });
        case 'nip04_decrypt': return answer({ result: await groupNip04(req.params[0], req.params[1], true) });
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
    const relays = [...new Set(u.searchParams.getAll('relay').filter(r => /^wss?:\/\//.test(r)).map(normRelay))];
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
      // Whichever math the partner used (it may not be updated yet), finish the round in it.
      const scheme = Sig.schemeOfAll(S.group, id, commits, theirZs);
      if (!scheme) return { m, reason: 'bad partial' };
      io.debug?.(`${m.name} signed with ${scheme === 2 ? 'FROST (RFC 9591)' : 'the earlier math'}`);
      const zs = Sig.partialAll(scheme, S.group, myShares, mine.nonces, id, commits);
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
        ? (other()?.pk && enough(other()!) ? 'Neither your phone nor your backup server answered. Is Cosign running on your phone?' : 'Your phone didn’t answer. Is Cosign running on it?')
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
    return respond(cosign(msg, msg.frost === 2 ? 2 : 1));
  }

  /** Our commitments and partials for a round someone else runs, over its commitments and ours. */
  function cosign(msg: any, scheme: Sig.Scheme) {
    const theirs: Sig.Commit[] = msg.commits ?? [msg.commit];
    const mine = Sig.commitAll(S.group, myShares);
    const zs = Sig.partialAll(scheme, S.group, myShares, mine.nonces, msg.msg, [...theirs, ...mine.commits]);
    // The first ones again the earlier way, for a coordinator that predates several shares.
    return { ok: true, commits: mine.commits, zs, commit: mine.commits[0], z: zs[0][1] };
  }

  function onEcdhReq(msg: any, from: Member): object {
    const respond = (r: object) => ({ type: 'ecdh_res', id: msg.id, ...r });
    if (!Array.isArray(msg.participants) || !sameSet(msg.participants, [...sharesOf(from), ...myIdxs])) return respond({ ok: false, reason: 'bad request' });
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
    if (s && !s.revoked) return pushState();
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
    if (decrypt) {
      const [ct, iv] = text.split('?iv=');
      const d = createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'base64'));
      return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
    }
    const iv = nodeRandom(16);
    const c = createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([c.update(text, 'utf8'), c.final()]).toString('base64') + '?iv=' + iv.toString('base64');
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

  interface Adding { ks: number[]; helpers: number[]; pk: string; name: string; by: Member; local: Map<string, string[]>; at: number }
  const adding = new Map<string, Adding>();
  /** Deltas waiting to be summed, by new share and the helper share they're for. */
  const slot = (k: number, j: number) => `${k}:${j}`;

  async function addDevice(msg: any, by: Member) {
    const pk = String(msg.pk ?? '');
    if (!/^[0-9a-f]{64}$/.test(pk)) throw new Error('that code is damaged');
    if (members.some(m => m.pk === pk && !m.removed)) throw new Error('that device is already one of yours');
    // One device vouching is instant only with its own lock, asked for right then.
    if (msg.lock !== true) throw new Error('adding a device needs this phone’s lock');
    // The new device gets as many shares as the one vouching for it (3 in a weighted key).
    const next = Math.max(...members.flatMap(sharesOf)) + 1;
    const ks = sharesOf(by).map((_, i) => next + i);
    const helpers = [...sharesOf(by), ...myIdxs].sort((a, b) => a - b);
    if (helpers.length < S.group.threshold) throw new Error('not enough shares to vouch with');
    // Each of our shares splits its part of f(k) into a delta per helper share: ours stay
    // here, the vouching device's go to it.
    const local = new Map<string, string[]>();
    const toBy: [number, number, number, string][] = [];
    for (const k of ks) for (const s of myShares) {
      for (const [j, d] of Sig.repairStep1(S.group, s.idx, s.secret, helpers, k)) {
        if (myIdxs.includes(j)) local.set(slot(k, j), [...local.get(slot(k, j)) ?? [], d]);
        else toBy.push([k, s.idx, j, d]);
      }
    }
    adding.set(String(msg.id), { ks, helpers, pk, name: String(msg.name ?? 'A device').slice(0, 40), by, local, at: io.now() });
    const relays = (msg.relays ?? []).filter((r: unknown) => typeof r === 'string' && /^wss?:\/\//.test(r));
    if (relays.length) await io.listen(relays);
    // `k`/`delta`: the earlier one-share form, for an app not updated yet.
    const one = ks.length === 1 && myShares.length === 1 ? { k: ks[0], delta: toBy[0][3] } : {};
    send(by.pk, { type: 'repair', id: msg.id, ks, helpers, deltas: toBy, pk, ...one });
    note(`${by.name} is adding ${msg.name ?? 'a device'}`);
  }

  function onRepairDelta(msg: any, from: Member) {
    const a = adding.get(String(msg.id));
    if (!a || a.by.idx !== from.idx || io.now() - a.at > 120_000) return;
    const theirs: [number, number, number, string][] = msg.deltas ?? [[a.ks[0], from.idx, myIdxs[0], String(msg.delta)]];
    const sigmas: [number, number, string][] = [];
    for (const k of a.ks) for (const j of myIdxs) {
      const ds = [...a.local.get(slot(k, j)) ?? [], ...theirs.filter(t => t[0] === k && t[2] === j && sharesOf(from).includes(t[1])).map(t => String(t[3]))];
      if (ds.length !== a.helpers.length) return note(`${a.name}: pieces missing; not added`);
      sigmas.push([k, j, Sig.repairStep2(ds)]);
    }
    const one = sigmas.length === 1 ? { k: a.ks[0], sigma: sigmas[0][2] } : {};
    send(a.pk, {
      type: 'welcome', id: msg.id, ks: a.ks, helpers: a.helpers, sigmas, name: a.name, signer: S.signer?.pk ?? null, ...one,
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
    members.push({ idx: a.ks[0], name: a.name, role: 'device', pk: a.pk, sharePub: shares[0].sharePub, push: null, ...(shares.length > 1 ? { shares } : {}) });
    lastSeen.set(a.ks[0], io.now());
    save();
    toOther({ type: 'members', members });
    toDevices({ type: 'members', members: publicMembers() });
    note(`${a.name} joined, vouched for by ${a.by.name}`);
  }

  const publicMembers = () => members.filter(m => !m.removed).map(m => ({ idx: m.idx, name: m.name, role: m.role, pk: m.pk, sharePub: m.sharePub, ...(m.shares ? { shares: m.shares } : {}) }));

  /** The other server's member list: take anything new, and every removal. */
  function mergeMembers(list: Member[]) {
    let dirty = false;
    for (const m of list) {
      const mine = members.find(x => x.idx === m.idx);
      if (!mine) { members.push({ ...m, push: m.push ?? null }); dirty = true; continue; }
      if (m.removed && !mine.removed) { mine.removed = m.removed; dirty = true; }
      if (!mine.pk && m.pk) { mine.pk = m.pk; dirty = true; }
    }
    if (dirty) { save(); toDevices({ type: 'members', members: publicMembers() }); }
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
    if (msg.lock !== true) return fail('reporting a device needs this phone’s lock');
    if (!target || target.role === 'server') return fail('that isn’t one of your devices');
    if (!target.removed) {
      target.removed = now(); target.removedBy = by.idx;
      save();
      send(target.pk, { type: 'removed', by: by.name });
      toOther({ type: 'members', members });
      toDevices({ type: 'members', members: publicMembers() });
      note(`${by.name} reported ${target.name} lost: it can't take part in anything now`);
    }
    if (msg.plan) startRefresh(msg.plan as RefreshPlan, by);
  }

  /** The plan must be the next epoch, dealt by the device that sent it and a server, over every remaining share. */
  function startRefresh(plan: RefreshPlan, by: Member) {
    if (refresh?.plan.epoch === plan?.epoch) return;
    const want = members.filter(m => !m.removed).flatMap(m => sharesOf(m).map(idx => ({ idx, pk: m.pk })));
    const ok = plan && plan.epoch === (S.epoch ?? 0) + 1 && plan.threshold === S.group.threshold && Array.isArray(plan.dealers) && Array.isArray(plan.holders)
      && plan.dealers.includes(by.pk!) && plan.dealers.some(d => members.some(m => m.pk === d && m.role === 'server' && !m.removed))
      && plan.holders.length === want.length && want.every(w => plan.holders.some(h => h.idx === w.idx && h.pk === w.pk))
      && Array.isArray(plan.points) && want.every(w => plan.points.some(([i, p]) => i === w.idx && p === pointOf(w.idx)));
    if (!ok) return note(`refused a refresh from ${by.name}: its plan doesn't match the members`);
    refresh?.stop();
    refresh = new RefreshRun(plan, me.pk!, myShares, send, onRefreshed);
    // Devices that aren't here now get the plan and our part when they're next seen.
    for (const [pk, part] of refresh.outgoing()) if (devices().some(d => d.pk === pk)) {
      holdMail(pk, { from: me.pk!, msg: { type: 'refresh_plan', plan }, epoch: plan.epoch });
      holdMail(pk, { from: me.pk!, msg: part, epoch: plan.epoch });
    }
    refresh.start();
    note(`refreshing your key (epoch ${plan.epoch})`);
  }

  function onRefreshed(r: RefreshResult) {
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
    save();
    toDevices({ type: 'members', members: publicMembers() });
    note(`your key moved to epoch ${r.epoch}: the lost device's pieces no longer combine with anything`);
  }

  /** The device reported lost says it's the user's: block the one that reported it too, until it's settled. */
  function onNotMe(msg: any, from: Member) {
    if (msg.lock !== true || from.contested) return;
    from.contested = now();
    const by = members.find(m => m.idx === from.removedBy);
    if (by && !by.removed) { by.removed = now(); by.contested = now(); }
    save();
    toOther({ type: 'members', members });
    toDevices({ type: 'contested', removed: from.name, by: by?.name ?? 'a device' });
    note(`${from.name} says it wasn't lost: ${by?.name ?? 'the device that reported it'} is blocked too, until another of your devices or your paper backup settles it`);
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
    for (const [k, v] of given) if (io.now() - v.at > 120_000) given.delete(k);
    for (const [k, v] of answers) if (io.now() - v.at > 180_000) answers.delete(k);
    if (io.now() - archivedAt > 15 * 60_000) void fetchArchive();
  }

  // --- Status page -------------------------------------------------------------

  const ago = (t: number) => { const s = now() - t; return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
  const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
  function status() {
    return {
      me: me.name, started: startedAt, npub: S.group.npub, coordinating: coordinating(),
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
    revoke: (pk: string, where: string) => revoke(pk, where),
  };
}

export type Group = ReturnType<typeof openGroup>;
