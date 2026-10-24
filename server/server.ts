// A cosign server: one share of your key, and the signer your sites talk to.
//
//   node server.ts data/a
//
// Sites connect with a one-time ticket your phone hands them over QRST (or, for a site
// that only knows NIP-46, by your phone scanning its nostrconnect:// code), then ask
// for signatures over relays. Almost everything signs at once, with the other server. A
// change that would destroy something (most of your follows, your profile, your relay
// list…) waits for your phone instead. Server A answers sites; server B answers only
// while A has been silent for 30 s.

import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes as nodeRandom } from 'node:crypto';
import { getEventHash, finalizeEvent, verifyEvent, type Event } from 'nostr-tools/pure';
import { SimplePool } from 'nostr-tools/pool';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import QRCode from 'qrcode';
import * as F from './frost.ts';
import * as Sig from './sign.ts';
import { Pool, sealParts, openFrom, Parts, normRelay, dial, KIND_MEMBER, KIND_NIP46 } from './net.ts';
import { ARCHIVED, assess, keyOf, kindName, type Ev } from './policy.ts';
import { Archive } from './archive.ts';
import { History, type Entry } from './history.ts';
import { checkClock } from './clock.ts';

// --- State -------------------------------------------------------------------

interface Member { idx: number; name: string; role: 'server' | 'phone'; pk: string | null; sharePub: string; push?: string | null }
/**
 * A grant. `parent` is set for one a connected site added under itself (the browser
 * extension adds one per website it signs for); `via` names what connected it.
 */
interface Site { pk: string; origin: string; added: number; lastUsed: number; revoked?: number; relays?: string[]; parent?: string; via?: string }
interface Ticket { t: string; origin: string; expires: number; used?: boolean }
interface Change { id: string; key: string; kind: number; at: number; text: string; by: string; held?: boolean; undone?: boolean }

const dir = process.argv[2];
if (!dir) { console.error('usage: node server.ts data/a'); process.exit(1); }
const file = join(dir, 'state.json');
const S = JSON.parse(readFileSync(file, 'utf8'));
S.sites ??= []; S.tickets ??= []; S.changes ??= [];
const save = () => { writeFileSync(file + '.tmp', JSON.stringify(S, null, 2), { mode: 0o600 }); renameSync(file + '.tmp', file); };
const archive = new Archive(join(dir, 'archive.json'));
const history = new History(join(dir, 'history.jsonl'), join(dir, 'saved.jsonl'));

const members: Member[] = S.group.members;
const me = members.find(m => m.idx === S.self.idx)!;
const other = () => members.find(m => m.role === 'server' && m.idx !== me.idx)!;
const phone = () => members.find(m => m.role === 'phone')!;
const byPk = (pk: string) => members.find(m => m.pk === pk);
const groupX: string = S.group.groupX;
const site = (pk: string) => (S.sites as Site[]).find(s => s.pk === pk);
const now = () => Math.floor(Date.now() / 1000);

const startedAt = Date.now();
const lastSeen = new Map<number, number>();
const seen = (idx: number) => lastSeen.get(idx) ?? 0;
// Pings go out every 10 s; three missed means gone.
const online = (m: Member) => m.idx === me.idx || Date.now() - seen(m.idx) < 30_000;

const activity: { ts: number; text: string }[] = [];
const note = (text: string) => {
  activity.unshift({ ts: Date.now(), text });
  activity.length = Math.min(activity.length, 40);
  console.log(`[${me.name}] ${text}`);
};

// --- Relays ------------------------------------------------------------------

const pool = new Pool(S.group.relays, onEvent, t => console.log(`[${me.name}] ${t}`));
const send = (toPk: string | null | undefined, msg: object) => { if (toPk) for (const e of sealParts(S.self.sk, toPk, msg)) pool.publish(e); };
const parts = new Parts();
const toOther = (msg: object) => send(other().pk, msg);
const toPhone = (msg: object) => send(phone().pk, msg);

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
setInterval(() => { for (const [k, v] of given) if (Date.now() - v.at > 120_000) given.delete(k); }, 30_000);
function answerOnce(to: Member, id: string, make: () => object | undefined) {
  const k = `${to.pk}:${id}`;
  const prior = given.get(k);
  if (prior) return send(to.pk, prior.msg);
  const msg = make();
  if (!msg) return;
  given.set(k, { at: Date.now(), msg });
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
    lastSeen.set(from.idx, Date.now());
    // The other server just came back: bring it up to date.
    if (!wasOnline && from.role === 'server') syncTo();
  }

  if ((msg.type === 'sign_res' || msg.type === 'ecdh_res') && pending.has(msg.id)) {
    const p = pending.get(msg.id)!; clearTimeout(p.timer); pending.delete(msg.id);
    return p.resolve({ ...msg, from });
  }
  if (msg.type === 'pair_hello') return onPairHello(msg, fromPk);
  if (msg.type === 'pair_ack') return onPairAck(msg, fromPk);
  if (!from) return;

  const fromPhone = from.role === 'phone';
  switch (msg.type) {
    case 'ping': return;
    case 'asking': { if (fromPhone) waitLonger(String(msg.id)); return; }
    case 'sign_req': return answerOnce(from, msg.id, () => onSignReq(msg, from));
    // An app on your phone asked it to sign (Android signer): the phone runs the round.
    case 'cosign_req': return answerOnce(from, msg.id, () => onCosignReq(msg, from));
    case 'phone_signed': { if (fromPhone) onPhoneSigned(msg); return; }
    case 'app_grant': { if (fromPhone) grantApp(msg); return; }
    case 'cancel_batch': { // Undo on a deletion in its 10 s
      const b = fromPhone ? batchById(String(msg.batch)) : undefined;
      if (b) { b.cancelled = true; clearTimeout(b.timer); const site = [...batches].find(([, x]) => x === b)?.[0]; if (site) void closeBatch(site, b); }
      return;
    }
    case 'repost': { if (fromPhone) repost(String(msg.id)).catch(err => toPhone({ type: 'undo_failed', id: msg.id, reason: err.message })); return; }
    case 'site_summary': { if (fromPhone) toPhone({ type: 'site_summary', pk: msg.pk, ...siteSummary(String(msg.pk)) }); return; }
    case 'undo_site': { if (fromPhone) undoSite(String(msg.pk)).catch(err => { note(`couldn't undo ${msg.pk}: ${err.message}`); toPhone({ type: 'undo_failed', id: msg.pk, reason: err.message }); }); return; }
    case 'batch_decision': { if (fromPhone) decisions.get(String(msg.batch))?.(msg.approve === true); return; }
    case 'remove_future': { if (fromPhone) removeFuture(String(msg.id)).catch(err => { note(`couldn't remove it: ${err.message}`); toPhone({ type: 'undo_failed', id: msg.id, reason: err.message }); }); return; }
    case 'ecdh_req': return answerOnce(from, msg.id, () => onEcdhReq(msg, from));

    case 'member': { // the server that added the phone says who it is
      if (fromPhone) return;
      phone().pk = msg.pk; save(); note('learned your phone from ' + from.name); return;
    }
    case 'push': { // where to send "approval needed"
      if (!fromPhone) return;
      phone().push = msg.endpoint || null; save(); toOther({ type: 'push_relay', endpoint: msg.endpoint }); return;
    }
    case 'push_relay': { if (!fromPhone) { phone().push = msg.endpoint || null; save(); } return; }
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
    case 'undo': { if (fromPhone) undo(String(msg.id)).catch(err => { note(`undo failed: ${err.message}`); toPhone({ type: 'undo_failed', id: msg.id, reason: err.message }); }); return; }
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

const coordinating = () => me.idx === 1 || (Date.now() - startedAt > 30_000 && !online(members.find(m => m.idx === 1)!));
const answers = new Map<string, { at: number; body: string; scheme: 'nip44' | 'nip04' }>();
const working = new Set<string>();
setInterval(() => { for (const [k, v] of answers) if (Date.now() - v.at > 180_000) answers.delete(k); }, 30_000);

function reply(clientPk: string, scheme: 'nip44' | 'nip04', body: string) {
  const sk = F.hexToBytes(S.signer.sk);
  const content = scheme === 'nip44' ? nip44.v2.encrypt(body, nip44.v2.utils.getConversationKey(sk, clientPk)) : nip04.encrypt(sk, clientPk, body);
  pool.publish(finalizeEvent({ kind: KIND_NIP46, created_at: now(), tags: [['p', clientPk]], content }, sk));
}

async function onSiteRequest(e: Event) {
  if (!coordinating()) return;
  const sk = F.hexToBytes(S.signer.sk);
  let scheme: 'nip44' | 'nip04' = 'nip44', req: any;
  try { req = JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(sk, e.pubkey))); }
  catch { try { scheme = 'nip04'; req = JSON.parse(nip04.decrypt(sk, e.pubkey, e.content)); } catch { return; } }
  if (!req?.id || !req.method) return;
  if (process.env.DEBUG) console.log(`[${me.name}] site ${e.pubkey.slice(0, 6)} asked ${req.method} (${req.id})`);

  const k = `${e.pubkey}:${req.id}`;
  const cached = answers.get(k);
  if (cached) return reply(e.pubkey, cached.scheme, cached.body);
  if (working.has(k)) return;
  working.add(k);
  const answer = (body: object) => {
    const text = JSON.stringify({ id: req.id, ...body });
    answers.set(k, { at: Date.now(), body: text, scheme });
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
  const s = site(client);
  if (!s || s.revoked) { // the phone repeats itself until it hears back; only the first counts
    if (!s) S.sites.push({ pk: client, origin, added: now(), lastUsed: now(), relays } satisfies Site);
    else { delete s.revoked; s.relays = relays; } // scanned again: that's you letting it back in
    note(`${origin} connected${s ? ' again' : ''}, by nostrconnect`);
    save(); syncTo();
  }
  pushState();
  await pool.add(relays);
  if (!coordinating()) return;
  // Twice, in case a relay drops the first; the site takes whichever arrives.
  const answer = () => reply(client, 'nip44', JSON.stringify({ id: rid(), result: secret }));
  answer(); setTimeout(answer, 4000);
  toPhone({ type: 'connected', pk: client, origin });
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
  const order = partners(hold ? [phone()] : [phone(), other()]);
  const tried: string[] = [];
  const done = (r: Attempt) => {
    note(`signed ${kindName(ev.kind)} for ${by} with ${r.m.name}${hold && !opts.undo ? ' — you approved' : ''}`);
    keep(r.signed!, judged.change ?? hold, by, !!hold && !opts.undo, opts.site ?? '', prev);
    return r.signed!;
  };

  /** One round with one partner: its commitment and partial, then ours, then the signature. */
  async function attempt(m: Member, wait: number, reqId = rid()): Promise<Attempt> {
    const participants = [me.idx, m.idx].sort((a, b) => a - b);
    const mine = Sig.commit(S.group, me.idx, S.self.share); // fresh every round; used only once we have a valid partner
    const res = await ask(m.pk!, { type: 'sign_req', id: reqId, event: ev, msg: id, participants, commit: mine.commit, frost: 2, app: by, hold: hold ?? null, undo: opts.undo ?? null, batch: batch ?? null }, wait);
    if (!res.ok) return { m, reason: String(res.reason) };
    const commits = [mine.commit, res.commit];
    // Whichever math the partner used (it may not be updated yet), finish the round in it.
    const scheme = res.commit?.idx === m.idx ? Sig.schemeOf(S.group, id, commits, m.idx, res.z) : null;
    if (!scheme) return { m, reason: 'bad partial' };
    if (process.env.DEBUG) console.log(`[${me.name}] ${m.name} signed with ${scheme === 2 ? 'FROST (RFC 9591)' : 'the earlier math'}`);
    const z = Sig.partial(scheme, S.group, me.idx, S.self.share, mine.nonces, id, commits);
    return { m, signed: { ...ev, id, sig: Sig.combine(scheme, S.group, id, commits, [[me.idx, z], [m.idx, res.z]]) } as Event };
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
    const runs = order.slice(0, 2).map((m, i) => attempt(m, m.role === 'phone' ? 10_000 : 8_000, ids[i]));
    const first = await new Promise<Attempt | null>(resolve => {
      let left = runs.length;
      for (const r of runs) void r.then(a => { if (a.signed) resolve(a); else { tried.push(`${a.m.name}: ${a.reason}`); if (--left === 0) resolve(null); } });
    });
    ids.forEach(cancelAsk);
    if (first) { if (process.env.DEBUG) console.log(`[${me.name}] ${first.m.name} answered first`); return done(first); }
  } else for (const [i, m] of order.entries()) {
    const isPhone = m.role === 'phone';
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
      ? (other().pk ? 'Neither your phone nor your backup server answered. Is Cosign running on your phone?' : 'Your phone didn’t answer. Is Cosign running on it?')
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
    const p = new SimplePool();
    const relays = [...new Set([...S.group.relays, ...ourWriteRelays()].map(dial))];
    try {
      for (const e of await p.querySync(relays, { ids: missing }, { maxWait: 4000 })) if (e.pubkey === groupX && verifyEvent(e)) history.save(e);
    } catch { /* keep what we have */ }
    p.close(relays);
  }
  const copies = ids.map(id => history.savedCopy(id)).filter(Boolean);
  if (copies.length) toOther({ type: 'saved', events: copies });
}

function deletionWindow(site: string, by: string, ev: Ev, held: boolean): Promise<{ id: string; approved: boolean }> {
  let b = batches.get(site);
  if (!b) {
    let settle!: Batch['settle'];
    const done = new Promise<{ id: string; approved: boolean }>((res, rej) => { settle = v => (v instanceof Error ? rej(v) : res(v)); });
    b = { id: rid(), by, requests: 0, targets: 0, held: false, cancelled: false, until: Date.now() + WINDOW, done, settle };
    batches.set(site, b);
    const batch = b;
    b.timer = setTimeout(() => void closeBatch(site, batch), WINDOW);
  }
  b.requests++;
  b.targets += ev.tags.filter(t => t[0] === 'e' || t[0] === 'a').length;
  b.held ||= held;
  toPhone({ type: 'deleting', batch: b.id, by, count: b.targets, until: b.until });
  return b.done;
}

async function closeBatch(site: string, b: Batch) {
  if (batches.get(site) === b) batches.delete(site);
  toPhone({ type: 'deleting_done', batch: b.id });
  if (b.cancelled) return b.settle(new Error('You stopped this deletion on your phone.'));
  if (b.targets < 5 && !b.held) return b.settle({ id: b.id, approved: false });
  const text = `Delete ${b.targets} event${b.targets === 1 ? '' : 's'} for ${b.by}${b.held ? ', including one of your lists' : ''}`;
  pushPhone();
  const ok = await new Promise<boolean>(resolve => {
    const t = setTimeout(() => { decisions.delete(b.id); resolve(false); }, 60_000);
    decisions.set(b.id, approve => { clearTimeout(t); decisions.delete(b.id); resolve(approve); });
    const askNow = () => { if (decisions.has(b.id)) toPhone({ type: 'approve_batch', batch: b.id, text, by: b.by, expires: Date.now() + 55_000 }); };
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
  if (history.add(entry)) { toOther({ type: 'logged', entry }); toPhone({ type: 'logged', entry }); }
  if (!ARCHIVED.has(signed.kind) && !held) return;
  archive.record(signed);
  const change: Change | undefined = text ? { id: signed.id, key: keyOf(signed), kind: signed.kind, at: signed.created_at, text, by, held } : undefined;
  if (change) addChange(change, false);
  toOther({ type: 'signed', event: signed, change });
  // The phone judges for itself too, against the latest version it has seen signed.
  if (ARCHIVED.has(signed.kind)) toPhone({ type: 'signed', event: signed });
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
  if (participants.length !== 2 || !participants.includes(me.idx) || !participants.includes(from.idx)) return respond({ ok: false, reason: 'bad participants' });
  if (ev.pubkey !== groupX || getEventHash(ev) !== msg.msg) return respond({ ok: false, reason: 'event does not match the message' });
  // Our own archive, not the coordinator's word: a compromised server can't talk us
  // into co-signing something destructive without the phone.
  const { hold, refuse } = assess(ev, archive.latest(keyOf(ev)));
  if (refuse) { note(`refused to co-sign for ${from.name}: ${refuse}`); return respond({ ok: false, reason: `refused: ${refuse}` }); }
  if (hold && !participants.includes(phone().idx)) {
    note(`refused to co-sign for ${from.name}: ${hold} needs your phone`);
    return respond({ ok: false, reason: `${hold} needs your phone` });
  }
  const mine = Sig.commit(S.group, me.idx, S.self.share);
  const z = Sig.partial(msg.frost === 2 ? 2 : 1, S.group, me.idx, S.self.share, mine.nonces, msg.msg, [msg.commit, mine.commit]);
  return respond({ ok: true, commit: mine.commit, z });
}

function onEcdhReq(msg: any, from: Member): object {
  const respond = (r: object) => ({ type: 'ecdh_res', id: msg.id, ...r });
  if (!msg.participants?.includes(me.idx) || !msg.participants.includes(from.idx)) return respond({ ok: false, reason: 'bad request' });
  // The phone asks on behalf of an app it has let read your messages; that app must still have access.
  if (from.role === 'phone' && !liveGrant(msg.grant)) return respond({ ok: false, reason: 'revoked: that app no longer has access' });
  return respond({ ok: true, point: F.ecdhPartial({ idx: me.idx, secret: S.self.share, participants: msg.participants, peerX: msg.peerX }) });
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
  if (s) delete s.revoked; // connected again on the phone
  else S.sites.push({ pk, origin: String(msg.origin ?? 'An app').slice(0, 80), added: now(), lastUsed: now(), via: 'App on this phone' } satisfies Site);
  save(); syncTo(); pushState();
  note(`${msg.origin} connected, as an app on your phone`);
}

function onCosignReq(msg: any, from: Member): object {
  const respond = (r: object) => ({ type: 'cosign_res', id: msg.id, ...r });
  const ev = msg.event;
  if (from.role !== 'phone') return respond({ ok: false, reason: 'only your phone does this' });
  const participants: number[] = msg.participants ?? [];
  if (participants.length !== 2 || !participants.includes(me.idx) || !participants.includes(from.idx)) return respond({ ok: false, reason: 'bad participants' });
  if (ev?.pubkey !== groupX || getEventHash(ev) !== msg.msg) return respond({ ok: false, reason: 'event does not match the message' });
  const grant = liveGrant(msg.grant);
  if (!grant) return respond({ ok: false, reason: 'revoked: that app no longer has access' });
  const { hold, refuse } = assess(ev, archive.latest(keyOf(ev)));
  if (refuse) return respond({ ok: false, reason: `refused: ${refuse}` });
  if (hold && !msg.approved) return respond({ ok: false, reason: `needs-approval: ${hold}` });
  grant.lastUsed = now();
  const mine = Sig.commit(S.group, me.idx, S.self.share);
  const z = Sig.partial(2, S.group, me.idx, S.self.share, mine.nonces, msg.msg, [msg.commit, mine.commit]);
  return respond({ ok: true, commit: mine.commit, z });
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
  if (hit && Date.now() - hit.at < 600_000) return hit.x;
  const tried: string[] = [];
  const order = partners([phone(), other()]);
  for (const [i, m] of order.entries()) {
    const participants = [me.idx, m.idx].sort((a, b) => a - b);
    const res = await ask(m.pk!, { type: 'ecdh_req', id: rid(), peerX, participants }, m.role === 'phone' ? phoneWait(false, order.slice(i + 1)) : 6_000);
    if (!res.ok) { tried.push(`${m.name}: ${res.reason}`); continue; }
    const x = F.ecdhCombine([F.ecdhPartial({ idx: me.idx, secret: S.self.share, participants, peerX }), res.point]);
    ecdhCache.set(peerX, { x, at: Date.now() });
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
  const before = archive.history(keyOf(target)).find(e => e.created_at < target.created_at && e.id !== target.id);
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
  toPhone({ type: 'undone_site', pk, origin: s.origin, restored, deleted });
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
  const targets = [...new Set([...ourWriteRelays(), ...S.group.relays].map(dial))];
  const p = new SimplePool();
  await Promise.allSettled(p.publish(targets, e as any));
  p.close(targets);
}

// --- Keeping the two servers and the phone in step ------------------------------

function syncTo() {
  toOther({ type: 'sync', sites: S.sites, tickets: S.tickets, changes: S.changes, archive: archive.all() });
}

function mergeSync(msg: any) {
  let dirty = false;
  for (const s of (msg.sites ?? []) as Site[]) {
    const mine = site(s.pk);
    if (!mine) { S.sites.push(s); dirty = true; if (s.relays && !s.revoked) void pool.add(s.relays); continue; }
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
  toPhone({
    type: 'state',
    sites: (S.sites as Site[]).filter(s => !s.revoked).map(s => ({ pk: s.pk, origin: siteName(s.origin), added: s.added, lastUsed: s.lastUsed, parent: s.parent ?? null, via: s.via ?? null })),
    changes: (S.changes as Change[]).slice(0, 30),
    // Deleted, with a copy kept: the newest 20, for "Post again".
    deleted: history.allSaved().filter(e => !ARCHIVED.has(e.kind) && !reposted.has(e.id!)).sort((a, b) => b.created_at - a.created_at).slice(0, 20)
      .map(e => ({ id: e.id, kind: kindName(e.kind), at: e.created_at, text: e.content.slice(0, 140) })),
    future: archive.future().map(e => ({ id: e.id, kind: e.kind, at: e.created_at, text: `Your ${kindName(e.kind)} has a version dated ${new Date(e.created_at * 1000).toISOString().slice(0, 10)}. On relays that took it, it blocks every change you make.` })),
  });
}

/** Wake the phone through ntfy. The message says only that something is waiting. */
function pushPhone() {
  const url = phone().push;
  if (!url) return;
  fetch(url, { method: 'POST', body: 'cosign:approve', headers: { Priority: 'high' } })
    .catch(err => note(`push failed: ${err.message}`));
}

// --- Adding your phone --------------------------------------------------------

let offeredTo: string | null = null;
const pairingUri = () => S.pairing
  ? `cosign:pair?pk=${me.pk}&t=${S.pairing.token}&${S.group.relays.map((r: string) => 'r=' + encodeURIComponent(r)).join('&')}`
  : null;

function onPairHello(msg: any, fromPk: string) {
  if (!S.pairing || msg.token !== S.pairing.token) return;
  offeredTo = fromPk;
  send(fromPk, {
    type: 'pair_offer', token: S.pairing.token, idx: S.pairing.idx, share: S.pairing.share,
    signer: S.signer.pk,
    group: { groupX, npub: S.group.npub, threshold: S.group.threshold, relays: S.group.relays,
      members: members.map(m => ({ idx: m.idx, name: m.name, role: m.role, pk: m.role === 'phone' ? null : m.pk, sharePub: m.sharePub })) },
  });
  note('a phone scanned the code');
}

function onPairAck(msg: any, fromPk: string) {
  if (!S.pairing || fromPk !== offeredTo || msg.token !== S.pairing.token) return;
  const p = phone();
  p.pk = fromPk;
  S.pairing = null; // the phone has its share; this server no longer does
  save();
  lastSeen.set(p.idx, Date.now());
  toOther({ type: 'member', idx: p.idx, pk: fromPk });
  note('your phone joined');
}

// --- Liveness ----------------------------------------------------------------

const pingAll = () => { for (const m of members) if (m.pk && m.idx !== me.idx) send(m.pk, { type: 'ping', idx: me.idx, ts: Date.now() }); };
setInterval(pingAll, 10_000);
setTimeout(pingAll, 2000);
setTimeout(syncTo, 4000);

// Pick up what's already published under your key, so the first change is judged
// against something.
async function fetchArchive() {
  const p = new SimplePool();
  const relays = [...new Set([...S.group.relays, 'wss://relay.damus.io'].map(dial))];
  try {
    const events = await p.querySync(relays, { authors: [groupX], kinds: [...ARCHIVED] }, { maxWait: 6000 });
    let n = 0;
    for (const e of events) if (archive.record(e)) n++;
    if (n) note(`archived ${n} version${n === 1 ? '' : 's'} already on relays`);
    checkFuture();
  } catch { /* relays come and go */ }
  p.close(relays);
}
setTimeout(fetchArchive, 3000);
// Judge "the future" by the network's time, not this machine's clock.
void checkClock(note);
setInterval(() => void checkClock(note), 30 * 60_000);
setInterval(fetchArchive, 15 * 60_000);

// --- Status page -------------------------------------------------------------

const ago = (t: number) => { const s = now() - t; return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
function status() {
  return {
    me: me.name, npub: S.group.npub, coordinating: coordinating(),
    members: members.map(m => ({ name: m.name, online: !!m.pk && online(m), paired: !!m.pk, self: m.idx === me.idx })),
    relays: pool.status(), pairing: !!S.pairing,
    sites: (S.sites as Site[]).filter(s => !s.revoked).sort((a, b) => b.lastUsed - a.lastUsed)
      .map(s => ({ pk: s.pk, origin: esc(siteName(s.origin)), via: esc(s.via ?? (s.parent ? 'Connected' : 'Connected by code')), lastUsed: ago(s.lastUsed) })),
    changes: (S.changes as Change[]).slice(0, 15).map(c => ({ text: esc(c.text), by: esc(c.by), when: ago(c.at), held: !!c.held, undone: !!c.undone })),
    activity: activity.map(a => ({ ts: a.ts, text: esc(a.text) })),
  };
}

const page = async () => {
  const pu = pairingUri();
  const pairQr = pu ? await QRCode.toString(pu, { type: 'svg', margin: 1 }) : '';
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${me.name} · cosign</title>
<style>
 body{font:15px/1.45 system-ui,sans-serif;background:#13110f;color:#ede6da;max-width:760px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:0 0 8px;color:#a69d90;font-weight:600}
 .muted{color:#a69d90} .card{background:#1e1b18;border:1px solid #2a2622;border-radius:12px;padding:16px;margin:14px 0}
 .row{display:flex;gap:10px;align-items:center;margin:6px 0} .dot{width:9px;height:9px;border-radius:50%;background:#4a443c;flex:none} .on{background:#7fc8c0}
 .qr{background:#fff;padding:10px;border-radius:10px;width:220px} .grid{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start}
 button{background:none;border:1px solid #5a4520;color:#e9cf97;border-radius:8px;padding:5px 12px;font:inherit;cursor:pointer}
 .site{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-top:1px solid #2a2622} .site:first-child{border-top:0}
 .open{display:inline-block;background:#7fc8c0;color:#13110f;border-radius:8px;padding:8px 14px;text-decoration:none;font-weight:600;margin-top:6px}
 .held{color:#f2b33d} ul{padding-left:18px;margin:4px 0} li{margin:3px 0}
</style>
<h1>${me.name}</h1><div class=muted>${S.group.npub} · 2 of 3</div>
<div class=card><div id=members></div><div class=muted id=coord style="margin-top:6px"></div></div>
${pu ? `<div class=card id=pair><h2>Add your phone</h2><div class=grid><div class=qr>${pairQr}</div>
<div style="flex:1;min-width:220px">Open <b>Cosign</b> on your phone and scan this. It becomes the third member and your remote control.<br><br>
Already on your phone? <a class=open href="${esc(pu)}">Open in Cosign</a><br><br>
<span class=muted>Whoever scans it (or opens it) first becomes that member, so only show it to your phone.</span></div></div></div>` : ''}
<div class=card><h2>Sites that can sign as you</h2><div id=sites></div></div>
<div class=card><h2>Recent changes to your lists</h2><ul id=changes></ul></div>
<div class=card><h2>Activity</h2><ul id=act></ul></div>
<script>
const $=id=>document.getElementById(id);
async function revoke(pk){ await fetch('/revoke',{method:'POST',body:pk}); tick(); }
async function tick(){const s=await (await fetch('/status')).json();
 $('members').innerHTML=s.members.map(m=>'<div class=row><span class="dot '+(m.online?'on':'')+'"></span>'+m.name+(m.self?' <span class=muted>(this one)</span>':'')+(m.paired?'':' <span class=muted>— not added</span>')+'</div>').join('');
 $('coord').textContent=(s.coordinating?'Answering your sites. ':'Standing by. ')+s.relays.filter(r=>r.up).length+'/'+s.relays.length+' relays';
 const groups={};for(const x of s.sites)(groups[x.origin]??=[]).push(x);
 $('sites').innerHTML=Object.entries(groups).map(([o,g])=>'<div class=site style="display:block"><div>'+o+'</div>'+g.map(x=>'<div class=row style="justify-content:space-between"><span class=muted style="font-size:13px">'+x.via+' · used '+x.lastUsed+'</span><button data-pk="'+x.pk+'">Remove</button></div>').join('')+'</div>').join('')||'<div class=muted>None yet. Scan a site’s code with your phone.</div>';
 for(const b of document.querySelectorAll('button[data-pk]')) b.onclick=()=>revoke(b.dataset.pk);
 $('changes').innerHTML=s.changes.map(c=>'<li class="'+(c.held?'held':'')+'">'+c.text+' <span class=muted>· '+c.by+' · '+c.when+(c.undone?' · undone':'')+'</span></li>').join('')||'<li class=muted>None yet.</li>';
 $('act').innerHTML=s.activity.map(a=>'<li><span class=muted>'+new Date(a.ts).toLocaleTimeString()+'</span> '+a.text+'</li>').join('')||'<li class=muted>Nothing yet.</li>';
 if(!s.pairing&&$('pair'))location.reload();}
tick(); setInterval(tick,2000);
</script>`;
};

createServer(async (req, res) => {
  if (req.url === '/status') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify(status())); }
  if (req.url === '/revoke' && req.method === 'POST') {
    let body = ''; req.on('data', c => (body += c)); req.on('end', () => { revoke(body.trim(), `on ${me.name}'s page`); res.end('ok'); }); return;
  }
  if (req.url === '/') { res.setHeader('content-type', 'text/html'); return res.end(await page()); }
  res.statusCode = 404; res.end();
}).listen(S.port, process.env.HOST ?? '127.0.0.1', () => console.log(`[${me.name}] http://localhost:${S.port}`));

pool.start([{ kinds: [KIND_MEMBER], '#p': [me.pk!] }, { kinds: [KIND_NIP46], '#p': [S.signer.pk] }]);
// Sites that came by nostrconnect may be listening on relays of their own.
void pool.add((S.sites as Site[]).filter(s => !s.revoked).flatMap(s => s.relays ?? []), 0);
note('started');
