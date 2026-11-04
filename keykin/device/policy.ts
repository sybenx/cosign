// Device policy §2–§4 and §6: how a device judges an event a site asks it to sign. Three levels: Silent, Confirm
// (one card on this device, one tap) and Held (core §5.8's set exactly: the lock, or a 3-day hold the person
// starts); plus a single deletion's 10-second Undo, `declined:` and `try-later:`. The judge is pure: it reads the
// device's history and every device's records (device/history.ts) and returns a verdict; the Guard holds what the
// person sees (cards, the Undo wait, auto-declines) and records what each signed event did.
//
// Not yet: Device policy §5 (drafts staged offline); a co-signing device's `waited` statements (it enforces Held
// with the coordinator's lock assertion or a hold at itself, as the core does); merging a leaving device's records
// into the device that takes over.

import { strictJson, KeykinError } from '../src/bytes.ts';
import { destructive, deletionTargets, nonEmptyField, profileObject, isReplaceable, type Ev } from '../src/destructive.ts';
import type { NostrEvent, Unsigned } from '../src/event.ts';
import { History, Ledger, addrOf, addrOfA, judged, isList, PROFILE, RELAY_LISTS, WALLET } from './history.ts';
import type { Scope } from './grants.ts';

export type Level = 'silent' | 'undo' | 'confirm' | 'held' | 'declined' | 'try-later';
const RANK: Record<Level, number> = { silent: 0, undo: 1, confirm: 2, held: 3, 'try-later': 4, declined: 5 };
/** A verdict: its level, the §2 row that set it (auto-declines count by row, §6), and plain words for the card. */
export interface Verdict { level: Level; row: string; reason: string; media?: { files: string[]; servers: string[] | '*'; expiry: number; url?: string } }
const v = (level: Level, row: string, reason: string, extra: Partial<Verdict> = {}): Verdict => ({ level, row, reason, ...extra });
const strictest = (vs: Verdict[]) => vs.reduce((a, b) => (RANK[b.level] > RANK[a.level] ? b : a), v('silent', 'ordinary', ''));

// --- items (§2 "Items") ------------------------------------------------------------------------------
const NOT_ITEMS = new Set(['d', 'title', 'description', 'image', 'alt', 'client']);
/** Kinds whose spec has no private items: judged by their public tags alone. */
const NO_PRIVATE = new Set([3, 10002, 10050, 10019, 10063]);
/** A relay URL with a lowercase host and no trailing slash; any other value as it is. */
export function normValue(x: string): string {
  if (!/^wss?:\/\//i.test(x)) return x;
  try { const u = new URL(x); return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}${u.search}`; } catch { return x; }
}
const tagItems = (tags: unknown, where: 'pub' | 'priv') => {
  const out = new Set<string>();
  if (Array.isArray(tags)) for (const t of tags) if (Array.isArray(t) && t.length >= 2 && typeof t[0] === 'string' && typeof t[1] === 'string' && !NOT_ITEMS.has(t[0]))
    out.add(`${where} ${t[0]} ${normValue(t[1])}`);
  return out;
};
/** How private content reads: the plaintext, null when it doesn't decrypt, undefined when the self key can't be had. */
export type Decrypt = (content: string) => Promise<string | null | undefined>;
/** A list version's items, public and private; undefined when its private content can't be read (no self key). */
export async function itemsOf(e: { kind: number; tags: string[][]; content: string }, decrypt: Decrypt): Promise<Set<string> | undefined> {
  const out = tagItems(e.tags, 'pub');
  if (NO_PRIVATE.has(e.kind) || e.content === '') return out;
  const plain = await decrypt(e.content);
  if (plain === undefined) return undefined;
  // Content that doesn't decrypt to a NIP-51 tag array removes every private item.
  let tags: unknown = null; try { if (plain !== null) tags = strictJson(plain); } catch { /* none */ }
  for (const it of tagItems(tags, 'priv')) out.add(it);
  return out;
}
const profileFields = (content: string) => {
  const o = profileObject(content) ?? {};
  return new Map(Object.entries(o).map(([k, x]) => [k, x]));
};
const filled = (content: string) => new Set([...profileFields(content)].filter(([, x]) => nonEmptyField(x)).map(([k]) => `pub field ${k}`));

// --- the judge ---------------------------------------------------------------------------------------
export interface JudgeCtx {
  g: string; now: number;
  /** Who asks: a grant `${by}:${id}`. */
  owner: string; scopes: Scope[];
  history: History;
  /** Every current device's records, this one's included. */
  ledger: Ledger;
  decrypt: Decrypt;
  /** The account's events by id, from its relays (a deletion's targets the device doesn't have). */
  lookup(ids: string[], addrs: string[]): Promise<NostrEvent[]>;
  /** Media deletes the person allowed on a card, for 10 minutes (§2's Blossom row). */
  allowed?(files: string[], server: string | null): boolean;
}
const DAY = 86400, WEEK = 7 * DAY, AHEAD_S = 300, BUDGET = 20;
const tag = (e: { tags: string[][] }, n: string) => e.tags.find((t) => t[0] === n)?.[1];
const HASH = /^[0-9a-f]{64}$/;

/** Judge an event a site asks to have signed (§2). */
export async function judge(e: Unsigned, c: JudgeCtx): Promise<Verdict> {
  const out: Verdict[] = [];
  const burst = c.ledger.burst(c.now);
  if (destructive(e as Ev, burst)) out.push(v('held', 'core', coreReason(e)));
  const addr = isReplaceable(e.kind) ? addrOf(e) : null;
  // Expiring lists: relays would drop the list a moment later.
  if (addr && judged(e.kind) && e.tags.some((t) => t[0] === 'expiration')) out.push(v('declined', 'expiring', 'a list that expires'));
  if (addr && judged(e.kind) && e.created_at - c.now > AHEAD_S) out.push(v('declined', 'ahead', 'dated more than 5 minutes ahead'));
  if (e.kind === 5) {
    const d = await judgeDeletion(e, c, burst);
    // The wallet row wins over the stricter rows; it never signs what core §5.8 would hold.
    if (d.row === 'wallet-delete') return out.some((x) => x.row === 'core') ? v('try-later', 'wallet-delete', 'too many wallet deletions; try later') : d;
    out.push(d);
  } else if (e.kind === 24242 && tag(e, 't') === 'delete') out.push(blossomDelete(e, c));
  else if (e.kind === 27235 && (tag(e, 'method') ?? '').toUpperCase() === 'DELETE') {
    const url = tag(e, 'u') ?? '', h = url.match(/([0-9a-f]{64})(?:\.[A-Za-z0-9]+)?$/)?.[1];
    let host: string | null = null; try { host = new URL(url).host; } catch { /* none */ }
    if (h && c.allowed?.([h], host)) out.push(v('silent', 'media-delete', ''));
    else out.push(v('confirm', 'media-delete', `Delete ${url}?`, { media: { files: h ? [h] : [], servers: host ? [host] : '*', expiry: 0, url } }));
  } else if (addr && judged(e.kind)) out.push(await judgeList(e, addr, c));
  return strictest(out);
}

function coreReason(e: Unsigned) {
  if (e.kind === 5) return `Delete ${deletionTargets(e as Ev)} events?`;
  if (e.kind === 0) return 'Empty your profile?';
  if (e.kind === 10002) return 'Leave you with no relays?';
  if (e.kind === 62) return 'Ask relays to forget everything you posted?';
  return e.kind >= 1244 && e.kind <= 1247 ? 'Change your key family?' : 'Empty this list?';
}

function blossomDelete(e: Unsigned, c: JudgeCtx): Verdict {
  const files = e.tags.filter((t) => t[0] === 'x' && typeof t[1] === 'string').map((t) => t[1].toLowerCase());
  const exp = Number(tag(e, 'expiration'));
  const servers = e.tags.filter((t) => t[0] === 'server' && typeof t[1] === 'string').map((t) => t[1]);
  if (files.length > 4 || !files.length || !Number.isSafeInteger(exp) || exp - c.now > 600) return v('declined', 'media-delete', 'a delete token that is too wide');
  if (servers.length <= 1 && c.allowed?.(files, servers[0] ?? null)) return v('silent', 'media-delete', '');
  const where = servers.length ? servers.join(', ') : 'every server they\'re on';
  return v('confirm', 'media-delete', `Delete ${files.length} file${files.length > 1 ? 's' : ''} from ${where}?`, { media: { files, servers: servers.length ? servers : '*', expiry: exp } });
}

async function judgeDeletion(e: Unsigned, c: JudgeCtx, burst: number): Promise<Verdict> {
  const ids = new Set<string>(), addrs = new Set<string>();
  for (const t of e.tags) if (Array.isArray(t) && t.length >= 2 && typeof t[1] === 'string') {
    if (t[0] === 'e' && HASH.test(t[1].toLowerCase())) ids.add(t[1].toLowerCase());
    else if (t[0] === 'a') { const a = addrOfA(t[1], c.g); if (a) addrs.add(a); else if (!/^\d+:[0-9a-fA-F]{64}:/.test(t[1])) addrs.add(`?${t[1]}`); }
  }
  // Fetch what the device doesn't have, by id and address (§2 "Deletions").
  const missIds = [...ids].filter((i) => !c.history.get(i)), missAddrs = [...addrs].filter((a) => !a.startsWith('?') && !c.history.current(a));
  const foreign = new Set<string>();
  if (missIds.length || missAddrs.length) for (const x of await c.lookup(missIds, missAddrs).catch(() => [] as NostrEvent[])) if (!c.history.take(x) && x?.id) foreign.add(String(x.id).toLowerCase());
  // Distinct events: an `e` and an `a` naming the same event are one. A target signed by another key is ignored.
  type T = { addr: string | null; ev: NostrEvent | null; viaA: boolean };
  const targets = new Map<string, T>();
  for (const i of ids) {
    const x = c.history.get(i);
    if (foreign.has(i) || (x && x.pubkey !== c.g)) continue;
    const a = x && isReplaceable(x.kind) ? addrOf(x) : null;
    targets.set(a && addrs.has(a) ? a : i, { addr: a, ev: x, viaA: false });
  }
  for (const a of addrs) {
    if (a.startsWith('?')) { targets.set(a, { addr: null, ev: null, viaA: true }); continue; }
    targets.set(a, { addr: a, ev: c.history.current(a), viaA: true });
  }
  if (!targets.size) return v('silent', 'ordinary', '');
  const list = [...targets.values()];
  const kindOf = (t: T) => t.ev?.kind ?? (t.addr ? Number(t.addr.split(':')[0]) : NaN);
  // The wallet row: every target a token, history or quote event, from a site with the wallet scope.
  if (c.scopes.includes('wallet') && list.every((t) => [7375, 7376, 7374].includes(kindOf(t)))) {
    const n = deletionTargets(e as Ev);
    const mine = c.ledger.dels.filter((d) => d.wallet && d.owner === c.owner && c.now - d.at < 600).length;
    return list.length <= 3 && mine < 3 && burst + n <= 3 ? v('silent', 'wallet-delete', '') : v('try-later', 'wallet-delete', 'too many wallet deletions; try later');
  }
  const out: Verdict[] = [];
  for (const t of list) {
    const k = kindOf(t);
    if (!t.ev && !t.addr) { out.push(v('confirm', 'delete-many', 'Delete an event this device can\'t find?')); continue; }
    if (Number.isFinite(k) && judged(k)) {
      const cur = t.addr ? c.history.current(t.addr) : null;
      const newest = t.viaA || !cur || !t.ev || t.ev.created_at >= cur.created_at;
      out.push(v('confirm', newest ? 'delete-list' : 'delete-many', newest ? (k === PROFILE ? 'Delete your profile?' : 'Delete this list?') : 'Delete an older version of a list?'));
    }
  }
  if (list.length >= 2) out.push(v('confirm', 'delete-many', `Delete ${list.length} events?`));
  else if (!out.length) {
    const t = list[0];
    if (!t.ev) out.push(v('confirm', 'delete-many', 'Delete an event this device can\'t find?'));
    else {
      // The site's own only if it was signed for this grant (for an address: every version known there).
      const own = t.addr ? c.history.all(t.addr).every((x) => c.ledger.signed.get(x.id) === c.owner) : c.ledger.signed.get(t.ev.id) === c.owner;
      const today = c.ledger.dels.filter((d) => d.single && d.owner === c.owner && c.now - d.at < DAY).length;
      if (!own) out.push(v('confirm', 'delete-other', 'Delete a post this site didn\'t make?'));
      else if (today >= BUDGET) out.push(v('confirm', 'delete-budget', 'Delete another post today?'));
      else out.push(v('undo', 'delete-one', 'Deleting a post'));
    }
  }
  // A deletion of a judged kind dated more than 5 minutes ahead is declined.
  if (e.created_at - c.now > AHEAD_S && out.some((x) => x.row === 'delete-list' || (x.row === 'delete-many' && list.some((t) => judged(kindOf(t)))))) out.push(v('declined', 'ahead', 'dated more than 5 minutes ahead'));
  return strictest(out);
}

/** The reference a site's removals are counted against: the newest of the pre-site version, the version from 7
 *  days ago and the version the person last approved for this site and list. */
export function reference(addr: string, c: Pick<JudgeCtx, 'history' | 'ledger' | 'owner' | 'now'>): NostrEvent | null {
  const ids = [c.ledger.presiteOf(c.owner, addr), c.ledger.approvedOf(c.owner, addr)?.[0]].filter(Boolean) as string[];
  const cands = [...ids.map((i) => c.history.get(i)), c.history.at(addr, c.now - WEEK)].filter(Boolean) as NostrEvent[];
  return cands.reduce<NostrEvent | null>((a, b) => (!a || b.created_at > a.created_at ? b : a), null);
}

async function judgeList(e: Unsigned, addr: string, c: JudgeCtx): Promise<Verdict> {
  const cur = c.history.current(addr), ref = reference(addr, c) ?? cur;
  const k = e.kind;
  if (k === PROFILE) {
    const out: Verdict[] = [];
    const now = filled(e.content), before = cur ? profileFields(cur.content) : new Map(), after = profileFields(e.content);
    for (const f of ['lud16', 'lud06', 'nip05']) if (JSON.stringify(before.get(f) ?? null) !== JSON.stringify(after.get(f) ?? null) && cur) out.push(v('confirm', 'profile', `Change your ${f === 'nip05' ? 'Nostr address' : 'lightning address'}?`));
    if (ref) {
      const removedNow = cur ? [...filled(cur.content)].filter((f) => !now.has(f)) : [];
      const log = c.ledger.removals(c.owner, addr);
      const emptied = [...filled(ref.content)].filter((f) => !now.has(f) && (log.has(f) || removedNow.includes(f)));
      if (emptied.length >= 2) out.push(v('confirm', 'profile', `Empty ${emptied.length} fields of your profile?`));
    }
    return strictest(out);
  }
  if (WALLET.has(k)) {
    if (!cur) return v('silent', 'wallet', '');
    if (k === 10019) {
      const pick = (x: { tags: string[][] }) => JSON.stringify(x.tags.filter((t) => t[0] === 'pubkey' || t[0] === 'mint').map((t) => [t[0], normValue(String(t[1] ?? ''))]).sort());
      return pick(cur) !== pick(e) ? v('confirm', 'wallet-settings', 'Change where you receive payments?') : v('silent', 'wallet', '');
    }
    return cur.content !== e.content || JSON.stringify(cur.tags) !== JSON.stringify(e.tags) ? v('confirm', 'wallet-settings', 'Change your wallet settings?') : v('silent', 'wallet', '');
  }
  if (!isList(k)) return v('silent', 'ordinary', '');
  const after = await itemsOf(e, c.decrypt), before = cur ? await itemsOf(cur, c.decrypt) : new Set<string>();
  if (!after || !before) return v('confirm', 'list-removals', 'Change a private list this device can\'t read?');
  const out: Verdict[] = [];
  if (RELAY_LISTS.has(k)) {
    const gone = [...before].filter((x) => !after.has(x)).length;
    const readOnly = k === 10002 && cur && e.tags.some((t) => t[0] === 'r' && t[2] === 'read' && cur.tags.some((u) => u[0] === 'r' && normValue(u[1] ?? '') === normValue(t[1] ?? '') && u[2] !== 'read'));
    if (gone || readOnly) out.push(v('confirm', 'relays', gone ? `Remove ${gone} of your relays?` : 'Stop writing to one of your relays?'));
    return strictest(out);
  }
  const refItems = ref ? (ref === cur ? before : await itemsOf(ref, c.decrypt)) : before;
  if (!refItems) return v('confirm', 'list-removals', 'Change a private list this device can\'t read?');
  // Emptied: no items left in a list that had some, or every item of a reference that had one (a new, empty set is no removal).
  const log = c.ledger.removals(c.owner, addr);
  const net = [...refItems].filter((x) => !after.has(x) && (log.has(x) || before.has(x))).length;
  if ((cur && before.size && !after.size) || (net && [...refItems].every((x) => !after.has(x)))) out.push(v('confirm', 'emptied', 'Empty this list?'));
  if (net >= 10 || (net >= 5 && net >= 0.2 * refItems.size)) out.push(v('confirm', 'list-removals', `Remove ${net} of your ${refItems.size} ${k === 3 ? 'follows' : 'list items'}?`));
  return strictest(out);
}

// --- the Guard: what the person sees, and what each signed event did ---------------------------------
export interface Card { id: number; owner: string; row: string; reason: string; level: 'confirm' | 'held'; events: Unsigned[]; at: number; shown: boolean;
  media?: Verdict['media'] }
export interface GuardHost {
  g: string; now: number; history: History; ledger(): Ledger;
  /** Write this device's records (and rebuild the merged view). */
  record(f: (l: Ledger) => void): void;
  decrypt: Decrypt; lookup: JudgeCtx['lookup'];
  /** The newest version of a list from the account's relays, for at most 3 seconds, before it is judged. */
  refresh(addr: string): Promise<void>;
  persist(): void;
}
/** A timer that never keeps the process alive on its own. */
const unref = (t: ReturnType<typeof setTimeout>) => { (t as any).unref?.(); return t; };
const HOUR = 3600, CARD_WAIT_MS = 120_000, QUIET_MS = 1000, ALLOW_S = 600;

export class Guard {
  readonly h: GuardHost;
  cards: Card[] = [];
  /** The person's declines per site: three of one row in an hour decline that row for an hour, six any card (§6). */
  declines = new Map<string, { at: number; row: string }[]>();
  allows: { owner: string; files: Set<string>; servers: Set<string> | '*'; until: number }[] = [];
  /** Shown to the app: a new or changed card. */
  onCard: ((c: Card) => void) | null = null;
  /** The 10-second wait on a single deletion (tests shorten it). */
  undoMs = 10_000; cardWaitMs = CARD_WAIT_MS; quietMs = QUIET_MS;
  #waits = new Map<number, { ok: (a: 'allow' | 'decline' | 'gone') => void }[]>();
  #undos = new Map<string, () => void>();
  #seq = 0;
  constructor(h: GuardHost) { this.h = h; }

  /** Judge an event for a site, with the newest list version fetched first. */
  async judge(e: Unsigned, owner: string, scopes: Scope[]): Promise<Verdict> {
    const a = isReplaceable(e.kind) ? addrOf(e) : null;
    if (a && judged(e.kind)) await this.h.refresh(a).catch(() => {});
    return judge(e, { g: this.h.g, now: this.h.now, owner, scopes, history: this.h.history, ledger: this.h.ledger(), decrypt: this.h.decrypt, lookup: this.h.lookup,
      allowed: (files, server) => this.#allowed(owner, files, server) });
  }

  /** Whether a site's event may be signed now: 'sign', or 'held' (core §5.8's answer is the caller's), or an error
   *  for the site. A Confirm waits for the person's answer; a single deletion waits 10 seconds for an Undo. */
  async gate(e: Unsigned, owner: string, scopes: Scope[]): Promise<{ ok: 'sign' | 'held'; verdict: Verdict } | { error: string; verdict: Verdict }> {
    const verdict = await this.judge(e, owner, scopes);
    switch (verdict.level) {
      case 'silent': return { ok: 'sign', verdict };
      case 'declined': return { error: `declined: ${verdict.reason}`, verdict };
      case 'try-later': return { error: `try-later: ${verdict.reason}`, verdict };
      case 'held': return this.#autoDeclined(owner, verdict.row) ? { error: 'declined: you declined this site\'s requests a moment ago', verdict } : { ok: 'held', verdict };
      case 'undo': return (await this.#undoWait(e)) ? { ok: 'sign', verdict } : { error: 'declined: undone', verdict };
      case 'confirm': {
        if (this.#autoDeclined(owner, verdict.row)) return { error: 'declined: you declined this site\'s requests a moment ago', verdict };
        const a = await this.#ask(e, owner, verdict);
        return a === 'allow' ? { ok: 'sign', verdict } : a === 'decline' ? { error: 'declined: you declined it', verdict } : { error: 'try-later: waiting for you on your phone', verdict };
      }
    }
  }

  // Cards (§2 Confirm, §6): one per event, except a site's media deletes within a quiet second, which share one.
  // Once a card is shown its contents never change; later tokens go to a new card.
  #ask(e: Unsigned, owner: string, verdict: Verdict): Promise<'allow' | 'decline' | 'gone'> {
    let card = verdict.row === 'media-delete' && verdict.media && !verdict.media.url?.length
      ? this.cards.find((c) => c.owner === owner && c.row === 'media-delete' && !c.shown && !c.media?.url) : undefined;
    if (card && verdict.media) {
      const m = card.media!; card.events.push(e);
      for (const f of verdict.media.files) if (!m.files.includes(f)) m.files.push(f);
      m.servers = m.servers === '*' || verdict.media.servers === '*' ? '*' : [...new Set([...m.servers, ...verdict.media.servers])];
      m.expiry = Math.max(m.expiry, verdict.media.expiry);
      card.reason = `Delete ${m.files.length} file${m.files.length > 1 ? 's' : ''} from ${m.servers === '*' ? 'every server they\'re on' : m.servers.join(', ')}?`;
    } else {
      card = { id: ++this.#seq, owner, row: verdict.row, reason: verdict.reason, level: 'confirm', events: [e], at: this.h.now, shown: false, media: verdict.media && { ...verdict.media, files: [...verdict.media.files] } };
      this.cards.push(card);
      const c = card;
      // A media card is drawn after one quiet second, so tokens arriving together share it.
      setTimeout(() => { if (this.cards.includes(c)) { c.shown = true; this.onCard?.(c); } }, verdict.row === 'media-delete' ? this.quietMs : 0);
    }
    const c = card;
    return new Promise((ok) => {
      const ws = this.#waits.get(c.id) ?? []; ws.push({ ok }); this.#waits.set(c.id, ws);
      unref(setTimeout(() => { if (this.cards.includes(c)) this.answer(c.id, 'gone'); }, this.cardWaitMs));
    });
  }
  /** The person's answer to a card. An Allow of media deletes covers only its files and servers, for 10 minutes; a
   *  Confirm allowed on a list is that site's last-approved version of it. */
  answer(id: number, a: 'allow' | 'decline' | 'gone') {
    const c = this.cards.find((x) => x.id === id); if (!c) return;
    this.cards = this.cards.filter((x) => x !== c);
    if (a === 'decline') this.#declined(c.owner, c.row);
    if (a === 'allow' && c.media) this.allows.push({ owner: c.owner, files: new Set(c.media.files), servers: c.media.servers === '*' ? '*' : new Set(c.media.servers), until: this.h.now + ALLOW_S });
    if (a === 'allow') this.#approved.set(c.owner, new Set([...(this.#approved.get(c.owner) ?? []), ...c.events.map((e) => (e as any).id).filter(Boolean)]));
    for (const w of this.#waits.get(id) ?? []) w.ok(a);
    this.#waits.delete(id);
  }
  #approved = new Map<string, Set<string>>();
  #allowed(owner: string, files: string[], server: string | null) {
    this.allows = this.allows.filter((x) => x.until > this.h.now);
    return this.allows.some((x) => x.owner === owner && files.every((f) => x.files.has(f)) && (x.servers === '*' || (server !== null && x.servers.has(server))));
  }
  /** A decline by the person (a card's Decline, or an Undo of the site's change). */
  declinedBy(owner: string, row: string) { this.#declined(owner, row); }
  #declined(owner: string, row: string) { const q = (this.declines.get(owner) ?? []).filter((d) => this.h.now - d.at < HOUR); q.push({ at: this.h.now, row }); this.declines.set(owner, q); }
  #autoDeclined(owner: string, row: string) {
    const q = (this.declines.get(owner) ?? []).filter((d) => this.h.now - d.at < HOUR);
    return q.length >= 6 || q.filter((d) => d.row === row).length >= 3;
  }

  // The 10-second wait on a single deletion (§3): signed once it passes, unless Undo was tapped first.
  #undoWait(e: Unsigned): Promise<boolean> {
    const key = JSON.stringify(e.tags);
    return new Promise((ok) => {
      const t = setTimeout(() => { this.#undos.delete(key); ok(true); }, this.undoMs);
      this.#undos.set(key, () => { clearTimeout(t); this.#undos.delete(key); ok(false); });
    });
  }
  /** Deletions waiting their 10 seconds (the notification's Undo). */
  pendingUndos() { return [...this.#undos.keys()]; }
  /** Undo a waiting deletion: it is never signed, and counts as the person's decline (§6). */
  undoPending(key: string, owner?: string) { const f = this.#undos.get(key); if (!f) return false; f(); if (owner) this.#declined(owner, 'delete-one'); return true; }

  /** After an event was signed for `owner` (a grant, or `member`): the history takes it, and the records say what it
   *  did: which grant it was signed for, the deletions, the removal logs, the pre-site and approved versions. */
  async signed(e: NostrEvent, owner: string, o: { approved?: boolean } = {}) {
    const all = this.h.ledger();
    const a = isReplaceable(e.kind) ? addrOf(e) : null;
    const prev = a ? this.h.history.current(a) : null;
    const approvedNow = !!o.approved || !!this.#approved.get(owner)?.delete(e.id);
    let removed: string[] = [], added: string[] = [];
    const judgedList = a && judged(e.kind) && owner !== 'member';
    if (judgedList) {
      const before = prev ? (e.kind === PROFILE ? filled(prev.content) : await itemsOf(prev, this.h.decrypt)) : new Set<string>();
      const after = e.kind === PROFILE ? filled(e.content) : await itemsOf(e, this.h.decrypt);
      if (before && after) { removed = [...before].filter((x) => !after.has(x)); added = [...after].filter((x) => !before.has(x)); }
    }
    const n = e.kind === 5 ? deletionTargets(e as Ev) : 0;
    const wallet = n > 0 && e.tags.filter((t) => t[0] === 'e').every((t) => [7375, 7376, 7374].includes(this.h.history.get(t[1])?.kind ?? -1)) && !e.tags.some((t) => t[0] === 'a');
    if (judgedList && prev && !all.presiteOf(owner, a!)) this.h.history.pin(prev);
    this.h.record((led) => {
      led.sign(e.id, owner);
      if (e.kind === 5) led.del({ at: this.h.now, owner, n, single: n === 1, wallet, approved: !!o.approved });
      if (judgedList) {
        if (prev && !all.presiteOf(owner, a!)) led.setPresite(owner, a!, prev.id);
        if (approvedNow) led.approve(owner, a!, e.id, this.h.now);
        led.log('removed', owner, a!, removed, this.h.now);
        led.log('added', owner, a!, added, this.h.now);
      }
    });
    this.h.history.take(e, true);
    this.h.persist();
  }

  dump() { return { declines: [...this.declines], allows: this.allows.map((x) => ({ ...x, files: [...x.files], servers: x.servers === '*' ? '*' : [...x.servers] })) }; }
  load(x: any) {
    this.declines = new Map(x?.declines ?? []);
    this.allows = (x?.allows ?? []).map((a: any) => ({ ...a, files: new Set(a.files), servers: a.servers === '*' ? '*' : new Set(a.servers) }));
  }
  clear() { this.cards = []; this.declines.clear(); this.allows = []; for (const ws of this.#waits.values()) for (const w of ws) w.ok('gone'); this.#waits.clear(); for (const f of this.#undos.values()) f(); }
}

/** §3 Undo's date: one second after the newest version and after any deletion naming it, or now if later. */
export function undoDate(h: History, addr: string, now: number, ids: string[] = []): number {
  const newest = h.current(addr)?.created_at ?? 0;
  const del = Math.max(h.deletedAt.get(addr) ?? 0, ...ids.map((i) => h.deletedAt.get(i) ?? 0));
  return Math.max(now, newest + 1, del + 1);
}
/** Undo, rebased drafts and the person's own edits stay within 9 minutes ahead; past that they wait. */
export const UNDO_AHEAD_S = 540;
export { KeykinError };
