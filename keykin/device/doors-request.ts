// A site's request, whatever door it came through (Doors §1–§2, Device policy §2–§4): the one place that decides what
// a site gets. The NIP-46 home (device/nip46.ts) answers its transport's own methods (connect, ping, relays, logout)
// and hands everything else here with its grant as the caller; the extension's NIP-07 door calls
// `dev.doors.request(entryId, method, params)` for a grant in the account's grant store. Both go through the same
// checks: freshness and a grant ended elsewhere; the account's machinery and vault material refused (siteGuard,
// vaultPlaintext); the scope each request needs (scopesForEvent, scopeForDecrypt); a held list's pending change;
// Device policy's verdict (guard.serve, with the grant as owner); Held events kept for the person; and to-self
// encryptions budgeted and recorded as the grant's evidence.

import { KeykinError, strictJson } from '../src/bytes.ts';
import { siteEvent } from '../src/event.ts';
import type { DeviceNode } from './node.ts';
import { siteGuard, vaultPlaintext } from './doors.ts';
import { scopesForEvent, scopeForDecrypt, expired, type Scope } from './grants.ts';

const HELD_PER_GRANT = 8, HELD_MAX = 64, HELD_TTL_S = 7 * 86400;
const SELF_ENCRYPTS_PER_HOUR = 300;
/** A replaceable or addressable event's list: kind, and `d` for addressable kinds. */
export const listKey = (e: any): string | null => {
  const k = e?.kind;
  if (!Number.isSafeInteger(k)) return null;
  if (k === 0 || k === 3 || (k >= 10000 && k < 20000)) return `${k}`;
  if (k >= 30000 && k < 40000) return `${k}:${(e.tags ?? []).find((t: string[]) => t[0] === 'd')?.[1] ?? ''}`;
  return null;
};

export type DoorAnswer = { result?: string; error?: string };
/** Who is asking: a grant in the account's grant store, held by a door. `key` names the asker for asks, held events
 *  and budgets (the NIP-46 signer key, or the entry id for a door without one). */
export interface DoorCaller {
  entry: string | null;
  key: string;
  /** Whether the grant holds `scope` now; a door records an unanswered ask itself (shown to the person). */
  has(scope: Scope): boolean;
  /** Keep a Held event for the person (approved with the lock, or a hold's wait); the answer the site gets. */
  hold(event: any): DoorAnswer;
  /** Whether a change to the list `lk` is held and waiting (Device policy §4: the site's next change to it waits). */
  heldWaiting(lk: string): boolean;
  /** The grant ended on another device (a tombstone, a removal): the door ends its side. */
  ended?(): Promise<void> | void;
  /** On the helper (Helper module §2): only the helper kinds, and no person to ask. */
  helper?: boolean;
}
type Held = { id: string; holder: string; event: any; at: number; wait: string | null };

export class DoorRequests {
  readonly d: DeviceNode;
  constructor(d: DeviceNode) { this.d = d; }
  /** Scopes a grant asked for and the person hasn't answered, by entry: a door without a home of its own shows them. */
  asks = new Map<string, Set<Scope>>();
  /** Held events of doors without a home of their own (the extension), by event id. */
  held = new Map<string, Held>();
  #crypt = new Map<string, number[]>();

  /** A door's request for grant `entryId` (the extension's NIP-07): its scopes from the grant store, its asks and held
   *  events kept here. */
  async request(entryId: string, method: string, params: unknown[]): Promise<DoorAnswer>;
  async request(caller: DoorCaller, method: string, params: unknown[]): Promise<DoorAnswer>;
  async request(c: string | DoorCaller, method: string, params: unknown[]): Promise<DoorAnswer> {
    return this.answer(typeof c === 'string' ? this.callerFor(c) : c, method, Array.isArray(params) ? params : []);
  }
  /** The caller for a grant in the grant store with no home of its own. */
  callerFor(entryId: string): DoorCaller {
    return {
      entry: entryId, key: entryId,
      has: (scope) => {
        const e = this.d.grants.own.get(entryId);
        if (e && e.scopes.includes(scope) && !expired(e, this.d.now, this.d.grants.lastUsed.get(e.id))) { this.d.grants.used(e.id); return true; }
        const a = this.asks.get(entryId) ?? new Set<Scope>(); a.add(scope); this.asks.set(entryId, a); this.d.persist();
        return false;
      },
      hold: (event) => this.#hold(entryId, event),
      heldWaiting: (lk) => [...this.held.values()].some((x) => x.wait && listKey(x.event) === lk),
      ended: () => { this.asks.delete(entryId); for (const [k, h] of this.held) if (h.holder === entryId) this.held.delete(k); this.d.persist(); },
    };
  }
  #hold(holder: string, event: any): DoorAnswer {
    for (const [k, h] of this.held) if (this.d.now - h.at > HELD_TTL_S) this.held.delete(k);
    if (![...this.held.values()].some((x) => x.event.id === event.id)) {
      if ([...this.held.values()].filter((x) => x.holder === holder).length >= HELD_PER_GRANT || this.held.size >= HELD_MAX) return { error: 'try-later: too many events waiting for you' };
      this.held.set(event.id, { id: event.id, holder, event, at: this.d.now, wait: null }); this.d.persist();
    }
    return { error: 'held: approve on your phone' };
  }
  /** The person allowed `scope` for a door's grant (asked the first time it was needed). */
  allowScope(entryId: string, scope: Scope) {
    if (!this.d.grants.own.has(entryId)) throw new KeykinError('unknown_grant');
    this.d.grants.widen(entryId, [scope]); this.asks.get(entryId)?.delete(scope); this.d.persist(); this.d.publishGrantsSoon();
  }
  /** At most 300 to-self encryptions an hour per grant: each becomes a metadata record (review 17 H2). */
  #budget(key: string): boolean {
    const q = (this.#crypt.get(key) ?? []).filter((t) => this.d.now - t < 3600);
    if (q.length >= SELF_ENCRYPTS_PER_HOUR) { this.#crypt.set(key, q); return false; }
    q.push(this.d.now); this.#crypt.set(key, q); return true;
  }
  #backupKeys() { const m = this.d.m!; return [...new Set([m.backupKey, ...m.accepted.filter((p) => p.type === 'paper').map((p) => (p.c.change as any).paper.key)].filter(Boolean) as string[])]; }

  async answer(c: DoorCaller, method: string, params: any[]): Promise<DoorAnswer> {
    const now = this.d.now;
    const ask = (scope: Scope) => ({ error: `permission: ${scope} needs your OK on your phone` });
    // Doors §2: never on old news. A device that hasn't caught up within 30 seconds does first (a site signed out
    // elsewhere is then refused here), waiting at most 5 seconds for it: a site gives up on its request at about 30.
    await this.d.catchUp();
    // A grant ended on another device (a tombstone, a removal) ends here too.
    if (c.entry && !c.helper && !this.d.grants.own.has(c.entry)) { await c.ended?.(); return { error: 'revoked: this site was disconnected' }; }
    if (!c.entry && !c.helper) return { error: 'not-connected: connect first' };
    const owner = `${this.d.kp.pub}:${c.entry}`;
    try {
      switch (method) {
        case 'get_public_key': return c.has('sign-in') ? { result: this.d.g } : ask('sign-in');
        case 'sign_event': {
          const ev = strictJson(String(params[0]));
          siteGuard({ kind: ev?.kind, tags: Array.isArray(ev?.tags) ? ev.tags : [] }, this.d.g, this.#backupKeys(), this.d.protectedIds, (id) => this.d.history.get(id)?.kind);
          const needs = scopesForEvent(Number(ev?.kind), Array.isArray(ev?.tags) ? ev.tags : [], null);
          if (needs === 'declined') return { error: 'declined: a deletion by token, or a token for no host, is never a site\'s to get signed' };
          for (const n of needs) if (!c.has(n)) return ask(n);
          // Device policy §4: while a hold for this list is pending, a site's changes to it wait (review 12 H3), any
          // site's, not only the one whose change is held (review 18 L9).
          const lk = listKey(ev);
          if (lk && c.heldWaiting(lk)) return { error: 'try-later: a held change to this list is waiting' };
          const event = siteEvent({ ...ev, created_at: ev?.created_at ?? now }, this.d.g);
          // The helper has no person to ask: it signs only the helper kinds, which the co-signers enforce (Helper §2).
          if (c.helper) return { result: JSON.stringify(await this.d.sign(event, { owner: `helper:${c.key}` })) };
          // Device policy §2: judged first. A Confirm waits for the person's answer, a single deletion 10 seconds for an
          // Undo; a site's deletions and list changes one at a time (review 18 M1). Signed for this grant: the evidence
          // records who got each ciphertext signed (review 17 M1).
          try {
            const r = await this.d.guard.serve(event, owner, (c.entry ? this.d.grants.own.get(c.entry)?.scopes : undefined) ?? [], () => this.d.sign(event, { owner }));
            if ('signed' in r) return { result: JSON.stringify(r.signed) };
            if ('error' in r) return { error: r.error };
          } catch (err) {
            if ((err as KeykinError).code !== 'needs_approval') throw err;
            // A server's demand the device's own check doesn't explain: Held only when two servers demand it (§2).
            if (((err as any).demands ?? 0) < 2) return { error: 'try-later: a server asked for an approval; try again later' };
          }
          // Held (Doors §3.3, Device policy §4, review 11 L4): kept for the person, who approves it with the lock or
          // lets a hold's wait pass; the result is published, not returned.
          return c.hold(event);
        }
        case 'nip44_encrypt': case 'nip04_encrypt': case 'nip44_decrypt': case 'nip04_decrypt':
          if (c.helper) return { error: 'unsupported: the helper can\'t encrypt or decrypt' };
          return await this.#crypto(c, owner, method, params);
        default: return { error: `unsupported: ${method}` };
      }
    } catch (err) {
      const code = (err as KeykinError).code;
      if (c.helper && (code === 'helper_kind' || code === 'needs_approval' || code === 'declined')) return { error: 'declined: ask on your phone' };
      if (code === 'needs_approval' || code === 'hold_not_passed') return { error: 'held: approve on your phone' };
      if (code === 'declined') return { error: `declined: ${(err as Error).message.replace(/^declined: /, '') || 'not allowed for this site'}` };
      if (code === 'unreachable' || code === 'no_server' || code === 'no_answer') return { error: 'try-later: no server answered' };
      return { error: `declined: ${code ?? 'refused'}` };
    }
  }

  async #crypto(c: DoorCaller, owner: string, method: string, params: any[]): Promise<DoorAnswer> {
    const ask = (scope: Scope) => ({ error: `permission: ${scope} needs your OK on your phone` });
    switch (method) {
      case 'nip44_encrypt': case 'nip04_encrypt': {
        // Encrypting to the account's own key is `post`; to anyone else, `dms`.
        const peer = String(params[0]);
        // Doors 20 §2: no door encrypts a vault invitation or vault payload for a site.
        if (vaultPlaintext(String(params[1]))) return { error: 'declined: vault material is the vault apps\' own' };
        const self = peer.toLowerCase() === this.d.g;
        if (!c.has(self ? 'post' : 'dms')) return ask(self ? 'post' : 'dms');
        if (self && !this.#budget(c.key)) return { error: 'try-later: too many encryptions; wait a while' };
        // An encryption to self is recorded for this grant: evidence for its later decrypts (Device policy §1).
        return { result: method === 'nip44_encrypt' ? await this.d.nip44(peer, String(params[1]), true, { owner }) : await this.d.nip04(peer, String(params[1]), true) };
      }
      case 'nip44_decrypt': case 'nip04_decrypt': {
        const peer = String(params[0]);
        if (!/^[0-9a-fA-F]{64}$/.test(peer)) return { error: 'declined: a peer key is 32 bytes of hex' };
        // With someone else's key, `dms`. To the account itself: decrypted here first, released only under the scope
        // its plaintext needs (lists, wallet, dms for its own NIP-17 copies, private-data otherwise).
        if (peer.toLowerCase() !== this.d.g) {
          if (!c.has('dms')) return ask('dms');
          const text = method === 'nip44_decrypt' ? await this.d.nip44(peer, String(params[1]), false) : await this.d.nip04(peer, String(params[1]), false);
          // Doors 20 §2: never a vault invitation or vault secret to a site, under any scope (a `dms` client included).
          return vaultPlaintext(text) ? { error: 'declined: vault material reaches a site only through the vault API' } : { result: text };
        }
        // A grant holding none of the to-self scopes is refused before any round (review 16 M9).
        const e = c.entry ? this.d.grants.own.get(c.entry) : undefined;
        if (!e?.scopes.some((x) => ['lists', 'wallet', 'private-data', 'dms'].includes(x))) { c.has('private-data'); return { error: 'permission: needs your OK on your phone' }; }
        const plain = method === 'nip44_decrypt' ? await this.d.nip44(this.d.g, String(params[1]), false) : await this.d.nip04(this.d.g, String(params[1]), false);
        const need = scopeForDecrypt(this.d.g, peer.toLowerCase(), plain, method === 'nip44_decrypt' ? { payload: String(params[1]), evidence: this.d.evidence, owner } : {});
        if (need === 'malformed') return { error: 'declined: not a canonical payload' };
        // One message for every class, so a refusal never says what the ciphertext is (review 16 M9).
        if (vaultPlaintext(plain)) return { error: 'declined: vault material reaches a site only through the vault API' };
        return c.has(need) ? { result: plain } : { error: 'permission: needs your OK on your phone' };
      }
      default: return { error: `unsupported: ${method}` };
    }
  }

  dump() { return { asks: [...this.asks].map(([k, v]) => [k, [...v]]), held: [...this.held.values()] }; }
  load(x: any) {
    this.asks = new Map((Array.isArray(x?.asks) ? x.asks : []).map(([k, v]: [string, Scope[]]) => [k, new Set(v)]));
    this.held = new Map((Array.isArray(x?.held) ? x.held : []).map((h: Held) => [h.id, h]));
  }
  clear() { this.asks.clear(); this.held.clear(); this.#crypt.clear(); }
}
