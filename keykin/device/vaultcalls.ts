// The device calls for vault apps on the same machine (Doors 20 §3.7; ~/nostr-sync-nip/vaults.md draft 7.13 §4.5,
// §12.2–12.3). An app gets them once the person has granted it all three open domains together, one hand-grant
// question for the set ("Let *Notes* use all your vaults, in every app, on this device?"):
//
//   ksig(app, root)                 the device's member-key signature of a vault root, domain nostr-vault/ksig/1
//   derive(app, ids, domain, bytes) dataKeys.derive under nostr-vault/owner/1 or nostr-vault/keyring/1
//   current(app), states(app)       which state to write under, and which this device has held (never a key)
//   sign(app, event)                kinds 4810, 4811 and 30811, each a normal co-signed round; kind 5 only when every
//                                   target is one of those by the account, judged by Device policy like any deletion
//   invite(app, rumor, recipient)   a kind-4812 rumor by the account, sealed (kind 13) and gift-wrapped (kind 1059) by
//                                   the device itself: the app never gets an encrypt call nor makes a seal
//   unwrap(app, wrap)               a gift wrap answered only for a kind-4812 rumor whose seal signer is its pubkey,
//                                   with the seal's pubkey
//   decrypt(app, peer, payload)     NIP-44 as the account, answered only for a vault payload (an object with `vault`
//                                   and `keys`, `keys_ref`, `secret`, `inboxes` or `genesis`)
//
// So a vault app gets vault material and nothing else of the account's: no DMs, no other private data. A rumor is
// never answered by `decrypt`, even a vault-shaped one (nor an object with an event's `kind` and `content`): an invitation's seal content reaches an app only through
// `unwrap`, with its signer check. The grant is this device's only, kept with the device and cleared by a wipe; the
// app id is whatever the platform vouches for (on Android, the calling uid's package and signing certificate). The
// open domains, once registered for a grant, stay registered for the process: they are open to every vault app by
// design (core 14.21 §5.9), and a call still needs the app's grant (review 22 L6).

import { KeykinError, refuse, randomBytes, strictJson } from '../src/bytes.ts';
import { eventId, eventShape, verifyEvent, type NostrEvent, type Unsigned } from '../src/event.ts';
import { finalizeEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { VAULT_KINDS, KIND_VAULT_INVITE, vaultPayload } from './doors.ts';
import { registerDomain } from './membersig.ts';
import { KIND_SEAL, KIND_WRAP_STORED } from '../src/transport.ts';
import type { DeviceNode } from './node.ts';

export const KSIG_DOMAIN = 'nostr-vault/ksig/1';
/** The open domains a vault app may derive under (core 14.21 §5.9). */
export const VAULT_DERIVE_DOMAINS = new Set(['nostr-vault/owner/1', 'nostr-vault/keyring/1']);
/** NIP-59: a seal's and a wrap's created_at is up to two days in the past, so it says nothing of when it was made. */
const TWO_DAYS = 2 * 24 * 3600;
const HEX64 = /^[0-9a-f]{64}$/;
/** Per app and hour (review 22 M2), as NIP-55's grants: signatures (invitations' seals included), and decrypts and
 *  unwraps, each an ECDH round with a co-signer. */
export const VAULT_SIGNS_PER_HOUR = 60, VAULT_OPENS_PER_HOUR = 300;
/** Kind 5's `a` target: exactly `<vault kind>:<account>:<d>` (review 22 L7). */
const VAULT_ADDR = /^(4810|4811|30811):([0-9a-f]{64}):/;

const no = (why: string): never => { throw new KeykinError('declined', why); };

export class VaultCalls {
  readonly d: DeviceNode;
  /** The apps granted the three open domains, by app id. */
  apps = new Set<string>();
  /** Apps the person said "Don't allow" to, remembered until they change it (review 22 L7). */
  declined = new Set<string>();
  #used = new Map<string, { at: number; signs: number; opens: number }>();
  constructor(d: DeviceNode) { this.d = d; }

  /** The person said yes to the one question for the set. */
  allow(app: string) {
    if (typeof app !== 'string' || !app || app.length > 256) refuse('malformed', 'an app id');
    if (this.d.wiped) refuse('wiped');
    for (const x of VAULT_DERIVE_DOMAINS) registerDomain(x);
    this.apps.add(app); this.declined.delete(app); this.d.persist();
  }
  /** "Don't allow": the app isn't asked about again until the person changes it. */
  decline(app: string) { if (typeof app === 'string' && app) { this.apps.delete(app); this.declined.add(app); this.d.persist(); } }
  /** The person changed it: no grant, and the app may ask again. */
  revoke(app: string) { if (this.apps.delete(app) || this.declined.delete(app)) this.d.persist(); }
  mayAsk(app: string) { return !this.apps.has(app) && !this.declined.has(app); }
  allowed(): string[] { return [...this.apps].sort(); }
  #need(app: string) {
    if (this.d.wiped) refuse('wiped');
    if (!this.apps.has(app)) no('this app hasn\'t been granted your vaults on this device');
  }
  #spend(app: string, what: 'signs' | 'opens') {
    const u = this.#used.get(app);
    const cur = u && this.d.now - u.at < 3600 ? u : { at: this.d.now, signs: 0, opens: 0 };
    if (cur[what] >= (what === 'signs' ? VAULT_SIGNS_PER_HOUR : VAULT_OPENS_PER_HOUR)) refuse('try-later', 'too many requests from this app this hour');
    cur[what]++; this.#used.set(app, cur);
  }

  ksig(app: string, root: Uint8Array): { mk: string; ksig: string } {
    this.#need(app);
    if (!(root instanceof Uint8Array) || root.length !== 32) refuse('malformed', 'a vault root is 32 bytes');
    const { sig, key } = this.d.signAsMember(KSIG_DOMAIN, root);
    return { mk: key, ksig: sig };
  }

  derive(app: string, ids: string[], domain: string, bytes: Uint8Array): Uint8Array {
    this.#need(app);
    if (!VAULT_DERIVE_DOMAINS.has(domain)) no('a vault app derives only under nostr-vault/owner/1 and nostr-vault/keyring/1');
    return this.d.dataKeys.derive(ids, domain, bytes);
  }
  current(app: string) { this.#need(app); return this.d.dataKeys.forApps().current(); }
  states(app: string) { this.#need(app); return this.d.dataKeys.forApps().states(); }

  /** Kinds 4810, 4811 and 30811 as a normal co-signed round; a kind 5 of only those, by the account, through Device
   *  policy. Held (by Device policy or a co-signer's approval) is declined: a vault app has no held events. */
  async sign(app: string, ev: Partial<Unsigned>): Promise<NostrEvent> {
    this.#need(app);
    const kind = Number(ev?.kind);
    if (!VAULT_KINDS.has(kind) && kind !== 5) no('a vault app gets signatures for kinds 4810, 4811 and 30811 only');
    this.#spend(app, 'signs');
    // An event core §5.8 or Device policy would hold has no way to the person from a vault app: declined, not a
    // try-later the app would retry forever (review 22 M1).
    const held = (e: unknown): never => { if ((e as KeykinError).code === 'needs_approval') no('this would need your approval on your phone; vault apps get no held events'); throw e; };
    if (VAULT_KINDS.has(kind)) return this.d.sign({ ...ev, created_at: ev.created_at ?? this.d.now }, { owner: `vault:${app}` }).catch(held);
    const tags: string[][] = Array.isArray(ev.tags) ? ev.tags : [];
    await this.#vaultTargets(tags);
    const e: Unsigned = { pubkey: this.d.g, created_at: ev.created_at ?? this.d.now, kind: 5, tags, content: ev.content ?? '' };
    eventShape({ ...e, id: '0'.repeat(64) }, 'rumor');
    const owner = `vault:${app}`;
    const r = await this.d.guard.serve(e, owner, ['sign-in', 'post'], () => this.d.sign(e, { owner })).catch(held);
    if ('signed' in r) return r.signed;
    if ('error' in r) { const [code, ...why] = r.error.split(': '); throw new KeykinError(code === 'try-later' ? 'try-later' : 'declined', why.join(': ') || r.error); }
    return no('Device policy holds this deletion; vault apps get no held events');
  }
  /** Every target of a deletion is a 4810, 4811 or 30811 by the account: by `e` (its kind known to this device or
   *  fetched), by `a` (kind and pubkey in the address), and `k` only naming those kinds. At least one target. */
  async #vaultTargets(tags: string[][]) {
    const g = this.d.g, es: string[] = [];
    let n = 0;
    for (const t of tags) {
      if (!Array.isArray(t) || typeof t[1] !== 'string') continue;
      if (t[0] === 'k' && !VAULT_KINDS.has(Number(t[1]))) no('a deletion of something other than vault machinery');
      if (t[0] === 'a') {
        const m = VAULT_ADDR.exec(t[1]);
        if (!m || m[2] !== g) no('a deletion of something other than the account\'s vault machinery');
        n++;
      }
      if (t[0] === 'e') { if (!HEX64.test(t[1])) no('an e target is a lowercase event id'); es.push(t[1]); n++; }
    }
    if (!n) no('a deletion with no target');
    const unknown = es.filter((id) => !this.d.history.get(id));
    const found = new Map((unknown.length ? await this.d.lookupEvents(unknown, []) : []).map((x) => [x.id, x]));
    for (const id of es) {
      const x = this.d.history.get(id) ?? found.get(id);
      if (!x) refuse('try-later', 'this device can\'t see one of the events to delete');
      if (x!.pubkey !== g || !VAULT_KINDS.has(x!.kind)) no('a deletion of something other than the account\'s vault machinery');
    }
  }

  /** NIP-59 by the account: the rumor (kind 4812, pubkey the account) encrypted to `recipient` in a kind-13 seal the
   *  account signs, wrapped in a kind 1059 from a one-time key. Returns the wrap, for the app to publish. */
  async invite(app: string, rumor: Partial<Unsigned> & { id?: string }, recipient: string): Promise<NostrEvent> {
    this.#need(app);
    if (typeof recipient !== 'string' || !HEX64.test(recipient)) refuse('malformed', 'recipient');
    if (rumor?.kind !== KIND_VAULT_INVITE) no('an invitation is a kind-4812 rumor');
    if (rumor.pubkey !== this.d.g) no('an invitation is by this account');
    if ('sig' in (rumor as object)) no('a rumor is unsigned');
    // Exactly a rumor's fields, none filled in (review 22 L7: as Kotlin's Event.shape).
    const { id: given, ...fields } = rumor as any;
    eventShape({ ...fields, id: '0'.repeat(64) }, 'rumor');
    const r: Unsigned = { pubkey: this.d.g, created_at: fields.created_at, kind: KIND_VAULT_INVITE, tags: fields.tags, content: fields.content };
    const id = eventId(r);
    if (given !== undefined && given !== id) refuse('malformed', 'the rumor id differs from its fields');
    this.#spend(app, 'signs');
    const content = await this.d.nip44(recipient, JSON.stringify({ ...r, id }), true, { owner: `vault:${app}` });
    const seal = await this.d.sign({ kind: KIND_SEAL, created_at: this.#past(), tags: [], content }, { owner: `vault:${app}` });
    const eph = randomBytes(32);
    return finalizeEvent({ kind: KIND_WRAP_STORED, created_at: this.#past(), tags: [['p', recipient]],
      content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(eph, recipient)) }, eph) as NostrEvent;
  }
  #past() { const k = new Uint32Array(randomBytes(4).buffer)[0] % TWO_DAYS; return this.d.now - k; }

  /** A gift wrap to the account, answered only when it holds a kind-4812 rumor whose seal is signed by the rumor's
   *  pubkey: the rumor and the seal's pubkey (vaults.md §4.5's same-npub check). Anything else is refused without
   *  saying what it held. */
  async unwrap(app: string, wrap: NostrEvent): Promise<{ rumor: Unsigned & { id: string }; seal: string }> {
    this.#need(app);
    this.#spend(app, 'opens');
    const nope = (): never => no('not a vault invitation');
    if (wrap?.kind !== KIND_WRAP_STORED || !verifyEvent(wrap)) nope();
    // A co-signer that can't be reached is said as such; anything that doesn't open is just "not an invitation".
    let seal: NostrEvent, rumor: any;
    await this.d.ecdhX(wrap.pubkey);
    try { seal = strictJson(await this.d.nip44(wrap.pubkey, wrap.content, false)); } catch { return nope(); }
    if (seal?.kind !== KIND_SEAL || !verifyEvent(seal) || !HEX64.test(seal.pubkey)) nope();
    await this.d.ecdhX(seal!.pubkey);
    try { rumor = strictJson(await this.d.nip44(seal!.pubkey, seal!.content, false)); eventShape(rumor, 'rumor'); } catch { return nope(); }
    if (rumor.kind !== KIND_VAULT_INVITE || rumor.pubkey !== seal!.pubkey || eventId(rumor) !== rumor.id) nope();
    return { rumor, seal: seal!.pubkey };
  }

  /** NIP-44 as the account with `peer`, answered only when the plaintext is a vault payload. */
  async decrypt(app: string, peer: string, payload: string): Promise<string> {
    this.#need(app);
    this.#spend(app, 'opens');
    await this.d.ecdhX(peer);
    let plain: string;
    try { plain = await this.d.nip44(peer, payload, false); } catch { return no('not a vault payload'); }
    if (!vaultPayload(plain)) no('not a vault payload');
    return plain;
  }

  /** As Kotlin keeps it (review 22 L2): `{apps, declined}`. */
  dump() { return { apps: [...this.apps], declined: [...this.declined] }; }
  load(x: any) {
    const strs = (a: unknown) => (Array.isArray(a) ? a.filter((v) => typeof v === 'string') : []);
    this.apps = new Set(Array.isArray(x) ? strs(x) : strs(x?.apps)); this.declined = new Set(strs(x?.declined));
    if (this.apps.size) for (const d of VAULT_DERIVE_DOMAINS) registerDomain(d);
  }
  clear() { this.apps.clear(); this.declined.clear(); this.#used.clear(); }
}
