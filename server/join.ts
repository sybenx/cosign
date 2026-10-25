// Who may make an account with this server: the "Who can join" choice on its page.
//
// Four modes, kept in host.json as `enroll`:
//
//   owner    Only me. Nobody enrolls except with a code from this server's page (§9.6).
//   follows  People I follow: an npub in the owner's follow list (kind 3), proved.
//   invite   People I invite: an npub on the list here, proved. (A device key on the
//            list still works, as it did before there were proofs.)
//   open     Anyone.
//
// Announcements (§9.5) carry only "open" or "invite", so the spec and every client stay
// as they are: the first three announce themselves as "invite".
//
// A code from the page works in every mode, and it is the only way in `owner`. That is
// also how a brand-new account joins a `follows` or `invite` server: a key that doesn't
// exist yet has no npub to prove, so the proof is for someone bringing an account they
// already have ("Add a server").

import { verifyEvent, type Event } from 'nostr-tools/pure';
import type { Filter } from 'nostr-tools/filter';

export type Mode = 'owner' | 'follows' | 'invite' | 'open';
export const MODES: Mode[] = ['owner', 'follows', 'invite', 'open'];
export const modeOf = (v: unknown): Mode => (MODES as unknown[]).includes(v) ? v as Mode : 'invite';
/** What §9.5 announcements and clients see: only these two exist on the wire. */
export const announced = (m: Mode) => m === 'open' ? 'open' : 'invite';
export const modeName = (m: Mode) =>
  ({ owner: 'only me', follows: 'people I follow', invite: 'people I invite', open: 'anyone' })[m];

// --- Proving an npub -------------------------------------------------------------------
//
// A device enrolls with its own fresh key, which says nothing about who holds it. To
// enroll as someone the owner follows or invited, it carries a `proof`: a kind 27235
// event (NIP-98 shaped) signed by that npub, naming this server and this device key. It
// is good for five minutes and for that device only, so one seen on a relay is of no use
// to anyone else.

export const PROOF_KIND = 27235;
export const proofFor = (hostPk: string) => `cosign:server?pk=${hostPk}`;
const PROOF_LIFE = 300;

/** What a device signs (with the account it already has) to prove whose it is. */
export const proofTemplate = (hostPk: string, devicePk: string, nowSec: number) => ({
  kind: PROOF_KIND, created_at: nowSec, content: '',
  tags: [['u', proofFor(hostPk)], ['method', 'ENROLL'], ['p', devicePk]],
});

/** The npub a proof is good for, or null. */
export function proofNpub(proof: unknown, hostPk: string, devicePk: string, nowSec: number): string | null {
  const e = proof as Event;
  if (!e || typeof e !== 'object' || e.kind !== PROOF_KIND || !Array.isArray(e.tags)) return null;
  if (Math.abs(nowSec - Number(e.created_at)) > PROOF_LIFE) return null;
  const tag = (k: string) => e.tags.find(t => Array.isArray(t) && t[0] === k)?.[1];
  if (tag('u') !== proofFor(hostPk) || tag('p') !== devicePk) return null;
  // Only these fields, as a plain event: nothing else it carries can stand in for the
  // signature (nostr-tools marks an event it has verified on the object itself).
  const plain = { id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig };
  try { if (!verifyEvent(plain as Event)) return null; } catch { return null; }
  return plain.pubkey;
}

// --- The owner's follow list -----------------------------------------------------------

type Query = (relays: string[], filter: Filter, ms: number) => Promise<Event[]>;

/**
 * Who the owner follows, from their newest kind 3 on these relays, kept for ten minutes.
 * The owner is always in it. When the relays say nothing, the last list stands (and
 * nothing is remembered, so the next ask tries again).
 */
export function followList(query: Query) {
  const cache = new Map<string, { at: number; set: Set<string> }>();
  return async (owner: string, relays: string[], now: number): Promise<Set<string>> => {
    const had = cache.get(owner);
    if (had && now - had.at < 10 * 60_000) return had.set;
    const got = await query(relays, { kinds: [3], authors: [owner] }, 4000).catch(() => []);
    const newest = got.sort((a, b) => b.created_at - a.created_at)[0];
    if (!newest) return had?.set ?? new Set([owner]);
    const set = new Set([owner, ...newest.tags.filter(t => t[0] === 'p' && /^[0-9a-f]{64}$/.test(t[1])).map(t => t[1])]);
    cache.set(owner, { at: now, set });
    return set;
  };
}

// --- The decision ----------------------------------------------------------------------

export interface Ask {
  mode: Mode;
  /** A live one-time code from this server's page: in every mode, that is enough. */
  code: boolean;
  hostPk: string;
  /** The key the device is enrolling with, and what it signed to say whose it is. */
  devicePk: string;
  proof?: unknown;
  invites: string[];
  owner?: string;
  relays: string[];
  now: number;
}

export type Verdict = { ok: true; as: string | null } | { ok: false; reason: string };

const WHO = { follows: 'the people its owner follows', invite: 'the people it invited' } as const;

export async function mayJoin(a: Ask, follows: ReturnType<typeof followList>): Promise<Verdict> {
  if (a.code) return { ok: true, as: null };
  if (a.mode === 'open') return { ok: true, as: null };
  if (a.mode === 'owner')
    return { ok: false, reason: 'not-invited: This server takes on accounts for the person who runs it. Open its page for a code.' };
  // The old way, from before proofs: the enrolling key itself on the invite list.
  if (a.mode === 'invite' && a.invites.includes(a.devicePk)) return { ok: true, as: null };
  const who = WHO[a.mode];
  if (a.proof === undefined)
    return { ok: false, reason: `proof-needed: This server takes on accounts for ${who}. Sign in with the account you already have, or open its page for a code.` };
  const npub = proofNpub(a.proof, a.hostPk, a.devicePk, Math.floor(a.now / 1000));
  if (!npub)
    return { ok: false, reason: 'bad-proof: That proof is for another server or another device, or it has expired. Try again, or open this server’s page for a code.' };
  const allowed = a.mode === 'invite'
    ? a.invites.includes(npub)
    : !!a.owner && (await follows(a.owner, a.relays, a.now)).has(npub);
  if (!allowed)
    return { ok: false, reason: `not-invited: This server takes on accounts for ${who}, and yours isn’t one of them. Open its page for a code.` };
  return { ok: true, as: npub };
}
