// Sealed member-to-member messages: what travels over relays between the members of a
// group. Member traffic is an ephemeral event (relays don't store it) whose content is
// NIP-44 encrypted to the recipient and whose signature says who sent it. Pure: no
// relays here, so any host (../net.ts for Node, a Worker) can use it.

import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

export const KIND_MEMBER = 28001;
export const KIND_NIP46 = 24133;

const now = () => Math.floor(Date.now() / 1000);
/** One spelling per relay, so a site's "wss://x/" and our "wss://x" share a connection. */
export const normRelay = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase();

/** Seal a JSON message to another member. */
export function sealTo(sk: string, toPk: string, msg: unknown, kind = KIND_MEMBER): Event {
  const ck = nip44.v2.utils.getConversationKey(hexToBytes(sk), toPk);
  return finalizeEvent(
    { kind, created_at: now(), tags: [['p', toPk]], content: nip44.v2.encrypt(JSON.stringify(msg), ck) },
    hexToBytes(sk),
  );
}

// NIP-44 takes at most 64 KB, and a follow list of a thousand people is more. A message
// that big goes in parts small enough for any relay, and is put back together on arrival.
const PART = 24_000;

/** Seal a member message, in as many events as it takes. */
export function sealParts(sk: string, toPk: string, msg: unknown): Event[] {
  const text = JSON.stringify(msg);
  if (text.length <= PART) return [sealTo(sk, toPk, msg)];
  const id = bytesToHex(randomBytes(8)), n = Math.ceil(text.length / PART);
  return Array.from({ length: n }, (_, i) => sealTo(sk, toPk, { type: 'part', id, i, n, data: text.slice(i * PART, (i + 1) * PART) }));
}

/** Collects parts; gives back the whole message once the last one is in. */
export class Parts {
  private open = new Map<string, { at: number; got: string[]; left: number }>();
  take(fromPk: string, m: any): any | null {
    if (m?.type !== 'part') return m;
    const k = `${fromPk}:${m.id}`;
    for (const [key, v] of this.open) if (Date.now() - v.at > 120_000) this.open.delete(key);
    const p = this.open.get(k) ?? { at: Date.now(), got: new Array(m.n), left: m.n };
    if (p.got[m.i] === undefined) { p.got[m.i] = String(m.data); p.left--; }
    this.open.set(k, p);
    if (p.left > 0) return null;
    this.open.delete(k);
    try { return JSON.parse(p.got.join('')); } catch { return null; }
  }
}

/** Open a sealed message. Returns null when it isn't for us or doesn't decrypt. */
export function openFrom(sk: string, e: Event): any | null {
  try {
    const ck = nip44.v2.utils.getConversationKey(hexToBytes(sk), e.pubkey);
    return JSON.parse(nip44.v2.decrypt(e.content, ck));
  } catch {
    return null;
  }
}

export const pubOf = (sk: string) => getPublicKey(hexToBytes(sk));
