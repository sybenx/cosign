// What every node and transport share: the simulation's in-memory Bus, runtime/relay.ts over real
// relays, and the server runtime all speak through `Transport` to `Node`s.

import type { KeyPair } from '../src/event.ts';

/** `meta.ip`: the source address, when the request came over HTTPS (Server profile §3's buckets). */
export interface Node { kp: KeyPair; handle(from: string, body: any, sentAt: number, meta?: { ip?: string; pow?: number }): any }
/** Marks an answer the transport made up itself (unreachable, timed out): a server can't send a symbol,
 *  so a sealed `error` never looks like silence (review 9 M4). */
export const TRANSPORT_FAILED = Symbol('transport_failed');
export const unreachable = () => ({ type: 'error', code: 'unreachable', [TRANSPORT_FAILED]: true });
export interface Transport { now: number; alive(pub: string): boolean; send(from: KeyPair, to: string, body: any, o?: { timeoutMs?: number; pow?: number }): Promise<any>; kill?(pub: string): void; rekey?(oldPub: string, node: Node): void; pushes?: { push(p: PushOut): unknown }; events?: Events }
/** A relay filter, as much of NIP-01's as Core's doors need. */
export interface Filter { ids?: string[]; limit?: number; kinds?: number[]; authors?: string[]; '#p'?: string[]; '#d'?: string[]; since?: number }
export const matches = (f: Filter, e: { id?: string; kind: number; pubkey: string; tags: string[][]; created_at: number }) =>
  (!f.ids || f.ids.includes(e.id ?? '')) && (!f.kinds || f.kinds.includes(e.kind)) && (!f.authors || f.authors.includes(e.pubkey)) && (f.since === undefined || e.created_at >= f.since)
  && (!f['#p'] || e.tags.some((t) => t[0] === 'p' && f['#p']!.includes(t[1])))
  && (!f['#d'] || e.tags.some((t) => t[0] === 'd' && f['#d']!.includes(t[1])));
/** Raw Nostr events, for the doors (NIP-46, Doors §3.3) and watching: publish to relays, and subscribe. */
export interface Events {
  publishEvent(e: any, relays?: string[]): Promise<void>;
  watch(filter: Filter, onEvent: (e: any) => void, relays?: string[]): { close(): void };
  /** The stored events matching `filter`, from every relay, until each says it sent them all (EOSE); and how many
   *  relays were asked and answered, so a caller can tell a failed fetch from an empty one. */
  query(filter: Filter, relays?: string[]): Promise<{ events: any[]; answered: number; asked: number }>;
}
/** A Web Push request as a gateway receives it. */
export interface PushOut { url: string; authorization: string; body: Uint8Array; at: number }

