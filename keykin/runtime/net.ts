// What every node and transport share: the simulation's in-memory Bus, runtime/relay.ts over real
// relays, and the server runtime all speak through `Transport` to `Node`s.

import type { KeyPair } from '../src/event.ts';

/** `meta.ip`: the source address, when the request came over HTTPS (Server profile §3's buckets). */
export interface Node { kp: KeyPair; handle(from: string, body: any, sentAt: number, meta?: { ip?: string; pow?: number }): any }
/** Marks an answer the transport made up itself (unreachable, timed out): a server can't send a symbol,
 *  so a sealed `error` never looks like silence (review 9 M4). */
export const TRANSPORT_FAILED = Symbol('transport_failed');
export const unreachable = () => ({ type: 'error', code: 'unreachable', [TRANSPORT_FAILED]: true });
export interface Transport { now: number; alive(pub: string): boolean; send(from: KeyPair, to: string, body: any, o?: { timeoutMs?: number; pow?: number }): Promise<any>; kill?(pub: string): void; rekey?(oldPub: string, node: Node): void; pushes?: { push(p: PushOut): unknown } }
/** A Web Push request as a gateway receives it. */
export interface PushOut { url: string; authorization: string; body: Uint8Array; at: number }

