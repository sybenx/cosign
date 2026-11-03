// Core's records and changes (core §3.1, §3.2, §6.7.2), as JSON.

import type { LockPub, Assertion } from './lock.ts';

export const KIND_EPOCH = 30242, KIND_CHANGE = 24302, KIND_RUMOR = 24301, KIND_SIGNPOST = 30078;
export const T = 4;
export const KNOWN_KINDS = ['device', 'helper', 'server', 'backup'] as const;
export type MemberKind = (typeof KNOWN_KINDS)[number];

export interface MemberEntry {
  key: string; kind: MemberKind | string; shares: number[];
  lock?: LockPub | null;
  host?: string; operator?: string; own?: boolean; https?: string; vapid?: string; relays?: string[];
  enroll?: unknown;
}

export interface Seats { servers: number[]; backup: number[]; helper: number[] }

export interface EpochContent {
  v: 1; g: string; epoch: { n: number; id: string }; prev: null; t: 4;
  commitment: string[]; role: 'master' | 'child'; origin: 'dkg' | 'import';
  relays: string[]; members: MemberEntry[]; removed: string[]; backup: string; seats: Seats;
}

export type Change =
  | { add: { key: string; kind: 'device'; lock: LockPub | null; salt: number } }
  | { remove: string; to?: string }
  | { lock: { member: string; replaces: string | null; new: LockPub } }
  | { seat: { seat: string; new: MemberEntry | null; replaces: string | null } }
  | { paper: { key: string; replaces: string; inner?: string; state?: string[] } }
  | { redeal: Redeal | { dealer: string } };

export interface Redeal {
  id: string; dealer: string; D: string[]; paper_to: string; paper_item: string; dk: string; rs: string;
  base: string[]; abandons: string[]; sig?: string;
}

/** An approval (§6.2). `expiry` is part of the lock string (§6.1), so every list approval carries
 *  it; the other fields are this implementation's encodings of §6.2's shapes. */
export interface Approval {
  expiry?: number;
  lock?: { member: string; assertion: Assertion };
  pair?: [{ member: string; sig: string; r: string }, { member: string; code_sig: string }];
  paper?: { member: string; sig: string; backup: string; challenge: string; server: string; backup_sig: string };
  recovery?: { backup: string; release_request: unknown; waited: Waited[]; backup_sig: string };
  self?: { member: string; sig: string; app_sig: string };
}

export interface Waited { server: string; kind: 'recovery' | 'hold'; wait: string; start: number; end: number; sig: string }

/** A kind 24302 change's content. `list` is the approval list it belongs to (§6.7.2), carried in
 *  every change of the list so anyone can recompute the list hash. */
export interface ChangeContent { v: 1; g: string; epoch: string; change: Change; list: Change[]; approval: Approval; cosig?: { host: string; sig: string } }

export const changeType = (c: Change): string => Object.keys(c).find((k) => k !== 'to')!;
