// Taking on a new group, on a server already running for other people: one of the
// group's devices writes to the server's host key (its identity across everyone it
// serves), sealed to it, and the server starts serving that group with no setup step.
//
//   enroll_key                → enroll_key { pk, key }
//     A member key of this server's own for the new group, made from its host key and
//     `key`, so nothing has to wait on disk between the two steps. The device puts `pk`
//     in the group record as this server's member.
//   enroll { how, key, group, signer?, share | shares, relays? }
//                             → enrolled { pk, group } | enroll_failed { reason }
//     `how` is how this server's share came to be:
//     'dealt': a device dealt the key and sends this server its share, which it checks
//       against the group's share points before keeping it. Moving a key in from a web
//       page (site/src/import.ts) adds `claim`, a token the phone that gets the device
//       shares sends back (pair_ack) to become that member, and `tickets`, so the page
//       can sign in with the key it just gave away.
//   enroll { how: 'dkg', key, group, plan, signer? }
//     No key yet: the device and its servers make one (dkg.ts), nobody ever holding it.
//     `group` is the record without key or share points; `plan` is {session, threshold,
//     holders: [{idx, pk}]}, this server's member key at the indices the record gives it.
//     The group starts with the plan and runs it with the others; `groupX` and the share
//     points arrive when it's done. The device knows it's done from its own run.
//
// Who may enroll at all (anyone, or an invite list of device keys) is the host's call,
// made before any of this. Asking again gets the same answer: the member key is the same.

import { nip19 } from 'nostr-tools';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import * as F from '../frost.ts';
import type * as Sig from '../sign.ts';
import { pubOf } from './seal.ts';
import type { Member } from './group.ts';

/** What an enroller gets: the message, who sent it, and this server's member key for the group. */
export interface Enrolling {
  msg: any;
  /** The device that sent it. */
  from: string;
  memberSk: string;
  /** The shares (indices) this host already holds of a key, in any group: a server must never hold enough to sign alone. */
  holds: (groupX: string) => number[];
  /** Milliseconds. */
  now: number;
}

/** Turns an enroll message into a new group's state (state.json), or throws why not. */
export type Enroller = (e: Enrolling) => any | Promise<any>;

/** This server's member key for a group, from its host key and the `key` it handed out. */
export const memberSk = (hostSk: string, key: string) => {
  if (!/^[0-9a-f]{32}$/.test(key)) throw new Error('bad-key: Ask this server for a member key first (enroll_key).');
  return bytesToHex(sha256(concatBytes(hexToBytes(hostSk), utf8ToBytes('cosign member key'), hexToBytes(key))));
};

export function newMemberKey(hostSk: string) {
  const key = bytesToHex(randomBytes(16));
  return { key, pk: pubOf(memberSk(hostSk, key)) };
}

/** A group's relays, at most: the host connects to each, and a stranger chose them. */
const MAX_RELAYS = 8;

const sameSet = (a: number[], b: number[]) => [...a].sort((x, y) => x - y).join() === [...b].sort((x, y) => x - y).join();
const mod = (a: bigint) => F.Point.Fn.create(a);
const pointOf = (hex: string) => { try { return F.Point.fromHex(hex); } catch { return null; } };

/**
 * Why the share points don't make one key, or null if they do: the first `threshold` of
 * them must interpolate to the group key at 0 (even y, as BIP-340 keys are), and to each
 * of the others at its index. Any threshold, so a weighted key checks the same way.
 */
function offTheLine(groupX: string, threshold: number, points: { idx: number; sharePub: string }[]): string | null {
  if (points.length < threshold) return 'fewer share points than the threshold';
  const P = points.map(p => ({ idx: p.idx, x: BigInt(p.idx), P: pointOf(p.sharePub) }));
  const bad = P.find(p => !p.P || p.idx < 1);
  if (bad) return `share point ${bad.idx} is damaged`;
  const base = P.slice(0, threshold);
  const at = (x: bigint) => base.reduce((acc, j) => {
    let num = 1n, den = 1n;
    for (const m of base) if (m !== j) { num = mod(num * (x - m.x)); den = mod(den * (j.x - m.x)); }
    const c = mod(num * F.Point.Fn.inv(den));
    return c === 0n ? acc : acc.add(j.P!.multiply(c));
  }, F.Point.ZERO);
  const key = pointOf('02' + groupX);
  if (!key || !at(0n).equals(key)) return 'the share points don’t belong to this key';
  for (const p of P.slice(threshold)) if (!at(p.x).equals(p.P!)) return `share point ${p.idx} doesn’t belong to this key`;
  return null;
}

/** A share a device dealt: check the group record holds together and the share is the one it says, then keep it. */
function dealt({ msg, from, memberSk: sk, holds, now }: Enrolling) {
  const g = msg.group;
  if (!g || typeof g.groupX !== 'string' || !/^[0-9a-f]{64}$/.test(g.groupX) || !Array.isArray(g.members) || !Array.isArray(g.relays)) throw new Error('bad-group: That group record is damaged.');
  const threshold = Number(g.threshold);
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('bad-group: A group needs a threshold of at least 2.');
  const relays = g.relays.filter((r: unknown) => typeof r === 'string' && /^wss?:\/\//.test(r)).slice(0, MAX_RELAYS);
  if (!relays.length) throw new Error('bad-group: A group needs relays.');
  const members: Member[] = g.members.map((m: any) => ({
    idx: Number(m.idx), name: String(m.name ?? 'A member').slice(0, 40), role: m.role === 'server' ? 'server' : m.role === 'phone' ? 'phone' : 'device',
    pk: typeof m.pk === 'string' && /^[0-9a-f]{64}$/.test(m.pk) ? m.pk : null, sharePub: String(m.sharePub ?? '').toLowerCase(), push: null,
    ...(Array.isArray(m.shares) ? { shares: m.shares.map((s: any) => ({ idx: Number(s.idx), sharePub: String(s.sharePub).toLowerCase() })) } : {}),
  }));
  const pk = pubOf(sk);
  const me = members.find(m => m.pk === pk);
  if (!me || me.role !== 'server') throw new Error('bad-group: The group record doesn’t list this server’s member key as one of its servers.');
  const group: Sig.Group = { groupX: g.groupX, threshold, members };

  // Every share point on one line through the key, or signing would fail later, and confusingly.
  const points = group.members.flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]);
  if (new Set(points.map(p => p.idx)).size !== points.length) throw new Error('bad-group: Two shares with one index.');
  const off = offTheLine(g.groupX, threshold, points);
  if (off) throw new Error(`bad-group: ${off[0].toUpperCase()}${off.slice(1)}.`);
  // This server's shares: exactly the ones the record says it holds, each making its point.
  const shares: Sig.Share[] = Array.isArray(msg.shares) ? msg.shares.map((s: any) => ({ idx: Number(s.idx), secret: String(s.secret) })) : [{ idx: me.idx, secret: String(msg.share ?? '') }];
  const want = me.shares?.map(s => s.idx) ?? [me.idx];
  if (!sameSet(shares.map(s => s.idx), want)) throw new Error('bad-share: Those aren’t the shares the group record gives this server.');
  for (const s of shares) {
    let pub = '';
    try { const k = BigInt('0x' + s.secret); if (/^[0-9a-f]{64}$/.test(s.secret) && k > 0n && k < F.N) pub = F.bytesToHex(F.G.multiply(k).toBytes(true)); } catch { /* damaged */ }
    if (!pub) throw new Error(`bad-share: Share ${s.idx} is damaged.`);
    if (pub !== points.find(p => p.idx === s.idx)!.sharePub) throw new Error(`bad-share: Share ${s.idx} doesn’t match its share point.`);
  }
  // Never enough here to sign alone, counting anything of this key the host already has.
  if (new Set([...shares.map(s => s.idx), ...holds(g.groupX)]).size >= threshold) throw new Error('too-many: This server would hold enough of the key to sign alone.');

  const signer = signerOf(msg);
  const { pairing, tickets } = claimOf(msg, members);

  return {
    // As setup.ts writes it: `share` for a member of one share, `shares` for one the record gives several.
    self: { idx: me.idx, sk, share: shares[0].secret, ...(me.shares ? { shares } : {}) },
    group: { groupX: g.groupX, npub: nip19.npubEncode(g.groupX), threshold, relays, members },
    signer, sites: [], tickets, changes: [], pairing,
    enrolled: { at: Math.floor(now / 1000), by: from, how: 'dealt' },
  };
}

/** The group record's members, as this server keeps them. */
const membersOf = (g: any): Member[] => g.members.map((m: any) => ({
  idx: Number(m.idx), name: String(m.name ?? 'A member').slice(0, 40), role: m.role === 'server' ? 'server' : m.role === 'phone' ? 'phone' : 'device',
  pk: typeof m.pk === 'string' && /^[0-9a-f]{64}$/.test(m.pk) ? m.pk : null, sharePub: String(m.sharePub ?? '').toLowerCase(), push: null,
  ...(Array.isArray(m.shares) ? { shares: m.shares.map((s: any) => ({ idx: Number(s.idx), sharePub: String(s.sharePub ?? '').toLowerCase() })) } : {}),
}));

const signerOf = (msg: any) => {
  if (!msg.signer) return null;
  const signer = { sk: String(msg.signer.sk), pk: String(msg.signer.pk) };
  let ok = false;
  try { ok = pubOf(signer.sk) === signer.pk; } catch { /* damaged */ }
  if (!ok) throw new Error('bad-signer: The signer key doesn’t match its public key.');
  return signer;
};

/** A device member still to be claimed by whoever brings `claim` back, and tickets for the page that sent it. */
function claimOf(msg: any, members: Member[]) {
  let pairing: { token: string; idx: number; claim: true } | null = null;
  if (msg.claim !== undefined) {
    const m = members.find(x => x.idx === Number(msg.claim?.idx));
    if (!/^[0-9a-f]{32}$/.test(String(msg.claim?.token)) || !m || m.role === 'server' || m.pk) throw new Error('bad-claim: That claim doesn’t name a device member without a key.');
    pairing = { token: String(msg.claim.token), idx: m.idx, claim: true };
  }
  const tickets = (Array.isArray(msg.tickets) ? msg.tickets : []).slice(0, 4).map((t: any) => {
    if (!/^[0-9a-f]{32}$/.test(String(t?.t)) || typeof t.expires !== 'number') throw new Error('bad-ticket: A ticket is damaged.');
    return { t: String(t.t), origin: String(t.origin ?? 'a site').slice(0, 80), expires: Math.min(t.expires, Math.floor(Date.now() / 1000) + 3600) };
  });
  return { pairing, tickets };
}

/** A key not made yet: check the record and the plan agree on who holds what, then wait for the run. */
function dkg({ msg, from, memberSk: sk, now }: Enrolling) {
  const g = msg.group, plan = msg.plan;
  if (!g || !Array.isArray(g.members) || !Array.isArray(g.relays)) throw new Error('bad-group: That group record is damaged.');
  const threshold = Number(g.threshold);
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('bad-group: A group needs a threshold of at least 2.');
  const relays = g.relays.filter((r: unknown) => typeof r === 'string' && /^wss?:\/\//.test(r)).slice(0, MAX_RELAYS);
  if (!relays.length) throw new Error('bad-group: A group needs relays.');
  const members = membersOf(g);
  const pk = pubOf(sk);
  const me = members.find(m => m.pk === pk);
  if (!me || me.role !== 'server') throw new Error('bad-group: The group record doesn’t list this server’s member key as one of its servers.');
  if (!plan || typeof plan.session !== 'string' || !/^[0-9a-f]{16,64}$/.test(plan.session) || Number(plan.threshold) !== threshold || !Array.isArray(plan.holders))
    throw new Error('bad-plan: That key plan is damaged.');
  const holders: { idx: number; pk: string }[] = plan.holders.map((h: any) => ({ idx: Number(h.idx), pk: String(h.pk) }));
  // The plan and the record must agree, share by share: every member's indices, held by its key.
  const idxs = (m: Member) => m.shares?.map(s => s.idx) ?? [m.idx];
  const all = members.flatMap(m => idxs(m).map(idx => ({ idx, pk: m.pk })));
  if (new Set(all.map(a => a.idx)).size !== all.length || all.some(a => a.idx < 1)) throw new Error('bad-group: Two shares with one index.');
  if (all.length !== holders.length || all.some(a => !a.pk || holders.find(h => h.idx === a.idx)?.pk !== a.pk))
    throw new Error('bad-plan: The plan doesn’t give each share to the member the record does.');
  if (threshold > all.length) throw new Error('bad-group: The threshold is more than there are shares.');
  if (idxs(me).length >= threshold) throw new Error('too-many: This server would hold enough of the key to sign alone.');
  return {
    self: { idx: me.idx, sk, shares: [] },
    group: { groupX: null, npub: null, threshold, relays, members },
    signer: signerOf(msg), sites: [], tickets: [], changes: [], pairing: null,
    dkg: { session: plan.session, threshold, holders },
    enrolled: { at: Math.floor(now / 1000), by: from, how: 'dkg' },
  };
}

/**
 * Joining a key that already exists, as one more server ("Add a server"): the record as it
 * is, this server at index `k` with no share yet. One of the user's devices vouches for it
 * with a server already in the key (add_device {server: true}); the repair's sigmas arrive
 * here, and the group finishes with its share (core/group.ts, `joining`).
 */
function repair({ msg, from, memberSk: sk, now }: Enrolling) {
  const g = msg.group;
  if (!g || !/^[0-9a-f]{64}$/.test(String(g.groupX)) || !Array.isArray(g.members) || !Array.isArray(g.relays)) throw new Error('bad-group: That group record is damaged.');
  const threshold = Number(g.threshold);
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('bad-group: A group needs a threshold of at least 2.');
  const k = Number(msg.k);
  const members = membersOf(g);
  const pk = pubOf(sk);
  if (!Number.isInteger(k) || k < 1 || members.some(m => (m.shares?.map(s => s.idx) ?? [m.idx]).includes(k))) throw new Error('bad-index: That share index is taken.');
  if (members.some(m => m.pk === pk)) throw new Error('bad-group: This server is already in that group.');
  const relays = g.relays.filter((r: unknown) => typeof r === 'string' && /^wss?:\/\//.test(r)).slice(0, MAX_RELAYS);
  members.push({ idx: k, name: String(msg.name ?? 'A server').slice(0, 40), role: 'server', pk, sharePub: '', push: null });
  return {
    self: { idx: k, sk, shares: [] },
    group: { groupX: g.groupX, npub: nip19.npubEncode(g.groupX), threshold, relays, members },
    signer: null, sites: [], tickets: [], changes: [], pairing: null,
    joining: { k, at: Math.floor(now / 1000) },
    enrolled: { at: Math.floor(now / 1000), by: from, how: 'repair' },
  };
}

/** Every way a server can be given a share in a new group, by the `how` of the message. */
export const enrollers: Record<string, Enroller> = { dealt, dkg, repair };
