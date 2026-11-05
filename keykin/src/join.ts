// Joining (core §4.1–§4.2, §4.4): the codes, the typed check and the new device's checks, as
// transport-free state machines. A joining member trusts only what it scanned, the group key and
// the check both screens show (live finding #17).

import { bytesToHex, randomBytes, hexN, refuse, fromB64u, b64u, hexToBytes } from './bytes.ts';
import { joinCheck, stateHash } from './codes.ts';
import { checkEpochRecord } from './record.ts';
import { computeMembership, type Membership } from './membership.ts';
import { commitmentAt } from './redeal.ts';
import { repairShare } from './frost.ts';
import { commitmentFrom, type Commitment } from './curve.ts';
import type { NostrEvent } from './event.ts';
import type { LockPub } from './lock.ts';

export const CODE_TTL_S = 600;

export interface Invite { g: string; m: string; s: string; x: number; r: string[] }
export interface Hello { n: string; s: string; x: number; r: string[] }

const enc = (scheme: string, kv: [string, string][]) => `keykin:${scheme}?` + kv.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
export const inviteCode = (i: Invite) => enc('join', [['g', i.g], ['m', i.m], ['s', sOnWire(i.s)], ['x', String(i.x)], ...i.r.map((r) => ['r', r] as [string, string])]);
export const helloCode = (h: Hello) => enc('hello', [['n', h.n], ['s', sOnWire(h.s)], ['x', String(h.x)], ...h.r.map((r) => ['r', r] as [string, string])]);

/** Read a code; `cosign:` is accepted in place of `keykin:` (§11.3). `s` is base64url on the wire. */
export function parseCode(code: string): ({ kind: 'join' } & Invite) | ({ kind: 'hello' } & Hello) {
  const m = /^(keykin|cosign):(join|hello)\?(.*)$/.exec(code.trim());
  if (!m) refuse('bad_code');
  const q = new URLSearchParams(m![3]);
  const s = q.get('s') ?? '', x = Number(q.get('x')), r = q.getAll('r');
  if (!Number.isSafeInteger(x)) refuse('bad_code', 'x');
  const sHex = bytesToHex(fromB64u(s));
  hexN(sHex, 16, 's');
  if (m![2] === 'join') { const g = q.get('g')!, mm = q.get('m')!; hexN(g, 32, 'g'); hexN(mm, 32, 'm'); return { kind: 'join', g, m: mm, s: sHex, x, r }; }
  const n = q.get('n')!; hexN(n, 32, 'n');
  return { kind: 'hello', n, s: sHex, x, r };
}
export const sOnWire = (sHex: string) => b64u(hexToBytes(sHex));

/** The inviting device's side, either direction. */
export class Inviter {
  g: string; m: string; s: string; x: number;
  /** Join-code direction: the `n` from the scanned code; the only key that may be added. */
  expectN: string | null;
  accepted: { n: string; lock: LockPub | null; t: string } | null = null;
  constructor(o: { g: string; m: string; now: number; scanned?: Hello; s?: string }) {
    this.g = o.g; this.m = o.m;
    if (o.scanned) {
      if (o.scanned.x < o.now) refuse('expired');
      this.s = o.scanned.s; this.x = o.scanned.x; this.expectN = o.scanned.n;
    } else { this.s = o.s ?? bytesToHex(randomBytes(16)); this.x = o.now + CODE_TTL_S; this.expectN = null; }
  }
  invite(relays: string[]): string { return inviteCode({ g: this.g, m: this.m, s: this.s, x: this.x, r: relays }); }
  /** Join-code direction: the offer sealed to the code's `n`. */
  offer() { if (!this.expectN) refuse('no_code'); return { to: this.expectN!, msg: { type: 'welcome_offer', g: this.g, m: this.m, s: this.s } }; }
  /** A `join_hello` arrives, sealed by `from`. Returns the `join_nonce` to send, or throws (drop). */
  onHello(from: string, hello: any, now: number) {
    if (this.accepted) refuse('already_accepted');
    if (now > this.x) refuse('expired');
    if (hello?.s !== this.s) refuse('bad_secret');
    if (hello.n !== from) refuse('not_sealed_by_n');
    if (this.expectN && from !== this.expectN) refuse('not_sealed_by_n', 'the join-code direction adds only the scanned n');
    const t = bytesToHex(randomBytes(16));
    this.accepted = { n: from, lock: hello.lock ?? null, t };
    return { to: from, msg: { type: 'join_nonce', t } };
  }
  /** The person typed the number shown on the new device. Only a match goes on. */
  typed(code: string): boolean { return !!this.accepted && joinCheck(this.g, this.m, this.accepted.n, this.s, this.accepted.t) === code; }
}

/** The new device's side. */
export class Joiner {
  n: string; lock: LockPub | null;
  g: string | null = null; m: string | null = null; s: string | null = null; x = 0;
  helloTo: string | null = null; t: string | null = null;
  constructor(o: { n: string; lock?: LockPub | null; now: number; scanned?: Invite; s?: string }) {
    this.n = o.n; this.lock = o.lock ?? null;
    if (o.scanned) {
      if (o.scanned.x < o.now) refuse('expired');
      this.g = o.scanned.g; this.m = o.scanned.m; this.s = o.scanned.s; this.x = o.scanned.x;
    } else { this.s = o.s ?? bytesToHex(randomBytes(16)); this.x = o.now + CODE_TTL_S; }
  }
  helloCode(relays: string[]) { return helloCode({ n: this.n, s: this.s!, x: this.x, r: relays }); }
  /** Invite direction: the hello, sealed to the invite's `m`. */
  hello() { this.helloTo = this.m; return { to: this.m!, msg: { type: 'join_hello', n: this.n, s: this.s, lock: this.lock } }; }
  /** Join-code direction: an offer arrives; answer with the hello sealed to its `m`. */
  onOffer(from: string, offer: any, now: number) {
    if (this.g) refuse('already_accepted');
    if (now > this.x) refuse('expired');
    if (offer?.s !== this.s) refuse('bad_secret');
    if (offer.m !== from) refuse('not_sealed_by_m');
    hexN(offer.g, 32, 'g');
    this.g = offer.g; this.m = offer.m;
    return this.hello();
  }
  onNonce(from: string, msg: any) {
    if (from !== this.helloTo) refuse('wrong_sender', 'a join_nonce only from the key the hello went to');
    if (this.t) refuse('already_accepted');
    hexN(msg?.t, 16, 't');
    this.t = msg.t;
  }
  /** The 6 digits this screen shows (§1.1 item 1). */
  get check() { if (!this.t) refuse('no_nonce'); return joinCheck(this.g!, this.m!, this.n, this.s!, this.t!); }

  /** §4.2 step 5 (and §4.4 for a recovery join). Returns the checked view and the new shares. */
  finish(o: {
    from: string; welcome: { record: NostrEvent; changes: NostrEvent[]; state: string[]; redeals?: any[] };
    sigmas: { from: string; index: number; sigma: string; state: string }[];
    recovery?: { backup: string };
  }): { membership: Membership; shares: Map<number, bigint>; C: Commitment } {
    const sealer = o.recovery ? o.recovery.backup : this.m;
    if (o.from !== sealer) refuse('not_sealed_by_m', 'a welcome from a stranger');
    const rec = checkEpochRecord(o.welcome.record, { g: this.g! });
    const mem = computeMembership(rec, o.welcome.changes);
    if (mem.invariantError) refuse('invariant', mem.invariantError);
    if (o.recovery && o.recovery.backup !== mem.backupKey) refuse('not_current_backup');
    const me = mem.members.get(this.n);
    if (!me || me.kind !== 'device') refuse('no_add', 'no valid change adds this key');
    const addP = mem.accepted.find((p) => p.type === 'add' && (p.c.change as any).add.key === this.n)!;
    if (JSON.stringify((addP.c.change as any).add.lock ?? null) !== JSON.stringify(this.lock)) refuse('no_add', 'the add names another lock');
    // The commitment at the welcome's state, from the redeals it names (each a change in the set).
    const ids = new Set(o.welcome.state);
    const reds = [...mem.redeals.values()].filter((x) => ids.has(x.r.id)).map((x) => x.r);
    if (reds.length !== ids.size) refuse('missing_redeal');
    const C = commitmentAt(commitmentFrom(rec.commitment), reds);
    const sh = stateHash(ids);
    const servers = new Set([...mem.members.values()].filter((x) => x.kind === 'server').map((x) => x.key));
    const shares = new Map<number, bigint>();
    for (const i of me!.shares) {
      // Exactly the sealer's sigma and the servers' (one; two in a recovery join): stray parts are ignored.
      const at = o.sigmas.filter((s) => s.index === i && s.state === sh);
      const fromHelper = at.find((s) => s.from === sealer);
      const serverKeys = [...new Set(at.filter((s) => servers.has(s.from)).map((s) => s.from))].slice(0, o.recovery ? 2 : 1);
      if (!fromHelper) refuse('sigma_missing', 'the inviter\'s sigma');
      if (serverKeys.length < (o.recovery ? 2 : 1)) refuse('sigma_missing', 'a server\'s sigma');
      const parts = [fromHelper!, ...serverKeys.map((k) => at.find((s) => s.from === k)!)];
      shares.set(i, repairShare(C, parts.map((p) => p.sigma), i));
    }
    return { membership: mem, shares, C };
  }
}
