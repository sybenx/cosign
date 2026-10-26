// A host for the member library (site/src/member), in TypeScript: it keeps the parts of the
// key in memory and does the maths with the same FROST the servers use. The Marble Mac app's
// host keeps them in the Keychain and does the maths in Rust; this one exists so the library
// can be driven against real servers from this repository, rather than proved only downstream.

import { createRequire } from 'node:module';
import * as F from '../../server/frost.ts';
import * as Sig from '../../server/sign.ts';
import { addDeltas, checkDelta, newPoint } from '../../server/refresh.ts';
import type { Commit, DeviceState, Group, ShareOps } from '../src/member/ops.ts';

const W = createRequire(import.meta.url)('../../server/frost-wasm/cosign_frost.js');

export interface Kept { mailboxKey: string; shares: { idx: number; secret: string }[]; group?: unknown; epoch: number }

/** The parts, and what the library asks of them. Nothing of this crosses into the library. */
export function hostFor(kept: Kept): ShareOps & { kept: Kept } {
  /** Parts made but not kept yet: a join's, or a refresh's, until commitParts. */
  let waiting: { epoch: number; shares: { idx: number; secret: string }[] } | null = null;
  const nonces = new Map<string, { idx: number; nonces: string; pending: boolean }>();
  const secretOf = (idx: number, pending: boolean) =>
    (pending ? waiting?.shares : kept.shares)?.find(s => s.idx === idx)?.secret;

  return {
    kept,
    async state(): Promise<DeviceState> {
      return { joined: kept.shares.length > 0, idxs: kept.shares.map(s => s.idx), group: kept.group, epoch: kept.epoch };
    },
    async mailboxKey() { return kept.mailboxKey; },

    async commit(group: Group, idx: number, pending?: boolean) {
      const secret = secretOf(idx, pending === true);
      if (!secret) throw new Error(`no part ${idx}`);
      const r = Sig.commit(group as Sig.Group, idx, secret);
      const handle = `${idx}:${Math.random()}`;
      nonces.set(handle, { idx, nonces: r.nonces, pending: pending === true });
      return { handle, commit: r.commit as Commit };
    },
    async sign(group: Group, idx: number, handle: string, msg: string, commits: Commit[], pending?: boolean) {
      const n = nonces.get(handle);
      if (!n || n.idx !== idx) throw new Error('that round is over');
      nonces.delete(handle); // once, as a host must
      const secret = secretOf(idx, pending === true || n.pending);
      if (!secret) throw new Error(`no part ${idx}`);
      return Sig.partial(2, group as Sig.Group, idx, secret, n.nonces, msg, commits as Sig.Commit[]);
    },
    async verifyPartial(group: Group, msg: string, commits: Commit[], idx: number, z: string) {
      // The scheme the servers sign under (server/sign.ts): a partial is checked by the wasm,
      // against the same group json the maths uses.
      return W.verifyPartial(JSON.stringify(group), msg, JSON.stringify(commits), idx, z) === true;
    },
    async aggregate(group: Group, msg: string, commits: Commit[], partials: [number, string][]) {
      return Sig.combine(2, group as Sig.Group, msg, commits as Sig.Commit[], partials);
    },

    async ecdhPartial(idx: number, participants: number[], peerX: string) {
      const secret = secretOf(idx, false);
      if (!secret) throw new Error(`no part ${idx}`);
      return F.ecdhPartial({ idx, secret, participants, peerX });
    },
    async ecdhCombine(parts: string[]) { return F.bytesToHex(F.ecdhCombine(parts)); },

    async repairStep1(group: Group, idx: number, helpers: number[], k: number) {
      const secret = secretOf(idx, false);
      if (!secret) throw new Error(`no part ${idx}`);
      return Sig.repairStep1(group as Sig.Group, idx, secret, helpers, k);
    },
    async repairStep2(deltas: string[]) { return Sig.repairStep2(deltas); },
    async repairStep3(group: Group, sigmas: string[], k: number) {
      const secret = W.repairStep3(JSON.stringify(group), sigmas, k);
      waiting = { epoch: waiting?.epoch ?? 0, shares: [...(waiting?.shares ?? []), { idx: k, secret }] };
      return W.sharePub(secret);
    },

    async refreshApply(group: Group, epoch: number, dealers: { commits: string[]; deltas: [number, string][] }[]) {
      const mine: { idx: number; secret: string }[] = [];
      for (const s of kept.shares) {
        const deltas = dealers.map(d => {
          const delta = d.deltas.find(([j]) => j === s.idx)?.[1];
          if (!delta || !checkDelta(d.commits, s.idx, delta)) throw new Error(`a delta that isn't for part ${s.idx}`);
          return delta;
        });
        mine.push({ idx: s.idx, secret: addDeltas(s.secret, deltas) });
      }
      const commits = dealers.map(d => d.commits);
      const points = group.members.map(m => [m.idx, newPoint(m.sharePub, m.idx, commits)] as [number, string]);
      // Each new part must make the point everyone else will be working with (refresh.ts).
      for (const s of mine) if (W.sharePub(s.secret) !== points.find(p => p[0] === s.idx)?.[1]) throw new Error(`a new part ${s.idx} that doesn't match its point`);
      waiting = { epoch, shares: mine };
      return points;
    },
    async dropPending(epoch: number) { if (waiting?.epoch === epoch) waiting = null; },

    async commitParts(group: unknown, epoch: number) {
      if (waiting) kept.shares = waiting.shares;
      waiting = null;
      kept.group = group;
      kept.epoch = epoch;
    },
    async update(group: unknown) { kept.group = group; },
    async lock() { /* a test has no one to ask */ },
    async forget() { kept.shares = []; kept.group = undefined; },
  };
}
