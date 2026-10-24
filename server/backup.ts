// Reading a paper backup back (COSIGN.md §8.3): with the paper's key, open every piece
// the servers kept for it, add each share's sigmas up (repair, frost/src/lib.rs) as of
// the epoch the paper was made in, then add every later refresh's part (refresh.ts), and
// check each share against the key's points now. The test phone uses this; the app has
// its own copy.

import * as nip44 from 'nostr-tools/nip44';
import { createRequire } from 'node:module';
import * as F from './frost.ts';
import { checkDelta, addDeltas } from './refresh.ts';

const W = createRequire(import.meta.url)('./frost-wasm/cosign_frost.js');

/** What a server sends the paper's key (`backup`), and the paper's secret key. */
export function restoreShares(sk: string, b: any): { idx: number; secret: string }[] {
  const open = (p: { from: string; content: string }) => JSON.parse(nip44.v2.decrypt(p.content, nip44.v2.utils.getConversationKey(F.hexToBytes(sk), p.from)));
  const sigmas: [number, number, string][] = b.pieces.flatMap((p: any) => open(p).sigmas);
  const then = JSON.stringify({ groupX: b.group.groupX, threshold: b.group.threshold, members: b.points.map(([idx, sharePub]: [number, string]) => ({ idx, sharePub })) });
  let shares: { idx: number; secret: string }[] = b.ks.map((k: number) => {
    const mine = sigmas.filter(s => s[0] === k).map(s => s[2]);
    if (mine.length !== b.helpers.length) throw new Error(`pieces missing for share ${k}`);
    return { idx: k, secret: W.repairStep3(then, mine, k) as string };
  });
  // Each refresh since: every dealer's part, checked against its commitments.
  const parts = b.parts.map((p: any) => ({ epoch: p.epoch, part: open(p) })).filter((p: any) => p.epoch > b.epoch);
  for (const epoch of [...new Set(parts.map((p: any) => p.epoch))].sort((x: any, y: any) => x - y)) {
    const these = parts.filter((p: any) => p.epoch === epoch).map((p: any) => p.part);
    shares = shares.map(s => {
      const ds = these.map((p: any) => (p.deltas as [number, string][]).find(d => d[0] === s.idx)?.[1]);
      if (ds.some((d: string | undefined, i: number) => !d || !checkDelta(these[i].commits, s.idx, d))) throw new Error(`a refresh part for share ${s.idx} doesn't check out`);
      return { idx: s.idx, secret: addDeltas(s.secret, ds as string[]) };
    });
  }
  // They must be the shares the key has now.
  const now = new Map<number, string>(b.group.members.flatMap((m: any) => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]).map((p: any) => [p.idx, p.sharePub]));
  for (const s of shares) if (W.sharePub(s.secret) !== now.get(s.idx)) throw new Error(`share ${s.idx} doesn't match the key as it is now`);
  return shares;
}
