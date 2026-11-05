// Recovering an account with its paper alone, over real relays (core §6.5), as the simulator's `recover`:
//   0. find the account and today's servers: `seated?` at each host the app lists (§6.7.5 route 1), else at the hosts
//      the signpost names (route 3, sealed to the paper's key); the sealed answer gives g, the epoch and the seats;
//   1. the paper holder asks each server for a challenge and sends `release_request {r}`;
//   2. each server starts a recovery wait W (three days; a locked device or two devices can cancel it);
//   3. once W has passed, the release bundles: the holder opens the backup seat's shares and the material;
//   4. a new device is added under a `recovery` approval, co-signed by the paper and two servers, repaired by them,
//      welcomed, and (optionally) reports the lost devices with a redeal it deals.
// `onWaiting` hears when the wait ends; the call keeps asking until then (or `o.giveUpAt`).

import { DeviceNode, PaperHolder } from './node.ts';
import { readBackupWords } from '../src/backup.ts';
import { refuse, KeykinError, strictJson, bytesToHex, hexToBytes, randomBytes, sha, utf8ToBytes } from '../src/bytes.ts';
import * as nip44 from 'nostr-tools/nip44';
import { nip44Open } from '../src/nip44.ts';
import { pubOf, verifyEvent, schnorrSign, schnorrVerify, type NostrEvent } from '../src/event.ts';
import { signpostD, pickSalt, seatedAskDigest, seatedDigest } from '../src/codes.ts';
import { takenIndices, signpostCount, computeMembership, type Membership } from '../src/membership.ts';
import { checkEpochRecord } from '../src/record.ts';
import { msg } from '../src/msg.ts';
import { Joiner } from '../src/join.ts';
import { unwrap } from '../src/transport.ts';
import { KIND_SIGNPOST, type Change, type MemberEntry } from '../src/types.ts';
import { W_DEFAULT } from '../src/approval.ts';
import type { Lock } from '../src/lock.ts';
import type { Transport, Node } from '../runtime/net.ts';

type Net = Transport & { add<N extends Node>(n: N): N; kill(pub: string): void };

/** The account a paper belongs to, and its seated servers (step 0, core 14.23): `seated?` at each host (§6.7.5 route 1),
 *  the hosts from the app's server list (`hosts`) or, failing that, from the signposts (route 3, kind 30078, sealed to the
 *  paper). A `seated` answer is only a hint: an account is believed once two distinct servers, both seated in it, return the same epoch record and change set (Backup §2), and its servers are then the change set's, not the hint's.
 *  Anyone can name a paper's public key as an account's backup, and two accounts may share a paper (I7): when more than
 *  one account is found, `pick` chooses by npub (the person does), and without it the lookup refuses `ambiguous` with
 *  the candidates (red team 23b). */
export async function findAccount(net: Net, paper: { sk: Uint8Array; pub: string }, hosts: string[] = [], o: { pick?: (cands: Found[]) => string | null } = {}): Promise<Found> {
  const cands = await findAccounts(net, paper, hosts);
  const gs = [...new Set(cands.found.map((c) => c.g))];
  if (gs.length === 1) return cands.found[0];
  if (gs.length > 1) {
    const g = o.pick?.(cands.found);
    const f = g ? cands.found.find((c) => c.g === g) : undefined;
    if (f) return f;
    throw Object.assign(new KeykinError('ambiguous', `this paper is the backup of ${gs.length} accounts: choose one`), { candidates: cands.found.map((c) => c.g) });
  }
  if (cands.unreachable) refuse('unreachable', 'the newest signpost\'s servers did not answer; try again later');
  return refuse('no_account', 'no server knows an account for this paper');
}
/** Every account found for this paper (each confirmed as `findAccount` says), and whether a signpost's servers didn't
 *  answer. */
export async function findAccounts(net: Net, paper: { sk: Uint8Array; pub: string }, hosts: string[] = []) {
  // The answers come back to the paper's key, so it is hosted while it asks (unless the caller already hosts it).
  const mine = !(net as any).hosted?.has?.(paper.pub);
  if (mine) { (net as any).revive?.(paper.pub); net.add({ kp: paper, handle: () => null }); }
  try { return await find(net, paper, hosts); } finally { if (mine) net.kill(paper.pub); }
}
export type Found = { g: string; epochId: string; servers: { key: string; host: string }[]; m: Membership };
const MAX_HINTS = 8, MAX_SERVERS = 16, MAX_SIGNERS = 8, MAX_POST_HOSTS = 8;
async function find(net: Net, paper: { sk: Uint8Array; pub: string }, hosts: string[]): Promise<{ found: Found[]; unreachable: boolean }> {
  const h = bytesToHex(sha(hexToBytes(paper.pub)));
  type Hint = { g: string; epoch: string; servers: string[] };
  // The hints a host gives: one entry per seat it holds for this key; each server key once.
  const ask = async (host: string): Promise<Hint[]> => {
    const ch = await net.send(paper, host, { type: 'challenge' }, { timeoutMs: 15_000 }).catch(() => null);
    if (ch?.type !== 'challenge' || typeof ch.challenge !== 'string') return [];
    const a = await net.send(paper, host, { type: 'seated?', h, challenge: ch.challenge, sig: schnorrSign(seatedAskDigest(h, ch.challenge), paper.sk) }, { timeoutMs: 15_000 }).catch(() => null);
    if (a?.type !== 'seated' || a.host !== host || !schnorrVerify(a.sig, seatedDigest(h, hexToBytes(ch.challenge), utf8ToBytes(a.ct)), host)) return [];
    try {
      const x = strictJson(nip44Open(a.ct, nip44.v2.utils.getConversationKey(paper.sk, host)));
      return (Array.isArray(x) ? x : []).filter((e: any) => /^[0-9a-f]{64}$/.test(e?.g ?? '') && typeof e?.epoch === 'string' && Array.isArray(e?.servers)).slice(0, MAX_HINTS)
        .map((e: any) => ({ g: e.g, epoch: e.epoch, servers: [...new Set<string>(e.servers.map((s: any) => s?.key).filter((k: any) => /^[0-9a-f]{64}$/.test(k ?? '')))].slice(0, MAX_SERVERS) }));
    } catch { return []; }
  };
  // A hint believed: two distinct servers return the same record (of `g`, at that epoch) and change set, both seated
  // servers of the membership it gives (a hint listing one key twice counts once), and the paper is its backup key.
  const confirm = async (hint: Hint): Promise<Found | null> => {
    const groups = new Map<string, { rec: NostrEvent; changes: NostrEvent[]; from: Set<string> }>();
    for (const key of hint.servers) {
      const a = await net.send(paper, key, msg('changes_get', hint.g, hint.epoch, 'ask'), { timeoutMs: 15_000 }).catch(() => null);
      if (a?.type !== 'changes' || !a.record || !Array.isArray(a.changes) || a.record.pubkey !== hint.g) continue;
      const k = `${a.record.id}:${a.changes.map((e: NostrEvent) => e?.id).sort().join(',')}`;
      const grp = groups.get(k) ?? { rec: a.record, changes: a.changes, from: new Set<string>() }; grp.from.add(key); groups.set(k, grp);
    }
    let best: Found | null = null;
    for (const grp of groups.values()) {
      if (grp.from.size < 2) continue;
      let m: Membership;
      try { const rec = checkEpochRecord(grp.rec, { g: hint.g }); if (rec.epoch.id !== hint.epoch) continue; m = computeMembership(rec, grp.changes); } catch { continue; }
      if (m.backupKey !== paper.pub) continue;
      const servers = [...m.seats.values()].filter((x) => x.holder?.kind === 'server' && !m.removed.has(x.holder.key)).map((x) => ({ key: x.holder!.key, host: x.holder!.host! }));
      if (servers.filter((x) => grp.from.has(x.key)).length < 2) continue;
      if (!best || signpostCount(m) > signpostCount(best.m)) best = { g: hint.g, epochId: m.epochId, servers, m };
    }
    return best;
  };
  const found = new Map<string, Found>();
  const keep = (r: Found) => { const o = found.get(r.g); if (!o || signpostCount(r.m) > signpostCount(o.m)) found.set(r.g, r); };
  // Route 1: every listed host (not only the first that answers: another account may share this paper).
  for (const host of [...new Set(hosts)]) for (const hint of await ask(host)) { const r = await confirm(hint); if (r) keep(r); }
  if (found.size) return { found: [...found.values()], unreachable: false };
  // Route 3: the signposts, for servers not on the app's list. Per signer, its highest `n` only, and never a lower one
  // because a newer signpost's servers didn't answer (a stale one could lead to an old or hostile host): the caller
  // retries. Another signer's signposts can't hide this account's (red team 23b).
  const events = net.events ? (await net.events.query({ kinds: [KIND_SIGNPOST], '#d': [signpostD(paper.pub)] })).events as NostrEvent[] : [];
  const bySigner = new Map<string, { e: NostrEvent; n: number; hosts: string[] }>();
  for (const e of events.filter((x) => verifyEvent(x))) {
    const nTag = e.tags.find((t) => t[0] === 'n')?.[1] ?? '';
    if (!/^(0|[1-9][0-9]{0,8})$/.test(nTag)) continue;
    let hs: string[];
    try {
      const c = strictJson(e.content);
      hs = [...new Set((strictJson(nip44Open(c.backup, nip44.v2.utils.getConversationKey(paper.sk, c.eph))) as any[]).map((sv) => sv?.host).filter((x) => typeof x === 'string'))].slice(0, MAX_POST_HOSTS) as string[];
    } catch { continue; }
    const o = bySigner.get(e.pubkey);
    if (!o || Number(nTag) > o.n || (Number(nTag) === o.n && e.created_at > o.e.created_at)) {
      if (!o && bySigner.size >= MAX_SIGNERS) continue;
      bySigner.set(e.pubkey, { e, n: Number(nTag), hosts: hs });
    }
  }
  let unreachable = false;
  for (const [signer, p] of bySigner) {
    let ok = false;
    for (const host of p.hosts) for (const hint of await ask(host)) {
      if (hint.g !== signer) continue;
      const r = await confirm(hint);
      // The signpost is the account's (signed by `g`), and the state found is at least as new as it says.
      if (r && signpostCount(r.m) >= p.n) { keep(r); ok = true; }
    }
    if (!ok) unreachable = true;
  }
  return { found: [...found.values()], unreachable };
}

export async function recoverWithPaper(net: Net, words: string[], o: { hosts?: string[]; name?: string; lock?: Lock | null; lost?: string[]; pollMs?: number; giveUpAt?: number;
  onWaiting?: (x: { endsBy: number }) => void; pick?: (cands: Found[]) => string | null } = {}): Promise<DeviceNode> {
  const sk = readBackupWords(words);
  const paper = { sk, pub: pubOf(sk) };
  // The paper's key is hosted for its exchanges (answers come back to it).
  const hosted: Node = { kp: paper, handle: () => null };
  net.add(hosted);
  try {
    const { g, epochId, servers } = await findAccount(net, paper, o.hosts ?? [], { pick: o.pick });
    const P = new PaperHolder(net, paper, g, epochId, servers.map((s) => s.key));
    const keys = servers.map((s) => s.key);
    await P.start(keys);
    o.onWaiting?.({ endsBy: net.now + W_DEFAULT });
    // The wait: each server releases once its own W has passed (a cancel from a device ends the recovery).
    let r: Awaited<ReturnType<PaperHolder['collect']>>;
    for (;;) {
      try { r = await P.collect(keys); break; } catch (e) { if ((e as any).code !== 'waited_missing') throw e; }
      if (o.giveUpAt && Date.now() > o.giveUpAt) refuse('waiting', `the recovery wait hasn't passed yet: ${[...P.started.values()].join('; ')}`);
      await new Promise((ok) => setTimeout(ok, o.pollMs ?? 60_000));
    }
    const seated = [...r!.m.seats.values()].filter((s) => s.holder && s.holder.kind === 'server').map((s) => s.holder!);
    const two = seated.slice(0, 2);
    // The new device's add, approved by `recovery`, co-signed by the paper and two servers (§4.4).
    const D = new DeviceNode(net, o.name ?? 'device', o.lock ?? null);
    const { salt, indices } = pickSalt(g, epochId, D.kp.pub, takenIndices(r!.m));
    const add: Change[] = [{ add: { key: D.kp.pub, kind: 'device', lock: D.lock?.pub ?? null, salt } }];
    const mk = (c: Change, list: Change[], ap: any) => ({ pubkey: g, created_at: net.now, kind: 24302, tags: [['v', '1'], ['epoch', epochId]],
      content: JSON.stringify({ v: 1, g, epoch: epochId, change: c, list, approval: ap }) });
    const addEv = await P.cosign(mk(add[0], add, P.approve(add, r!.waited)), two, r!.state);
    for (const s of seated) await net.send(paper, s.key, { type: 'change', events: [addEv], id: bytesToHex(randomBytes(16)) }, { timeoutMs: 15_000 }).catch(() => null);
    // Its indices repaired by the paper's backup seat and two servers, sealed to it (§4.4).
    const changes = [...r!.changes, addEv];
    const sigmas: any[] = [];
    const proxy = new DeviceNode(net, 'paper', null);
    proxy.kp = paper; proxy.state = { ids: r!.state, C: P.C!, shares: P.shares! };
    for (const i of indices) {
      const helpers = [{ key: paper.pub, indices: [...P.shares!.keys()] }, ...two.map((s) => ({ key: s.key, indices: s.shares }))];
      for (const w of await proxy.repairFor(helpers, i, D.kp.pub, 'add')) { const x = unwrap(D.kp.sk, w); sigmas.push({ ...x.body, from: x.from }); }
    }
    D.joiner = new Joiner({ n: D.kp.pub, lock: D.lock?.pub ?? null, now: net.now, scanned: { g, m: paper.pub, s: '00'.repeat(16), x: net.now + 600, r: [] } as any });
    const j = D.joiner.finish({ from: paper.pub, welcome: { record: r!.recEv, changes, state: [...r!.state] }, sigmas, recovery: { backup: paper.pub } });
    D.adopt(r!.recEv, changes, { ids: new Set(r!.state), C: j.C, shares: j.shares });
    for (const [k, v] of r!.seeds) D.seeds.set(k, v);
    D.base = r!.base; D.items = r!.items; D.baseDk = r!.dk; D.dkSeeds = [...r!.dkSeeds];
    D.recompute();
    net.add(D);
    // Report the lost devices and redeal, approved by `recovery`: this device deals, the paper co-signs.
    const lost = (o.lost ?? []).filter((k) => D.m!.devices.has(k) && !D.m!.removed.has(k) && k !== D.kp.pub);
    if (lost.length) {
      const list: Change[] = [...lost.map((k) => ({ remove: k }) as Change), { redeal: { dealer: D.kp.pub } }];
      await D.submit(list, P.approve(list, r!.waited), { cosigner: (evs, extra) => P.cosignAll(evs, two, r!.state, extra) });
    }
    // The holder's copies of the backup seat's shares and the release bundles go (§6.5 step 6).
    P.shares = null; P.bundles.clear();
    return D;
  } finally { net.kill(paper.pub); sk.fill(0); }
}
