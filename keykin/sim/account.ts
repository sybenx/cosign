// Whole-account flows over the simulated bus: create (by import, §11.2), invite a device (§4),
// fill a seat (§6.7.4), recover with the paper (§6.5, §4.4).

import { bytesToHex, randomBytes, sha, refuse } from '../src/bytes.ts';
import { helperSeat, pickSalt, stateHash } from '../src/codes.ts';
import { deal } from '../src/frost.ts';
import { commitmentHex, xOnly, scalarHex } from '../src/curve.ts';
import { finalizeEvent } from 'nostr-tools/pure';
import { Inviter, Joiner, parseCode } from '../src/join.ts';
import { takenIndices } from '../src/membership.ts';
import { itemHash } from '../src/redeal.ts';
import { baseItem } from '../src/upkeep.ts';
import { unwrap, wrap } from '../src/transport.ts';
import { softLock } from '../src/lock.ts';
import { newKey, type KeyPair, type NostrEvent } from '../src/event.ts';
import { KIND_EPOCH, type Approval, type Change, type EpochContent, type MemberEntry } from '../src/types.ts';
import { Bus, type Transport } from './bus.ts';
import { DeviceNode, ServerNode, PaperHolder } from './nodes.ts';

let seq = 0;
export interface Net extends Transport { add(n: any): any }
export interface Account { bus: Bus; A: DeviceNode; servers: ServerNode[]; paper: KeyPair; g: string; epochId: string }

/** §11.2 import: the device deals an nsec it holds into shares, signs the epoch record with it, welcomes
 *  the servers and the paper, then forgets the nsec. */
export async function create(o: { lockless?: boolean; net?: Net } = {}): Promise<Account> {
  const bus = (o.net ?? new Bus()) as Bus;
  const A = bus.add(new DeviceNode(bus, 'A', o.lockless ? null : softLock())) as DeviceNode;
  const servers = [4, 7, 8].map((_, k) => bus.add(new ServerNode(bus, `S${k + 1}`)) as ServerNode);
  const paper = newKey();
  const nsec = BigInt('0x' + bytesToHex(randomBytes(32)));
  const d = deal(nsec, [1, 2, 3, 4, 7, 8, 5, 6]);
  const g = xOnly(d.commitment[0]);
  const epochId = bytesToHex(randomBytes(16));
  const baseSeed = bytesToHex(randomBytes(32)), baseDk = bytesToHex(randomBytes(32));
  const base = baseItem(paper, baseSeed, new Map([[5, d.shares.get(5)!], [6, d.shares.get(6)!]]), baseDk, []);
  const members: MemberEntry[] = [
    { key: A.kp.pub, kind: 'device', shares: [1, 2, 3], ...(A.lock ? { lock: A.lock.pub } : {}) },
    ...servers.map((s, k) => s.entry([4, 7, 8][k])),
    { key: paper.pub, kind: 'backup', shares: [5, 6] },
  ];
  const rec: EpochContent = { v: 1, g, epoch: { n: 1, id: epochId }, prev: null, t: 4, commitment: commitmentHex(d.commitment), role: 'master', origin: 'import',
    relays: ['wss://r1.test', 'wss://r2.test', 'wss://r3.test'], members, removed: [], backup: itemHash(base), seats: { servers: [4, 7, 8], backup: [5, 6], helper: helperSeat(g) } };
  const recEv = finalizeEvent({ kind: KIND_EPOCH, created_at: bus.now, tags: [['d', 'keykin'], ['v', '1'], ['epoch', '1']], content: JSON.stringify(rec) },
    Uint8Array.from(Buffer.from(scalarHex(d.secret), 'hex'))) as NostrEvent;
  A.adopt(recEv, [], { ids: new Set(), C: d.commitment, shares: new Map([1, 2, 3].map((i) => [i, d.shares.get(i)!])) });
  A.seeds.set('base', baseSeed); A.base = base; A.baseDk = baseDk;
  for (const [k, s] of servers.entries()) {
    const a = await bus.send(A.kp, s.kp.pub, { type: 'seat_welcome', w: { recEv, changes: [], state: [], share: [[4, 7, 8][k], scalarHex(d.shares.get([4, 7, 8][k])!)], seeds: [['base', baseSeed]], items: [], base } });
    if (a?.type !== 'ack') refuse(a?.code ?? 'welcome_failed', a?.detail);
  }
  d.shares.clear();                                                   // the dealer forgets everything but A's own shares
  return { bus, A, servers, paper, g, epochId };
}

/** Invite a new device (§4.2), invite direction. `approve` makes the add's approval. Returns the joined device. */
export async function invite(acc: Account, inviter: DeviceNode, approve: (list: Change[]) => Approval, o: { lock?: boolean; via?: number; racer?: boolean } = {}): Promise<DeviceNode> {
  const { bus } = acc;
  const B = bus.add(new DeviceNode(bus, `D${++seq}`, o.lock ? softLock() : null)) as DeviceNode;
  inviter.inviter = new Inviter({ g: inviter.g, m: inviter.kp.pub, now: bus.now });
  const code = parseCode(inviter.inviter.invite(inviter.rec!.relays)) as any;
  B.joiner = new Joiner({ n: B.kp.pub, lock: B.lock?.pub ?? null, now: bus.now, scanned: code });
  const h = B.joiner.hello();
  const nonce = await bus.send(B.kp, h.to, h.msg);
  if (nonce?.type !== 'join_nonce') refuse(nonce?.code ?? 'no_nonce');
  B.joiner.onNonce(inviter.kp.pub, nonce);
  if (!inviter.inviter.typed(B.joiner.check)) refuse('check_mismatch');
  const { salt, indices } = pickSalt(inviter.g, inviter.epochId, B.kp.pub, takenIndices(inviter.m!));
  const add: Change = { add: { key: B.kp.pub, kind: 'device', lock: B.lock?.pub ?? null, salt } };
  await inviter.submit([add], approve([add]));
  const server = inviter.servers().filter((s) => bus.alive(s.key))[o.via ?? 0];
  const sigmas: any[] = [];
  for (const i of indices) for (const w of await inviter.repairFor([{ key: inviter.kp.pub, indices: [...inviter.state!.shares.keys()] }, { key: server.key, indices: server.shares }], i, B.kp.pub, 'add'))
    sigmas.push({ ...unwrap(B.kp.sk, w).body, from: unwrap(B.kp.sk, w).from });
  const welcome = { record: inviter.recEv!, changes: inviter.changes, state: [...inviter.state!.ids] };
  const sealed = wrap(inviter.kp.sk, B.kp.pub, { type: 'welcome', ...welcome });
  const opened = unwrap(B.kp.sk, sealed);
  const r = B.joiner.finish({ from: opened.from, welcome: opened.body, sigmas });
  B.adopt(inviter.recEv!, inviter.changes, { ids: new Set(inviter.state!.ids), C: r.C, shares: r.shares });
  for (const [k, v] of inviter.seeds) B.seeds.set(k, v);
  B.base = inviter.base; B.items = [...inviter.items]; B.baseDk = inviter.baseDk; B.dkSeeds = [...inviter.dkSeeds];
  return B;
}

/** Seat a new server (F1/F4): `[seat i→Y, redeal]` with one approval, then the repair of the seat
 *  at the new state by the device and one live server (§6.7.6). */
export async function replaceServer(acc: Account, dev: DeviceNode, oldIdx: number, approve: (list: Change[]) => Approval): Promise<ServerNode> {
  const { bus } = acc;
  const Y = bus.add(new ServerNode(bus, `Y${++seq}`)) as ServerNode;
  const old = dev.m!.seats.get(`server:${oldIdx}`)!.holder;
  const list: Change[] = [{ seat: { seat: `server:${oldIdx}`, new: Y.entry(oldIdx), replaces: old?.key ?? null } }, { redeal: { dealer: dev.kp.pub } }];
  const signed = await dev.submit(list, approve(list), { deliverTo: [...dev.servers().map((s) => s.key), Y.kp.pub, ...(old ? [old.key] : [])] });
  void signed;
  // The newcomer's welcome (no share yet), then `need_repair` answered by the device and a live server.
  const wa = await bus.send(dev.kp, Y.kp.pub, { type: 'seat_welcome', w: { recEv: dev.recEv!, changes: dev.changes, state: [...dev.state!.ids], seeds: [...dev.seeds], items: dev.items, base: dev.base! } });
  if (wa?.type !== 'ack') refuse(wa?.code ?? 'welcome_failed', wa?.detail);
  const helper = dev.servers().find((s) => s.key !== Y.kp.pub && bus.alive(s.key))!;
  const sigmas = await dev.repairFor([{ key: dev.kp.pub, indices: [...dev.state!.shares.keys()] }, { key: helper.key, indices: helper.shares }], oldIdx, Y.kp.pub, 'seat');
  await bus.send(dev.kp, Y.kp.pub, { type: 'seat_fill', sigmas, state: [...dev.state!.ids] });
  return Y;
}

/** Paper-only recovery (§6.5, §4.4, F9): wait, open the material, recovery-join a new device, then
 *  report `lost` and redeal under `recovery` approvals the holder co-signs in its session. */
export async function recover(acc: Account, lost: DeviceNode[], paper: KeyPair = acc.paper) {
  const { bus } = acc;
  const anyServer = acc.servers.find((s) => s.co && !s.retired && bus.alive(s.kp.pub))!;
  const servers = [...anyServer.m.seats.values()].filter((s) => s.holder && bus.alive(s.holder.key)).map((s) => s.holder!);
  const P = new PaperHolder(bus, paper, acc.g, acc.epochId, servers.map((s) => s.key));
  await P.start(servers.map((s) => s.key));
  bus.advance(3 * 86400 + 1);
  const r = await P.collect(servers.map((s) => s.key));
  const two = servers.slice(0, 2);
  // Recovery join: the new device's add, approved by `recovery`, co-signed by backup + two servers.
  const D = bus.add(new DeviceNode(bus, 'R', softLock())) as DeviceNode;
  const { salt, indices } = pickSalt(acc.g, acc.epochId, D.kp.pub, takenIndices(r.m));
  const add: Change[] = [{ add: { key: D.kp.pub, kind: 'device', lock: D.lock!.pub, salt } }];
  const mk = (c: Change, list: Change[], ap: Approval) => ({ pubkey: acc.g, created_at: bus.now, kind: 24302, tags: [['v', '1'], ['epoch', acc.epochId]],
    content: JSON.stringify({ v: 1, g: acc.g, epoch: acc.epochId, change: c, list, approval: ap }) });
  const addEv = await P.cosign(mk(add[0], add, P.approve(add, r.waited)), two, r.state);
  for (const s of servers) await bus.send(P.kp, s.key, { type: 'change', events: [addEv] });
  // Repair the new device's indices: helpers backup (2) and two servers (§4.4).
  const changes = [...r.changes, addEv];
  const sigmas: any[] = [];
  const holderHelper = { kept: new Map<string, string[]>() };
  void holderHelper;
  for (const i of indices) {
    const helpers = [{ key: P.kp.pub, indices: [...P.shares!.keys()] }, ...two.map((s) => ({ key: s.key, indices: s.shares }))];
    const proxy = new DeviceNode(bus, 'proxy', null);
    proxy.kp = P.kp; proxy.state = { ids: r.state, C: P.C!, shares: P.shares! };
    for (const w of await proxy.repairFor(helpers, i, D.kp.pub, 'add')) { const o = unwrap(D.kp.sk, w); sigmas.push({ ...o.body, from: o.from }); }
  }
  D.joiner = new Joiner({ n: D.kp.pub, lock: D.lock!.pub, now: bus.now, scanned: { g: acc.g, m: P.kp.pub, s: '00'.repeat(16), x: bus.now + 600, r: [] } });
  const welcome = unwrap(D.kp.sk, wrap(P.kp.sk, D.kp.pub, { type: 'welcome', record: r.recEv, changes, state: [...r.state] }));
  const j = D.joiner.finish({ from: welcome.from, welcome: welcome.body, sigmas, recovery: { backup: P.kp.pub } });
  D.adopt(r.recEv, changes, { ids: new Set(r.state), C: j.C, shares: j.shares });
  for (const [k, v] of r.seeds) D.seeds.set(k, v);
  D.base = r.base; D.items = r.items; D.baseDk = r.dk;
  // F9: report the lost devices and redeal, approved by `recovery`; D deals, the holder co-signs.
  if (lost.length) {
    const list: Change[] = [...lost.map((l) => ({ remove: l.kp.pub }) as Change), { redeal: { dealer: D.kp.pub } }];
    await D.submit(list, P.approve(list, r.waited), { cosigner: (evs, extra) => P.cosignAll(evs, two, r.state, extra) });
  }
  // The recovery app destroys the backup's shares and the release bundle (§6.5 step 6).
  P.shares = null; P.bundles.clear();
  return { D, P };
}
export { sha, stateHash };

/** F3, every server dead (§6.7.6): `[seat×3, redeal]` approved by `pair`, co-signed by a second
 *  device (no current seat holder can), then every seat filled by the two devices (6 points). */
export async function replaceAllServers(acc: Account, A: DeviceNode, B: DeviceNode, approve: (list: Change[]) => Approval): Promise<ServerNode[]> {
  const { bus } = acc;
  const idx = A.m!.record.seats.servers;
  const Ys = idx.map(() => bus.add(new ServerNode(bus, `Y${++seq}`)) as ServerNode);
  const list: Change[] = [...idx.map((i, k) => ({ seat: { seat: `server:${i}`, new: Ys[k].entry(i), replaces: A.m!.seats.get(`server:${i}`)!.holder?.key ?? null } }) as Change),
    { redeal: { dealer: A.kp.pub } }];
  const { ListCall } = await import('../src/coordinator.ts');
  await A.submit(list, approve(list), { deliverTo: Ys.map((y) => y.kp.pub), cosigner: async (evs, extra) => {
    const r = new ListCall(A.ctx(), A.me(), { key: B.kp.pub, indices: [...B.state!.shares.keys()] }, evs, extra as any);
    return r.finish(await bus.send(A.kp, B.kp.pub, r.request));
  } });
  for (const [k, Y] of Ys.entries()) {
    const wa = await bus.send(A.kp, Y.kp.pub, { type: 'seat_welcome', w: { recEv: A.recEv!, changes: A.changes, state: [...A.state!.ids], seeds: [...A.seeds], items: A.items, base: A.base! } });
    if (wa?.type !== 'ack') refuse(wa?.code ?? 'welcome_failed', wa?.detail);
    const sigmas = await A.repairFor([{ key: A.kp.pub, indices: [...A.state!.shares.keys()] }, { key: B.kp.pub, indices: [...B.state!.shares.keys()] }], idx[k], Y.kp.pub, 'seat');
    await bus.send(A.kp, Y.kp.pub, { type: 'seat_fill', sigmas, state: [...A.state!.ids] });
  }
  return Ys;
}
