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
  const paper = newKey();
  const nsec = BigInt('0x' + bytesToHex(randomBytes(32)));
  const d = deal(nsec, [1, 2, 3, 4, 7, 8, 5, 6]);
  const g = xOnly(d.commitment[0]);
  // Pick and enrol the servers (Account admin §1.2 step 3, Server profile §4).
  const servers = [4, 7, 8].map((_, k) => { const s = new ServerNode(bus, `S${k + 1}`); s.enroll(g, bus.now); return bus.add(s) as ServerNode; });
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
  const Y0 = new ServerNode(bus, `Y${++seq}`); Y0.enroll(dev.g, bus.now);
  const Y = bus.add(Y0) as ServerNode;
  const old = dev.m!.seats.get(`server:${oldIdx}`)!.holder;
  const list: Change[] = [{ seat: { seat: `server:${oldIdx}`, new: Y.entry(oldIdx), replaces: old?.key ?? null } }, { redeal: { dealer: dev.kp.pub } }];
  const signed = await dev.submit(list, approve(list), { deliverTo: [...dev.servers().map((s) => s.key), Y.kp.pub, ...(old ? [old.key] : [])] });
  void signed;
  // The newcomer's welcome (no share yet), then `need_repair` answered by the device and a live server.
  // Devices re-send stops to every incoming seat holder (core §5.7): from a live peer's view of them.
  const peer = acc.servers.find((x) => x.co && !x.retired && bus.alive(x.kp.pub));
  const stops = peer ? [...peer.co!.stops] : [], cleared = peer ? [...peer.co!.clearedStops] : [];
  const wa = await bus.send(dev.kp, Y.kp.pub, { type: 'seat_welcome', w: { recEv: dev.recEv!, changes: dev.changes, state: [...dev.state!.ids], seeds: [...dev.seeds], items: dev.items, base: dev.base!, stops, cleared } });
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
  D.base = r.base; D.items = r.items; D.baseDk = r.dk; D.dkSeeds = [...r.dkSeeds];
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
  const Ys = idx.map(() => { const y = new ServerNode(bus, `Y${++seq}`); y.enroll(A.g, bus.now); return bus.add(y) as ServerNode; });
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

/** F6, the helper (§6.7.6): `[seat helper→H, redeal]` with one approval, then the device and one
 *  server repair the helper's three seat indices, sealed to H. (The typed join check is §4.1's.) */
export async function addHelper(acc: Account, dev: DeviceNode, approve: (list: Change[]) => Approval, operator = newKey().pub): Promise<DeviceNode> {
  const { bus } = acc;
  const H = bus.add(new DeviceNode(bus, `H${++seq}`, null)) as DeviceNode;
  H.role = 'helper';
  const seat = dev.m!.record.seats.helper;
  const entry: MemberEntry = { key: H.kp.pub, kind: 'helper', shares: seat, host: newKey().pub, operator };
  const list: Change[] = [{ seat: { seat: 'helper', new: entry, replaces: dev.m!.seats.get('helper')?.holder?.key ?? null } }, { redeal: { dealer: dev.kp.pub } }];
  await dev.submit(list, approve(list));
  const server = dev.servers().find((x) => bus.alive(x.key))!;
  const shares = new Map<number, bigint>();
  const sigmaFrom: string[] = [];
  for (const i of seat) {
    const ws = await dev.repairFor([{ key: dev.kp.pub, indices: [...dev.state!.shares.keys()] }, { key: server.key, indices: server.shares }], i, H.kp.pub, 'seat');
    shares.set(i, (await import('../src/frost.ts')).repairShare(dev.state!.C, ws.map((w) => unwrap(H.kp.sk, w).body.sigma), i));
    for (const w of ws) sigmaFrom.push(unwrap(H.kp.sk, w).from);
  }
  H.adopt(dev.recEv!, dev.changes, { ids: new Set(dev.state!.ids), C: dev.state!.C, shares });
  for (const i of seat) for (const k of new Set(sigmaFrom)) await bus.send(H.kp, k, { type: 'repair_ok', participant: i });
  for (const [k, v] of dev.seeds) H.seeds.set(k, v);       // release seeds only: a helper never gets the data key
  return H;
}

/** Account admin §1.1: a fresh account by DKG. The device runs indices 1, 2, 3 and the backup seat's
 *  5, 6; three servers run 4, 7, 8 under throwaway DKG keys. The device signs the epoch record alone with
 *  its five points, every server adopts it provisionally, and the device's confirmation makes it live. */
export async function createByDkg(o: { lockless?: boolean; net?: Net } = {}): Promise<Account> {
  const bus = (o.net ?? new Bus()) as Bus;
  const A = bus.add(new DeviceNode(bus, 'A', o.lockless ? null : softLock())) as DeviceNode;
  const servers = [1, 2, 3].map((k) => bus.add(new ServerNode(bus, `S${k}`)) as ServerNode);
  const { dkg1, dkg2, dkg3, dkgCommitment } = await import('../src/dkg.ts');
  const { schnorrVerify } = await import('../src/event.ts');
  const { commit, signShare, aggregate, hedge } = await import('../src/frost.ts');
  const { eventId } = await import('../src/event.ts');
  const sIdx = [4, 7, 8], mine = [1, 2, 3, 5, 6], all = [...mine, ...sIdx].sort((a, b) => a - b);
  // 1. create: each server's throwaway DKG key, signed by its host key.
  const dkgKeys: Record<number, string> = {};
  for (const [k, s] of servers.entries()) {
    const a = await bus.send(A.kp, s.kp.pub, { type: 'create' });
    if (a?.type !== 'create_ok' || !schnorrVerify(a.host_sig, sha('keykin-dkg-key/1', Uint8Array.from(Buffer.from(a.dkg_key, 'hex'))), a.host)) refuse('create_failed');
    dkgKeys[sIdx[k]] = a.dkg_key;
  }
  // 2. Round 1, relayed by the device so everyone sees the same packages.
  const r1 = new Map<number, string>(), secrets = new Map<number, string>();
  for (const i of mine) { const r = dkg1(i, all.length, randomBytes(32)); r1.set(i, r.package); secrets.set(i, r.secret); }
  for (const [k, s] of servers.entries()) r1.set(sIdx[k], (await bus.send(A.kp, s.kp.pub, { type: 'dkg_1', index: sIdx[k], max: all.length })).package);
  const others = (i: number) => [...r1].filter(([j]) => j !== i);
  // 3. Round 2: packages to each holder (server-to-server ones sealed to the recipient's DKG key).
  const r2 = new Map<number, Map<number, any>>(all.map((i) => [i, new Map()]));
  const s2 = new Map<number, string>();
  for (const i of mine) { const r = dkg2(secrets.get(i)!, new Map(others(i))); s2.set(i, r.secret); for (const [j, p] of r.packages) r2.get(j)!.set(i, p); }
  secrets.clear();
  for (const [k, s] of servers.entries()) {
    const a = await bus.send(A.kp, s.kp.pub, { type: 'dkg_2', round1: others(sIdx[k]), dkg_keys: dkgKeys });
    for (const [j, p] of a.packages as [number, any][]) r2.get(j)!.set(sIdx[k], p);
  }
  // 4. Round 3.
  const shares = new Map<number, bigint>(); let g = '', points = new Map<number, string>();
  for (const i of mine) { const r = dkg3(s2.get(i)!, new Map(others(i)), r2.get(i)!); shares.set(i, r.share); g = r.g; points = r.points; }
  s2.clear();
  for (const [k, s] of servers.entries()) {
    const a = await bus.send(A.kp, s.kp.pub, { type: 'dkg_3', round1: others(sIdx[k]), round2: [...r2.get(sIdx[k])!] });
    if (a.g !== g) refuse('dkg', 'servers disagree on the group key');
  }
  const C = dkgCommitment(g, points);
  // 5. Enrol, now that g exists (Server profile §4).
  for (const s of servers) { const a = await bus.send(A.kp, s.kp.pub, { type: 'enroll', g }); if (a?.type !== 'enroll_reply') refuse('enroll_failed'); }
  // 6. The backup: base item of the backup seat's shares, under the creation release seed.
  const paper = newKey();
  const baseSeed = bytesToHex(randomBytes(32)), baseDk = bytesToHex(randomBytes(32));
  const base = baseItem(paper, baseSeed, new Map([[5, shares.get(5)!], [6, shares.get(6)!]]), baseDk, []);
  const epochId = bytesToHex(randomBytes(16));
  const members: MemberEntry[] = [
    { key: A.kp.pub, kind: 'device', shares: [1, 2, 3], ...(A.lock ? { lock: A.lock.pub } : {}) },
    ...servers.map((s, k) => s.entry(sIdx[k])), { key: paper.pub, kind: 'backup', shares: [5, 6] }];
  const rec: EpochContent = { v: 1, g, epoch: { n: 1, id: epochId }, prev: null, t: 4, commitment: commitmentHex(C), role: 'master', origin: 'dkg',
    relays: ['wss://r1.test', 'wss://r2.test', 'wss://r3.test'], members, removed: [], backup: itemHash(base), seats: { servers: sIdx, backup: [5, 6], helper: helperSeat(g) } };
  // 7. The device signs the record alone with four of its five points (no co-signer knows the account yet).
  const unsigned = { pubkey: g, created_at: bus.now, kind: KIND_EPOCH, tags: [['d', 'keykin'], ['v', '1'], ['epoch', '1']], content: JSON.stringify(rec) };
  const id = eventId(unsigned);
  const signers = [1, 2, 3, 5];
  const cs = signers.map((i) => commit(C, i, shares.get(i)!, hedge(shares.get(i)!, sha(id, String(i)))));
  const commits = cs.map((c) => c.commit);
  const sig = aggregate(C, id, commits, cs.map((c) => ({ i: c.commit.i, z: signShare(C, c.commit.i, shares.get(c.commit.i)!, c.nonces, id, commits) })));
  const recEv = { ...unsigned, id, sig } as NostrEvent;
  // 8. Welcome every server, provisionally; then confirm once all adopted.
  for (const s of servers) {
    const a = await bus.send(A.kp, s.kp.pub, { type: 'seat_welcome', w: { recEv, changes: [], state: [], seeds: [['base', baseSeed]], items: [], base, provisional: true } });
    if (a?.type !== 'ack') refuse(a?.code ?? 'welcome_failed', a?.detail);
  }
  A.adopt(recEv, [], { ids: new Set(), C, shares: new Map([1, 2, 3].map((i) => [i, shares.get(i)!])) });
  A.seeds.set('base', baseSeed); A.base = base; A.baseDk = baseDk;
  for (const s of servers) { const a = await bus.send(A.kp, s.kp.pub, { type: 'confirm', epoch: epochId }); if (a?.type !== 'ack') refuse(a?.code ?? 'confirm_failed'); }
  // The backup seat's shares were only ever in this device (5 points until "Write it down" or "Not now").
  shares.clear();
  return { bus, A, servers, paper, g, epochId };
}
