// Joining by an invite code over real relays (core §4.1–§4.2), the joiner's side, as the Kotlin device's `Device.join`:
// the extension (or any TS device) scans or pastes another device's code, says hello, shows the 6 digits the person types
// there, then takes the inviter's welcome and the repair sigmas (one from the inviter, one from a server) and builds
// its shares. Until the welcome, a small joining node on the transport collects them; then the device itself is hosted.

import { DeviceNode } from './node.ts';
import { Joiner, parseCode } from '../src/join.ts';
import { refuse, KeykinError } from '../src/bytes.ts';
import type { Lock } from '../src/lock.ts';
import type { Transport, Node } from '../runtime/net.ts';

/** Sigmas a stranger can make the joiner keep: bounded (review 12 L2). */
const SIGMAS_MAX = 64;

export async function joinByCode(net: Transport & { add<N extends Node>(n: N): N; kill(pub: string): void }, code: string,
  o: { onCheck: (digits: string) => void; lock?: Lock | null; timeoutMs?: number; name?: string }): Promise<DeviceNode> {
  const d = new DeviceNode(net, o.name ?? 'device', o.lock ?? null);
  const invite = parseCode(code);
  if (invite.kind !== 'join') refuse('malformed', 'not an invite code');
  const j = new Joiner({ n: d.kp.pub, lock: d.lock?.pub ?? null, now: net.now, scanned: invite as any });
  const got: { welcome?: { from: string; body: any } } = {};
  const sigmas = new Map<string, any>();
  // Only the inviter's welcome counts: `n` is public, and a stranger's would abort the join (review 12 K1).
  const joining: Node = { kp: d.kp, handle: (from: string, body: any) => {
    if (body?.type === 'repair_sigma') {
      const key = `${from}:${body.index}`;
      if (from === j.m || sigmas.size < SIGMAS_MAX) if (!sigmas.has(key)) sigmas.set(key, { ...body, from });
      return { type: 'ack' };
    }
    if (body?.type === 'welcome' && from === j.m) { got.welcome = { from, body }; return { type: 'ack' }; }
    return null;
  } };
  net.add(joining);
  const deadline = Date.now() + (o.timeoutMs ?? 120_000);
  let r: ReturnType<Joiner['finish']>;
  try {
    const h = j.hello();
    const nonce = await net.send(d.kp, h.to, h.msg);
    if (nonce?.type !== 'join_nonce') refuse(nonce?.code ?? 'no_nonce');
    j.onNonce(h.to, nonce);
    o.onCheck(j.check);
    // The welcome, and every sigma it needs: the welcome may overtake a server's sigma on the relays.
    for (;;) {
      if (Date.now() > deadline) refuse('timeout', 'no welcome from the inviting device');
      const wl = got.welcome;
      if (wl) {
        try { r = j.finish({ from: wl.from, welcome: wl.body, sigmas: [...sigmas.values()] }); break; }
        catch (e) { if ((e as KeykinError).code !== 'sigma_missing') throw e; }
      }
      await new Promise((ok) => setTimeout(ok, 200));
    }
  } finally { net.kill(d.kp.pub); }
  const w = got.welcome!.body;
  d.adopt(w.record, w.changes, { ids: new Set(w.state), C: r!.C, shares: r!.shares });
  // What a device holds of the account (core §4.2 step 4, §4.5, §7.2): the base data key and every seed.
  d.baseDk = typeof w.base_dk === 'string' ? w.base_dk : '';
  d.takeSeedRecords(w.dk);
  for (const x of Array.isArray(w.seeds) ? w.seeds : []) if (Array.isArray(x) && x.length === 2) d.seeds.set(x[0], x[1]);
  if (Array.isArray(w.items)) d.items = w.items;
  if (w.base) d.base = w.base;
  d.recompute();
  net.add(d);
  // §4.2 step 5: an ack to the inviter and to every server; the sigmas go.
  sigmas.clear();
  const servers = [...d.m!.members.values()].filter((x) => x.kind === 'server').map((x) => x.key);
  await Promise.all([got.welcome!.from, ...servers].map((k) => net.send(d.kp, k, { type: 'ack' }, { timeoutMs: 5000 }).catch(() => null)));
  return d;
}
