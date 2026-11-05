// Joining over real relays (core §4.1–§4.2), the joiner's side, as the Kotlin device's `Device.join`, both directions:
//   joinByCode    the extension (or any TS device) scans or pastes another device's invite code and says hello;
//   joinByShowing it shows its own hello code (a QR the phone scans), and the phone's offer arrives.
// Either way it shows the 6 digits the person types on the other device, then takes the inviter's welcome and the
// repair sigmas (one from the inviter, one from a server) and builds its shares. Until the welcome, a small joining node
// on the transport collects them; then the device itself is hosted.

import { DeviceNode } from './node.ts';
import { Joiner, parseCode } from '../src/join.ts';
import { refuse, KeykinError } from '../src/bytes.ts';
import type { Lock } from '../src/lock.ts';
import type { Transport, Node } from '../runtime/net.ts';

/** Sigmas a stranger can make the joiner keep: bounded (review 12 L2). */
const SIGMAS_MAX = 64;

type Net = Transport & { add<N extends Node>(n: N): N; kill(pub: string): void };
type JoinOptions = { onCheck: (digits: string) => void; lock?: Lock | null; timeoutMs?: number; name?: string };

/** Join with another device's invite code (`keykin:join?…`). */
export async function joinByCode(net: Net, code: string, o: JoinOptions): Promise<DeviceNode> {
  const invite = parseCode(code);
  if (invite.kind !== 'join') refuse('malformed', 'not an invite code');
  return join(net, o, (d) => new Joiner({ n: d.kp.pub, lock: d.lock?.pub ?? null, now: net.now, scanned: invite as any }), true);
}
/** Join by showing this device's own hello code (`keykin:hello?…`, over `relays`) for another device to scan: `onCode`
 *  gets the code to show as a QR. The other device's offer starts the exchange. */
export async function joinByShowing(net: Net, relays: string[], o: JoinOptions & { onCode: (code: string) => void }): Promise<DeviceNode> {
  return join(net, o, (d) => { const j = new Joiner({ n: d.kp.pub, lock: d.lock?.pub ?? null, now: net.now }); o.onCode(j.helloCode(relays)); return j; }, false);
}

async function join(net: Net, o: JoinOptions, make: (d: DeviceNode) => Joiner, sayHello: boolean): Promise<DeviceNode> {
  const d = new DeviceNode(net, o.name ?? 'device', o.lock ?? null);
  const j = make(d);
  const got: { welcome?: { from: string; body: any } } = {};
  const sigmas = new Map<string, any>();
  // Only the inviter's welcome counts: `n` is public, and a stranger's would abort the join (review 12 K1). In the
  // join-code direction the offer names the inviter; its nonce comes after the hello, and the digits with it.
  const joining: Node = { kp: d.kp, handle: (from: string, body: any) => {
    if (body?.type === 'welcome_offer' && !sayHello) { try { return j.onOffer(from, body, net.now).msg; } catch { return null; } }
    if (body?.type === 'join_nonce' && !sayHello) { try { j.onNonce(from, body); o.onCheck(j.check); return { type: 'ack' }; } catch { return null; } }
    if (body?.type === 'repair_sigma') {
      const key = `${from}:${body.index}`;
      if (from === j.m || sigmas.size < SIGMAS_MAX) if (!sigmas.has(key)) sigmas.set(key, { ...body, from });
      return { type: 'ack' };
    }
    if (body?.type === 'welcome' && j.m && from === j.m) { got.welcome = { from, body }; return { type: 'ack' }; }
    return null;
  } };
  net.add(joining);
  const deadline = Date.now() + (o.timeoutMs ?? (sayHello ? 120_000 : 600_000));
  let r: ReturnType<Joiner['finish']>;
  try {
    if (sayHello) {
      const h = j.hello();
      const nonce = await net.send(d.kp, h.to, h.msg);
      if (nonce?.type !== 'join_nonce') refuse(nonce?.code ?? 'no_nonce');
      j.onNonce(h.to, nonce);
      o.onCheck(j.check);
    }
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
