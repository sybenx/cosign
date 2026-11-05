// Joining over real relays (core §4.1–§4.2), the joiner's side, as the Kotlin device's `Device.join`, both directions:
//   joinByCode    the extension (or any TS device) scans or pastes another device's invite code and says hello;
//   joinByShowing it shows its own hello code (a QR the phone scans), and the phone's offer arrives.
// The side that scanned shows the 6 digits, and the person types them on the side that showed the code (core 14.24):
// by code, this device shows them (`onCheck`); by showing, the phone shows them and `askDigits` gets what the person
// typed here, then `join_confirm` tells the phone. Either way it then takes the inviter's welcome and the
// repair sigmas (one from the inviter, one from a server) and builds its shares. Until the welcome, a small joining node
// on the transport collects them; then the device itself is hosted.

import { DeviceNode } from './node.ts';
import { Joiner, parseCode } from '../src/join.ts';
import { checkEpochRecord } from '../src/record.ts';
import { computeMembership } from '../src/membership.ts';
import { refuse, KeykinError } from '../src/bytes.ts';
import type { Lock } from '../src/lock.ts';
import type { Transport, Node } from '../runtime/net.ts';

/** The typed digits against the expected, in constant time (as Kotlin's). */
const sameDigits = (a: string, b: string) => { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; };
/** Sigmas a stranger can make the joiner keep: bounded (review 12 L2). */
const SIGMAS_MAX = 64;

type Net = Transport & { add<N extends Node>(n: N): N; kill(pub: string): void };
type Common = { lock?: Lock | null; timeoutMs?: number; name?: string };
/** How many times the person may type the phone's digits before the join stops. */
const TRIES = 3;

/** Join with another device's invite code (`keykin:join?…`). */
export async function joinByCode(net: Net, code: string, o: Common & { onCheck: (digits: string) => void }): Promise<DeviceNode> {
  const invite = parseCode(code);
  if (invite.kind !== 'join') refuse('malformed', 'not an invite code');
  return join(net, o, (d) => new Joiner({ n: d.kp.pub, lock: d.lock?.pub ?? null, now: net.now, scanned: invite as any }), true);
}
/** Join by showing this device's own hello code (`keykin:hello?…`, over `relays`) for another device to scan: `onCode`
 *  gets the code to show as a QR. The other device's offer starts the exchange; that device then shows 6 digits, and
 *  `askDigits(attempt)` returns what the person typed here (3 tries; a wrong one says so with `attempt` > 1). */
export async function joinByShowing(net: Net, relays: string[], o: Common & { onCode: (code: string) => void; askDigits: (attempt: number) => Promise<string> }): Promise<DeviceNode> {
  return join(net, o, (d) => { const j = new Joiner({ n: d.kp.pub, lock: d.lock?.pub ?? null, now: net.now }); o.onCode(j.helloCode(relays)); return j; }, false);
}

/** The server keys of a welcome's membership (only to choose which sigmas to keep; `finish` checks it all again). */
function welcomeServers(w: any): Set<string> | null {
  if (!w?.record) return null;
  try {
    const m = computeMembership(checkEpochRecord(w.record, { g: w.record.pubkey }), Array.isArray(w.changes) ? w.changes : []);
    return new Set([...m.members.values()].filter((x) => x.kind === 'server').map((x) => x.key));
  } catch { return null; }
}

async function join(net: Net, o: Common & { onCheck?: (digits: string) => void; askDigits?: (attempt: number) => Promise<string> }, make: (d: DeviceNode) => Joiner, sayHello: boolean): Promise<DeviceNode> {
  const d = new DeviceNode(net, o.name ?? 'device', o.lock ?? null);
  const j = make(d);
  const got: { welcome?: { from: string; body: any }; contested?: boolean; servers?: Set<string> | null; confirmed?: boolean } = {};
  const sigmas = new Map<string, any>();
  // Only the inviter's welcome counts: `n` is public, and a stranger's would abort the join (review 12 K1). In the
  // join-code direction the offer names the inviter; its nonce comes after the hello, and the digits with it.
  const joining: Node = { kp: d.kp, handle: (from: string, body: any) => {
    if (body?.type === 'welcome_offer' && !sayHello) {
      // A second offer for this code from another device or account: someone else saw the QR. The join stops rather
      // than pick one (red team 23); the person shows a fresh code.
      // After the confirm, later offers are ignored, so a late one can't abort a join under way (core 14.24).
      if (j.m && body?.s === j.s && (from !== j.m || body?.g !== j.g)) { if (!got.confirmed) got.contested = true; return null; }
      try { return j.onOffer(from, body, net.now).msg; } catch { return null; }
    }
    if (body?.type === 'join_nonce' && !sayHello) { try { j.onNonce(from, body); return { type: 'ack' }; } catch { return null; } }
    if (body?.type === 'repair_sigma') {
      const key = `${from}:${body.index}`;
      // Once the welcome names the servers, a server's sigma always gets in and strangers' go (red team 23: a stranger
      // filling the slots before it would otherwise starve the join).
      const named = got.servers ?? null;
      if (named) for (const k of [...sigmas.keys()]) { const f = k.slice(0, k.indexOf(':')); if (f !== j.m && !named.has(f)) sigmas.delete(k); }
      const allowed = from === j.m || (named ? named.has(from) : sigmas.size < SIGMAS_MAX);
      if (allowed && !sigmas.has(key)) sigmas.set(key, { ...body, from });
      return { type: 'ack' };
    }
    if (body?.type === 'welcome' && j.m && from === j.m) { got.welcome = { from, body }; got.servers = welcomeServers(body); return { type: 'ack' }; }
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
      o.onCheck!(j.check);
      got.confirmed = true;   // the person types this device's digits on the inviter, which checks them
    } else {
      // The phone shows the digits; the person types them here. A match is confirmed to the phone (sealed by `n`,
      // carrying its `s` and `t`), and only then is a welcome taken (core 14.24).
      while (!j.t) {
        if (Date.now() > deadline) refuse('timeout', 'no answer to the shown code');
        if (got.contested) refuse('contested', 'someone else answered this code: show a new one');
        await new Promise((ok) => setTimeout(ok, 200));
      }
      for (let k = 1; ; k++) {
        const typed = (await o.askDigits!(k)).replace(/\s/g, '');
        if (got.contested) refuse('contested', 'someone else answered this code: show a new one');
        if (sameDigits(typed, j.check)) break;
        if (k >= TRIES) refuse('check_mismatch', 'the digits didn\'t match the other device\'s');
      }
      // From the send on, the phone may add this device: a later offer is ignored, not a reason to give up (red team 23b).
      got.confirmed = true;
      const a = await net.send(d.kp, j.m!, { type: 'join_confirm', s: j.s, t: j.t });
      if (a?.type !== 'ack') refuse(a?.code ?? 'no_confirm', 'the other device didn\'t take the confirmation');
    }
    // The welcome, and every sigma it needs: the welcome may overtake a server's sigma on the relays.
    for (;;) {
      if (Date.now() > deadline) refuse('timeout', 'no welcome from the inviting device');
      if (got.contested) refuse('contested', 'someone else answered this code: show a new one');
      const wl = got.confirmed ? got.welcome : undefined;
      if (wl) {
        const named = got.servers ?? null;
        if (named) for (const k of [...sigmas.keys()]) { const f = k.slice(0, k.indexOf(':')); if (f !== j.m && !named.has(f)) sigmas.delete(k); }
        try { r = j.finish({ from: wl.from, welcome: wl.body, sigmas: [...sigmas.values()] }); break; }
        catch (e) { const c = (e as KeykinError).code; if (c !== 'sigma_missing' && c !== 'no_nonce') throw e; }
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
