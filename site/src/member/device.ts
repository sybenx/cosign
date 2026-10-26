// A device in a Cosign key, for a host that keeps the parts of the key itself (ops.ts).
//
// What a device does: it joins a key that already exists — another of your devices vouches,
// and it and a server make this one's parts by repair — then it signs with any one server,
// works out shared secrets the same way, and follows the refreshes the key goes through. It
// never holds the whole key and never signs alone, which is the point of all of it.
//
//   const device = await openDevice({ ops, onStatus: say });
//   await device.join({ onCode: uri => showQr(uri) });   // another of your devices scans it
//   const signed = await device.sign({ kind: 1, content: 'hello', tags: [] });
//
// Ported from the browser extension's member code, with every secret behind ShareOps.
//
// **A host must keep this running.** Everything here waits on timers: reconnecting to a
// relay, asking a server again when a relay dropped the question, letting go of a refresh
// nobody committed. A WebKit page that is hidden has its timers stalled, so a signer kept in
// a hidden webview goes deaf — the messages arrive on the relays and nothing acts on them,
// and a join hangs with no error anywhere. The Marble Mac app turns that throttling off for
// its signer page (WKPreferences _setHiddenPageDOMTimerThrottlingEnabled and friends); an
// iOS host will have to do the same, and any host should check this before blaming the
// protocol for a round that never finishes.

import { getEventHash, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { Mailbox, pubOf } from './mailbox.ts';
import type { Commit, Group, ShareOps } from './ops.ts';

export interface Member { idx: number; name: string; role: string; pk: string | null; sharePub: string; shares?: { idx: number; sharePub: string }[] }

/** The account as this device keeps it. No secrets: the host holds those. */
export interface Account {
  groupX: string; npub: string; threshold: number; relays: string[]; members: Member[];
  /** The key the servers answer sites as. */
  signer?: string;
  /** This device's own grant, which its servers check before helping it read anything. */
  grant?: string;
  /**
   * A quiet refresh followed but not yet committed by the servers (COSIGN.md §7.7). The new
   * points are kept with it: the parts move when it is committed, and the points must move
   * with them or this device would be signing with parts its own record disagrees with.
   */
  pending?: { epoch: number; id: string | null; at: number; points?: [number, string][] };
  /** Reported lost by another of your devices: this one does nothing more. */
  removed?: { by: string; at: number };
}

export interface Host {
  ops: ShareOps;
  /** Where to listen before this device has an account. */
  relays?: string[];
  /** What this device calls itself in your list of devices. */
  name?: string;
  onStatus?: (text: string) => void;
  onRemoved?: (by: string) => void;
  onMembers?: (members: Member[]) => void;
}

const JOIN_RELAYS = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
const rid = () => bytesToHex(randomBytes(8));
const isHex32 = (s: unknown) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
/** An answer that ends a round: the person must decide, or the server refuses outright. */
const FINAL = /^(needs-approval|refused|revoked|not-allowed):/;
/**
 * Why something failed, in words. A host can reject with anything it likes — a Tauri call
 * rejects with a plain string, not an Error — and a server can refuse with no reason at all,
 * so this never comes out as "undefined" and leaves whoever reads it nothing to go on.
 */
const whyOf = (e: unknown): string => {
  if (e instanceof Error && e.message) return e.message;
  if (typeof e === 'string' && e.trim()) return e.trim();
  if (e !== null && e !== undefined) { try { const s = JSON.stringify(e); if (s && s !== '{}' && s !== 'null') return s; } catch { /* circular */ } }
  return 'no reason given';
};
const partsOf = (m: Member) => (m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]).map(p => p.idx);
/** The key as the maths wants it: every part, whoever holds it. */
const flat = (a: Account): Group => ({
  groupX: a.groupX, threshold: a.threshold,
  members: a.members.flatMap(m => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]),
});
/** NIP-44's conversation key from a shared x (the servers do the same, server/core/group.ts). */
const keyFromShared = (x: string) => extract(sha256, hexToBytes(x), utf8ToBytes('nip44-v2'));

export async function openDevice(host: Host): Promise<Device> {
  const ops = host.ops;
  const [state, sk] = await Promise.all([ops.state(), ops.mailboxKey()]);
  return new Device(host, sk, state.group as Account | undefined, state.idxs ?? [], state.epoch ?? 0, state.unreadable === true);
}

export class Device {
  private box: Mailbox;
  private waiting = new Map<string, (r: any) => void>();
  private ticker: ReturnType<typeof setInterval>;
  private closed = false;
  /** Pieces of a join, while it is going on. */
  private joining: { welcome?: any; from?: string; sigmas: [number, number, string][]; done: (a: Account) => void; fail: (e: Error) => void } | null = null;
  private selfKey: { at: number; key: Uint8Array } | null = null;

  private host: Host;
  private sk: string;
  private account: Account | undefined;
  private idxs: number[];
  private epoch: number;
  /** The parts are there but can't be read (a re-signed app): this device must join again. */
  readonly unreadable: boolean;

  constructor(host: Host, sk: string, account: Account | undefined, idxs: number[], epoch: number, unreadable: boolean) {
    this.host = host;
    this.sk = sk;
    this.account = account;
    this.idxs = idxs;
    this.epoch = epoch;
    this.unreadable = unreadable;
    this.box = new Mailbox(sk, account?.relays ?? host.relays ?? JOIN_RELAYS, (m, from) => void this.handle(m, from));
    this.ticker = setInterval(() => void this.tend(), 10_000);
  }

  private get ops() { return this.host.ops; }
  private say(text: string) { this.host.onStatus?.(text); }
  private servers() { return (this.account?.members ?? []).filter(m => m.role === 'server' && m.pk); }

  get pubkey() { return this.account?.groupX ?? null; }

  status() {
    return {
      joined: !!this.account && this.idxs.length > 0,
      unreadable: this.unreadable,
      pubkey: this.account?.groupX ?? null,
      npub: this.account?.npub ?? null,
      relays: this.account?.relays ?? this.host.relays ?? JOIN_RELAYS,
      epoch: this.epoch,
      removed: this.account?.removed ?? null,
      members: (this.account?.members ?? []).map(m => ({ idx: m.idx, name: m.name, role: m.role })),
    };
  }

  close() { this.closed = true; clearInterval(this.ticker); this.box.close(); }

  // --- Joining a key that already exists ----------------------------------------------------

  /**
   * Show a code for one of your devices to scan. It asks you there, with its lock, and then it
   * and a server make this device's parts by repair: one sigma from each helper part for each
   * new part, added up here. Nobody else ever sees them.
   */
  join(opts: { onCode: (uri: string) => void; name?: string }): Promise<void> {
    if (this.account && this.idxs.length && !this.unreadable) return Promise.reject(new Error('This device is already part of an account.'));
    const name = opts.name ?? this.host.name ?? 'This device';
    const relays = this.host.relays ?? JOIN_RELAYS;
    opts.onCode(`cosign:join?pk=${pubOf(this.sk)}&name=${encodeURIComponent(name)}&` + relays.map(r => `r=${encodeURIComponent(r)}`).join('&'));
    this.say('Scan this with a device that is already in your account.');
    return new Promise<void>((resolve, reject) => {
      this.joining = { sigmas: [], done: () => resolve(), fail: reject };
      setTimeout(() => { if (this.joining) { this.joining = null; reject(new Error('Nobody vouched for this device.')); } }, 5 * 60_000);
    });
  }

  /** A server's welcome, or a vouching device's sigmas: this device's parts, once both are in. */
  private async onJoinPiece(m: any, from: string, name: string) {
    const j = this.joining;
    if (!j) return;
    if (m.type === 'welcome') { j.welcome = m; j.from = from; j.sigmas.push(...(m.sigmas ?? [[m.k, 0, m.sigma]])); this.say('Your device said yes; making this one’s part…'); }
    else j.sigmas.push(...(m.sigmas ?? [[m.k, -1, m.sigma]]));
    const w = j.welcome;
    if (!w?.group?.groupX) return;
    const ks: number[] = w.ks ?? [w.k];
    const need = w.helpers?.length ?? 2;
    if (!ks.every(k => j.sigmas.filter(x => x[0] === k).length >= need)) return;
    this.joining = null;
    try {
      const g: Group = { groupX: w.group.groupX, threshold: w.group.threshold, members: (w.group.members as Member[]).flatMap(x => x.shares ?? [{ idx: x.idx, sharePub: x.sharePub }]) };
      const points: [number, string][] = [];
      for (const k of ks) points.push([k, await this.ops.repairStep3(g, j.sigmas.filter(x => x[0] === k).map(x => x[2]), k)]);
      const me: Member = { idx: ks[0], name, role: 'device', pk: pubOf(this.sk), sharePub: points[0][1], ...(ks.length > 1 ? { shares: points.map(([idx, sharePub]) => ({ idx, sharePub })) } : {}) };
      const account: Account = {
        groupX: w.group.groupX, npub: w.group.npub, threshold: w.group.threshold,
        relays: w.group.relays ?? this.host.relays ?? JOIN_RELAYS,
        members: [...(w.group.members as Member[]).filter(x => x.idx !== me.idx), me],
        signer: w.signer, grant: bytesToHex(randomBytes(32)),
      };
      // Tell the server we have them, more than once: it waits for this to count us a member.
      const reply = () => this.box.send(j.from!, { type: 'joined', id: w.id, sharePubs: points, sharePub: points[0][1] });
      reply(); setTimeout(reply, 4000);
      this.account = account;
      this.idxs = ks;
      this.epoch = Number(w.epoch ?? 0);
      await this.ops.commitParts(account, this.epoch);
      // This device's own grant: its servers check for one before helping it read anything.
      for (const s of this.servers()) this.box.send(s.pk!, { type: 'app_grant', pk: account.grant, origin: name, via: name });
      this.say('This device is part of your account now.');
      j.done(account);
    } catch (e) {
      j.fail(new Error(`Couldn’t make this device’s part: ${whyOf(e)}`));
    }
  }

  // --- Asking a server ------------------------------------------------------------------------

  /** One question to a member, asked again if a relay dropped it; its answer, or null. */
  private ask(toPk: string, body: object, ms = 8000): Promise<any | null> {
    const id = rid();
    const msg = { ...body, id };
    return new Promise(resolve => {
      const done = (r: any) => { clearTimeout(timer); clearInterval(again); this.waiting.delete(id); resolve(r); };
      this.waiting.set(id, done);
      this.box.send(toPk, msg);
      const again = setInterval(() => this.box.send(toPk, msg), 3000);
      const timer = setTimeout(() => done(null), ms);
    });
  }

  /**
   * Each server in turn until one does it. One that refuses outright — your access is gone, or
   * you must approve it first — ends it there; one that is quiet or broken means the next is asked.
   */
  private async withAServer<T>(what: string, round: (s: Member) => Promise<{ body: object; finish: (res: any) => Promise<T> }>): Promise<T> {
    const tried: string[] = [];
    const order = this.servers();
    if (!order.length) throw new Error(`${what}: this device has no servers`);
    for (const s of order) {
      let body: object, finish: (res: any) => Promise<T>;
      try { ({ body, finish } = await round(s)); } catch (e) { tried.push(`${s.name}: ${whyOf(e)}`); continue; }
      const res = await this.ask(s.pk!, body);
      if (!res) { tried.push(`${s.name}: no answer`); continue; }
      if (res.ok === false || res.error) {
        const why = whyOf(res.reason ?? res.error);
        if (FINAL.test(why)) throw new Error(why);
        tried.push(`${s.name}: ${why}`); continue;
      }
      try { return await finish(res); } catch (e) { tried.push(`${s.name}: ${whyOf(e)}`); }
    }
    throw new Error(`${what} (${tried.join('; ')})`);
  }

  // --- Signing ----------------------------------------------------------------------------------

  /** Sign an event as the account, with any one server. */
  async sign(t: { kind: number; content: string; tags: string[][]; created_at?: number }, opts: { approved?: boolean } = {}): Promise<Event> {
    const a = this.need();
    const ev = { kind: t.kind, content: t.content, tags: t.tags, created_at: t.created_at ?? Math.floor(Date.now() / 1000), pubkey: a.groupX };
    const msg = getEventHash(ev as any);
    const g = flat(a);
    const sig = await this.withAServer('Your servers didn’t sign', async s => {
      // The commitments are made before the request goes out: the server signs against them.
      const mine: { idx: number; handle: string; commit: Commit }[] = [];
      for (const idx of this.idxs) mine.push({ idx, ...(await this.ops.commit(g, idx)) });
      const participants = [...this.idxs, ...partsOf(s)].sort((x, y) => x - y);
      return {
        body: { type: 'cosign_req', event: ev, msg, participants, grant: a.grant, commits: mine.map(m => m.commit), commit: mine[0].commit, frost: 2, approved: opts.approved === true },
        finish: async res => {
          const theirs: [number, string][] = res.zs ?? [[partsOf(s)[0], res.z]];
          const commits = [...mine.map(m => m.commit), ...(res.commits ?? [res.commit])];
          for (const [idx, z] of theirs) if (!(await this.ops.verifyPartial(g, msg, commits, idx, z))) throw new Error('a bad partial signature');
          const ours: [number, string][] = [];
          for (const m of mine) ours.push([m.idx, await this.ops.sign(g, m.idx, m.handle, msg, commits)]);
          return await this.ops.aggregate(g, msg, commits, [...ours, ...theirs]);
        },
      };
    });
    const signed = { ...ev, id: msg, sig } as Event;
    // The servers keep what this device signed, as they keep what they sign themselves.
    for (const s of this.servers()) this.box.send(s.pk!, { type: 'phone_signed', event: signed, grant: a.grant, approved: opts.approved === true });
    return signed;
  }

  // --- Your own things, which only you read ---------------------------------------------------

  /** NIP-44 with the account itself (app data, NIP-78): the other side is always your own key. */
  async encryptToSelf(text: string): Promise<string> { return nip44.v2.encrypt(text, await this.ownKey()); }
  async decryptFromSelf(text: string): Promise<string> { return nip44.v2.decrypt(text, await this.ownKey()); }

  /** Worked out with a server's help, and kept while this device is awake. */
  private async ownKey(): Promise<Uint8Array> {
    const a = this.need();
    if (this.selfKey && Date.now() - this.selfKey.at < 600_000) return this.selfKey.key;
    const x = await this.withAServer('Couldn’t work with your own key', async s => {
      const participants = [...this.idxs, ...partsOf(s)].sort((p, q) => p - q);
      return {
        body: { type: 'ecdh_req', peerX: a.groupX, participants, grant: a.grant },
        finish: async res => {
          const mine: string[] = [];
          for (const idx of this.idxs) mine.push(await this.ops.ecdhPartial(idx, participants, a.groupX));
          return await this.ops.ecdhCombine([...mine, ...(res.points ?? [res.point])]);
        },
      };
    });
    this.selfKey = { at: Date.now(), key: keyFromShared(x) };
    return this.selfKey.key;
  }

  /** Nothing is kept from before: used when this device is reported lost or signed out. */
  forgetSecrets() { this.selfKey = null; }

  // --- What arrives ------------------------------------------------------------------------------

  private async handle(m: any, from: string) {
    if (this.closed) return;
    const id = m?.id;
    if (typeof id === 'string' && this.waiting.has(id) && (m.type === 'cosign_res' || m.type === 'ecdh_res' || m.type === 'sign_res')) {
      this.waiting.get(id)!(m); this.waiting.delete(id); return;
    }
    if (this.joining && (m.type === 'welcome' || m.type === 'sigma')) return void this.onJoinPiece(m, from, this.host.name ?? 'This device');
    const a = this.account;
    if (!a) return;
    // Only members of this account are listened to at all.
    const member = a.members.find(x => x.pk === from);
    if (!member) return;
    // A refresh is dealt by one of your devices and a server together, and each dealer sends
    // its part straight to every holder — so these come from a device as often as from a
    // server. What they are allowed to do is checked where they are used: a part counts only
    // from a dealer that plan named. Everything else is from a server or from nobody.
    if (m.type === 'refresh_plan') return void this.onPlan(m.plan);
    if (m.type === 'refresh_part') return void this.onPart(m, from);
    // What a server kept for this device while it was away: opened as if it had just arrived.
    if (m.type === 'mail' && typeof m.content === 'string' && isHex32(m.from)) {
      let inner: any;
      try { inner = JSON.parse(nip44.v2.decrypt(m.content, nip44.v2.utils.getConversationKey(hexToBytes(this.sk), m.from))); } catch { return; }
      // One layer: mail inside mail is nobody's doing but a server playing games.
      if (inner?.type === 'mail') return;
      return void this.handle(inner, m.from);
    }
    const server = member.role === 'server' ? member : null;
    if (!server) return;
    switch (m.type) {
      case 'members': return void this.onMembers(m);
      case 'refresh_committed': return void this.onCommitted(m);
      case 'removed': {
        a.removed = { by: String(m.by ?? 'another device'), at: Date.now() };
        this.forgetSecrets();
        await this.save();
        this.host.onRemoved?.(a.removed.by);
        return;
      }
      // A repair this device didn't ask for would make a part of its own key for someone else.
      case 'repair': {
        this.say(`${server.name} asked this device to make parts for something you didn’t add. Refused.`);
        return;
      }
      default: return;
    }
  }

  private async onMembers(m: any) {
    const a = this.account;
    if (!a || !Array.isArray(m.members)) return;
    // A relay can deliver a list from before a refresh this device has done.
    if (Number(m.epoch ?? this.epoch) < this.epoch) return;
    const list = (m.members as Member[]).filter(x => typeof x?.idx === 'number');
    if (!list.some(x => x.idx === this.idxs[0])) return; // a list without this device isn't one to take
    // Points move only by refresh, which this device works out itself: keep the ones it knows,
    // so a list sent mid-way can't break signing.
    const known = new Map(a.members.flatMap(x => (x.shares ?? [{ idx: x.idx, sharePub: x.sharePub }]).map(p => [p.idx, p.sharePub] as [number, string])));
    a.members = list.map(x => ({
      ...x,
      sharePub: known.get(x.idx) ?? x.sharePub,
      ...(x.shares ? { shares: x.shares.map(p => ({ idx: p.idx, sharePub: known.get(p.idx) ?? p.sharePub })) } : {}),
    }));
    await this.save();
    this.host.onMembers?.(a.members);
  }

  // --- Refreshes ---------------------------------------------------------------------------------

  private plans = new Map<number, { plan: any; parts: Map<string, { commits: string[]; deltas: [number, string][] }> }>();

  /** A plan from one of your devices (through a server): what this one's parts become. */
  private onPlan(plan: any) {
    if (!plan || typeof plan.epoch !== 'number' || plan.epoch <= this.epoch) return;
    if (!this.plans.has(plan.epoch)) this.plans.set(plan.epoch, { plan, parts: new Map() });
  }

  private async onPart(m: any, from: string) {
    const epoch = Number(m.epoch);
    const held = this.plans.get(epoch);
    if (!held || !Array.isArray(m.commits) || !Array.isArray(m.deltas)) return;
    if (!held.plan.dealers?.includes(from)) return; // only the dealers this plan named
    held.parts.set(from, { commits: m.commits, deltas: m.deltas });
    if (held.parts.size < (held.plan.dealers?.length ?? 2)) return;
    const a = this.account;
    if (!a) return;
    this.plans.delete(epoch);
    const dealers = [...held.parts.values()];
    // Everyone starts from the points the plan names, whatever each has heard since — a
    // member list that arrived mid-way can't be what this is worked out from (refresh.ts).
    const named: [number, string][] = Array.isArray(held.plan.points) ? held.plan.points : [];
    const start: Group = named.length
      ? { groupX: a.groupX, threshold: Number(held.plan.threshold ?? a.threshold), members: named.map(([idx, sharePub]) => ({ idx, sharePub })) }
      : flat(a);
    const points = await this.ops.refreshApply(start, epoch, dealers);
    // A quiet refresh is held: the servers go on signing with the current parts until a device
    // commits, so one that moved now would be alone on an epoch — and stranded for good if
    // nobody ever commits (COSIGN.md §7.7). Anything else takes effect as soon as it is worked out.
    if (held.plan.periodic === true) {
      a.pending = { epoch, id: held.plan.id ?? null, at: Date.now(), points };
      await this.save();
      return;
    }
    await this.apply(epoch, points);
  }

  private async onCommitted(m: any) {
    const a = this.account;
    const p = a?.pending;
    if (!a || !p) return;
    const epoch = Number(m.epoch);
    if (epoch !== p.epoch || (m.id && p.id && m.id !== p.id)) return;
    const points = p.points ?? null;
    delete a.pending;
    await this.apply(epoch, points);
  }

  /** The new parts are this device's now: its points move with everyone else's. */
  private async apply(epoch: number, points: [number, string][] | null) {
    const a = this.account;
    if (!a) return;
    if (points) {
      const at = new Map(points);
      a.members = a.members.map(m => {
        const idxs = partsOf(m);
        if (!idxs.every(i => at.has(i))) return m;
        const pts = idxs.map(idx => ({ idx, sharePub: at.get(idx)! }));
        return { ...m, sharePub: pts[0].sharePub, ...(m.shares ? { shares: pts } : {}) };
      });
    }
    this.epoch = epoch;
    delete a.pending;
    await this.ops.commitParts(a, epoch);
    this.selfKey = null; // worked out from the parts that just moved
    for (const s of this.servers()) this.box.send(s.pk!, { type: 'refreshed', epoch });
  }

  private need(): Account {
    if (this.unreadable) throw new Error('This device’s part of your key can’t be read any more. Add it to your account again.');
    const a = this.account;
    if (!a || !this.idxs.length) throw new Error('This device isn’t part of an account yet.');
    if (a.removed) throw new Error(`This device was reported lost from ${a.removed.by}.`);
    return a;
  }

  private async tend() {
    if (this.closed || !this.account) return;
    for (const s of this.servers()) this.box.send(s.pk!, { type: 'ping', idx: this.idxs[0], ts: Date.now() });
    const p = this.account.pending;
    if (p && Date.now() - p.at > 48 * 3600_000) {
      await this.ops.dropPending(p.epoch).catch(() => {});
      delete this.account.pending;
      await this.save();
      this.say('An epoch your servers never finished was let go; your key is unchanged.');
    }
  }

  private async save() { if (this.account) await this.ops.update(this.account); }
}
