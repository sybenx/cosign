// One transfer, end to end: a core Session, the relays that carry it, and the local
// store. This is the headless layer: it draws nothing, and a UI drives it through a
// handful of methods and re-reads view() whenever onChange fires.

import {
  type CodeCheck,
  type Effect,
  type Env,
  type Mode,
  type Outcome,
  type PairingParams,
  type Profile,
  type Role,
  KINDS,
  Session,
  type SessionView,
  VERSION,
  buildUri,
  generateSecretKey,
  giftWrap,
  isPrivateHost,
  relayPolicy,
  scannerRole,
  showingMode,
} from '../qrst-core/index.ts';
import { Pool } from './pool.ts';
import { type Net, type RelayProgress, type Timing, replenish, selectRelays } from './select.ts';
import type { Source, Store } from './store.ts';

const ALL_BUT_ABORT = Object.values(KINDS).filter((k) => k !== KINDS.ABORT);

export interface TransferDeps<T> {
  profile: Profile<T>;
  store: Store;
  env: Env;
  /** The https address of this page without a fragment: where a QR it shows points (§11.2a). */
  baseUrl: string;
  /** This page's origin. A web client must claim it in the QR it shows (§11.2). */
  origin: string;
  /** This device's setting for how the code is checked. Defaults to `type`, the strictest. */
  check?: CodeCheck;
  /** Relays worth asking for NIP-66 discovery events, beyond those this device knows. */
  discoveryHints?: readonly string[];
  /** Top up remembered relays in the background after a code is shown. Default true. */
  replenish?: boolean;
  timing?: Partial<Timing>;
  net?: Net;
}

export interface RelayStatus {
  url: string;
  state: 'testing' | 'failed' | 'spare' | 'connecting' | 'open' | 'closed';
  /** True for a relay this session is using. */
  inUse: boolean;
  source?: Source;
  why?: string;
}

export interface TransferView<T> {
  role: Role;
  showing: boolean;
  mode: Mode;
  /** `relays`: the showing device is still finding a relay that passes. */
  stage: 'relays' | 'session' | 'ended';
  session: SessionView;
  /** Showing device: the pairing link, once there is a tested relay to name in it. */
  uri?: string;
  relays: RelayStatus[];
  /** True while at least one of the session's relays is connected. */
  connected: boolean;
  /** Contacting device: what the code claimed about the device that showed it. Unverified. */
  peerOrigin?: string;
  /** False when the pairing did not come from this page's own camera (§9.1, §12.1). */
  viaCamera: boolean;
  /** Receiver: the value, once the user has confirmed it. */
  value?: T;
  log: string[];
}

export type Refusal = 'unknown-profile' | 'blocked-peer' | 'role-collision';

const REPLENISH_EVERY = 24 * 3600;

export function browserEnv(): Env {
  return {
    random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    now: () => Math.floor(Date.now() / 1000),
  };
}

export class Transfer<T> {
  onChange: () => void = () => {};
  /**
   * A sealed message crossed a relay, out of this device or into it. `ciphertext` is
   * the wrap's content as a relay sees it. For display only.
   */
  onCross: (ciphertext: string, direction: 'out' | 'in') => void = () => {};

  private readonly pool: Pool;
  private readonly timer: ReturnType<typeof setInterval>;
  private readonly log: string[] = [];
  private readonly startedMs = Date.now();
  private progress: RelayProgress[] = [];
  private relays: string[] = [];
  private uri: string | undefined;
  private value: T | undefined;
  private disposed = false;

  private constructor(
    private readonly deps: TransferDeps<T>,
    private readonly session: Session<T>,
    private readonly params: PairingParams | undefined,
    private readonly viaCamera: boolean,
  ) {
    this.pool = new Pool({
      filter: session.filter(),
      signAuth: (url, challenge) => session.signAuth(url, challenge),
      onEvent: (event) => {
        const effects = session.receive(event);
        // A repeat of a message already taken changes nothing, and is not shown crossing.
        const content = (event as { content?: unknown }).content;
        if (typeof content === 'string' && effects.some((e) => e.t !== 'trace')) this.onCross(content, 'in');
        this.apply(effects);
      },
      onChange: () => this.emit(),
      ...(deps.net?.WebSocketImpl ? { WebSocketImpl: deps.net.WebSocketImpl } : {}),
      ...(deps.timing?.resendMs ? { resendMs: deps.timing.resendMs } : {}),
      ...(deps.timing?.finalMs ? { finalMs: deps.timing.finalMs } : {}),
    });
    this.timer = setInterval(() => this.apply(this.session.tick()), 1000);
  }

  /**
   * Why this device must not act on a scanned code, checked before a burner is
   * generated: it does not implement the profile (§11.2), the code would give it the
   * role it already has (§11.2, role collision), or it recently failed a code against
   * that burner (§9.3).
   */
  static refusal<T>(deps: TransferDeps<T>, params: PairingParams, committedRole?: Role): Refusal | undefined {
    if (params.profile !== deps.profile.id) return 'unknown-profile';
    const role = scannerRole(params.mode);
    if (committedRole && committedRole !== role) return 'role-collision';
    if (role === 'sender' && deps.store.isBlocked(params.pub)) return 'blocked-peer';
    return undefined;
  }

  /** This device shows the code. A Receiver shows `mode=offer` (Flow A), a Sender `mode=request` (Flow B). */
  static show<T>(deps: TransferDeps<T>, role: Role, payload?: T): Transfer<T> {
    const session = new Session<T>({
      role,
      showing: true,
      profile: deps.profile,
      secretKey: generateSecretKey(deps.env.random),
      env: deps.env,
      isBlocked: (pub) => deps.store.isBlocked(pub),
      check: deps.check ?? 'type',
      ...(payload !== undefined ? { payload } : {}),
    });
    const transfer = new Transfer(deps, session, undefined, true);
    transfer.findRelays().catch((error) => transfer.fail(error));
    return transfer;
  }

  /** This device scanned, opened or pasted a code. Its role is the complement of the code's mode. */
  static join<T>(deps: TransferDeps<T>, params: PairingParams, how: { viaCamera: boolean }, payload?: T): Transfer<T> {
    const role = scannerRole(params.mode);
    const session = new Session<T>({
      role,
      showing: false,
      profile: deps.profile,
      secretKey: generateSecretKey(deps.env.random),
      peerPub: params.pub,
      token: params.token,
      peerCheck: params.check,
      env: deps.env,
      isBlocked: (pub) => deps.store.isBlocked(pub),
      check: deps.check ?? 'type',
      ...(payload !== undefined ? { payload } : {}),
    });
    const transfer = new Transfer(deps, session, params, how.viaCamera);
    transfer.relays = [...params.relays];
    // The showing device listens on these and nowhere else, so these are the relays to use.
    for (const url of params.relays) transfer.pool.add(url, true);
    // After the caller has had the chance to attach its listeners.
    queueMicrotask(() => transfer.apply(session.start()));
    return transfer;
  }

  private async findRelays(): Promise<void> {
    const listed = await selectRelays({
      pool: this.pool,
      store: this.deps.store,
      probe: () => {
        const probe = this.session.probe();
        this.pool.ignore(probe.id);
        return probe;
      },
      now: this.deps.env.now,
      onProgress: (progress) => {
        this.progress = progress;
        this.emit();
      },
      ...(this.deps.discoveryHints ? { discoveryHints: this.deps.discoveryHints } : {}),
      ...(this.deps.timing ? { timing: this.deps.timing } : {}),
      ...(this.deps.net ? { net: this.deps.net } : {}),
    });
    if (this.disposed || listed.length === 0 || this.session.view().phase === 'ended') return;
    this.relays = listed;
    this.uri = buildUri(this.deps.baseUrl, {
      v: VERSION,
      mode: showingMode(this.session.role),
      profile: this.deps.profile.id,
      pub: this.session.pub,
      check: this.session.view().check,
      token: this.session.token,
      relays: listed,
      origin: this.deps.origin,
    });
    this.trace(`listening on ${listed.length} relay${listed.length === 1 ? '' : 's'} that passed the loopback test`);
    this.emit();

    if (this.deps.replenish !== false && this.deps.store.discoveryAge() > REPLENISH_EVERY) {
      setTimeout(() => {
        if (this.disposed) return;
        void replenish(this.deps.store, this.deps.profile, this.deps.env, {
          ...(this.deps.discoveryHints ? { hints: this.deps.discoveryHints } : {}),
          ...(this.deps.timing ? { timing: this.deps.timing } : {}),
          ...(this.deps.net ? { net: this.deps.net } : {}),
        }).catch(() => {});
      }, 3000);
    }
  }

  view(): TransferView<T> {
    const session = this.session.view();
    const links = this.pool.all();
    const relays: RelayStatus[] = [];
    // Before the code is frozen, the relays in use are the ones that have passed so far.
    const inUse = this.relays.length > 0 ? this.relays : this.progress.filter((p) => p.state === 'listed').map((p) => p.url);
    for (const url of inUse) {
      const link = links.find((l) => l.url === url);
      const source = this.progress.find((p) => p.url === url)?.source;
      relays.push({
        url,
        state: link?.state ?? 'closed',
        inUse: true,
        ...(source ? { source } : {}),
        ...(link?.lastReason ? { why: link.lastReason } : {}),
      });
    }
    for (const p of this.progress) {
      if (inUse.includes(p.url)) continue;
      const state = p.state === 'listed' ? 'spare' : p.state;
      relays.push({ url: p.url, state, inUse: false, source: p.source, ...(p.why ? { why: p.why } : {}) });
    }
    const view: TransferView<T> = {
      role: this.session.role,
      showing: this.session.showing,
      mode: this.params?.mode ?? showingMode(this.session.role),
      stage: session.phase === 'ended' ? 'ended' : this.session.showing && !this.uri ? 'relays' : 'session',
      session,
      relays,
      connected: inUse.some((url) => links.find((l) => l.url === url)?.state === 'open'),
      viaCamera: this.viaCamera,
      log: [...this.log],
    };
    if (this.uri && session.phase !== 'ended') view.uri = this.uri;
    if (this.params?.origin) view.peerOrigin = this.params.origin;
    if (this.value !== undefined) view.value = this.value;
    return view;
  }

  /** Sender: the five digits read from the other device. Throws on anything that is not five digits. */
  enterCode(digits: string): void {
    this.apply(this.session.enterCode(digits));
  }

  /** Sender, check `compare`: the code on screen is the one on the other device. */
  confirmMatch(): void {
    this.apply(this.session.confirmMatch());
  }

  /** Sender, check `compare`: the codes differ. */
  rejectMatch(): void {
    this.apply(this.session.rejectMatch());
  }

  /** Sender, check `none`: send on consent alone. */
  release(): void {
    this.apply(this.session.release());
  }

  /** Sender: do not send. Receiver: discard what arrived. */
  decline(): void {
    this.apply(this.session.decline());
  }

  /** Receiver: keep what arrived. */
  accept(): void {
    this.apply(this.session.accept());
  }

  /** Receiver that showed the code: the other device rejected the code on screen; show the next. */
  advance(): void {
    this.apply(this.session.advance());
  }

  cancel(): void {
    this.apply(this.session.cancel());
  }

  /**
   * Re-sends what is outstanding and reconnects what is down, now. The pool does this
   * by itself when the page comes back into view; a host with its own notion of
   * "resumed" can call it too.
   */
  wake(): void {
    this.pool.wake();
  }

  /** Stops everything. Safe to call more than once. Does not wait for the network. */
  dispose(): void {
    if (this.disposed) return;
    this.cancel();
    this.disposed = true;
    clearInterval(this.timer);
    this.value = undefined;
  }

  /** Something outside the protocol went wrong. Say so and stop, instead of waiting for ever. */
  private fail(error: unknown): void {
    this.trace(`stopped: ${error instanceof Error ? error.message : String(error)}`);
    this.cancel();
  }

  private trace(text: string): void {
    const seconds = Math.floor((Date.now() - this.startedMs) / 1000);
    const stamp = `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
    this.log.push(`${stamp}  ${text}`);
    if (this.log.length > 200) this.log.shift();
  }

  private apply(effects: Effect<T>[]): void {
    if (effects.length === 0) return;
    for (const e of effects) {
      switch (e.t) {
        case 'publish': {
          const { seal, to } = e;
          // An ABORT ends the exchange with that peer: nothing sent to it before needs to
          // go out again, only the ABORT itself.
          if (e.kind === KINDS.ABORT) this.pool.settle(to, ALL_BUT_ABORT);
          this.pool.publish({
            event: e.event,
            again: () => giftWrap(seal, to, this.deps.env),
            to,
            kind: e.kind,
            unanswered: e.unanswered,
          });
          this.trace(e.label);
          this.onCross(e.event.content, 'out');
          break;
        }
        case 'settled':
          this.pool.settle(e.peer, e.kinds);
          break;
        case 'commit':
          this.value = e.value;
          break;
        case 'record':
          this.deps.store.addRecord({ ...e.record, transport: 'relay', relays: [...this.relays] });
          break;
        case 'failed-peers':
          this.deps.store.noteFailedSession(e.pubs);
          break;
        case 'trace':
          this.trace(e.text);
          break;
        case 'ended':
          this.ended(e.outcome);
          break;
      }
    }
    this.emit();
  }

  private ended(outcome: Outcome): void {
    clearInterval(this.timer);
    this.trace(`session ended: ${outcome}`);
    if (!this.session.showing && this.params && (outcome === 'delivered' || outcome === 'sent-unconfirmed' || outcome === 'received')) {
      // §11.3a "Learned": relays named in a code this device scanned, where the session completed.
      // A relay on a private network is not something to carry into later sessions.
      this.deps.store.noteLearned(this.params.relays.filter((url) => relayPolicy.loopback || !isPrivateHost(new URL(url).hostname)));
    }
    // The last messages (an ACK, an ABORT) are still on their way out, and go out again
    // a few times in case the peer is not listening at this moment.
    void this.pool.windDown();
  }

  private emit(): void {
    if (!this.disposed) this.onChange();
  }
}
