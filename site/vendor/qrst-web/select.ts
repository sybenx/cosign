// Relay selection for the device that shows the QR.
//
// No relay is depended on. A relay is listed in the QR only after it has passed a
// loopback test in this session: the device publishes a wrap addressed to its own
// burner, padded to the profile's maximum payload, and must receive that same event
// back. That is the only evidence that counts, because it is exactly what a session
// needs: the relay accepts a gift wrap from a key it has never seen, serves it to a
// subscriber it has never seen, and carries a payload of the declared size.
//
// Candidates come from, in order: what the user or the adopting page configured, what
// passed here before, what a scanned QR named, what NIP-66 monitors report, and last
// the seeds this build ships. A report or a seed is a reason to test a relay, never a
// reason to list one.

import {
  type Env,
  KINDS,
  MAX_RELAYS,
  type NostrEvent,
  type Profile,
  Session,
  firstTag,
  generateSecretKey,
  isEventShape,
  isPrivateHost,
  normalizeRelayUrl,
} from '../qrst-core/index.ts';
import { FINAL_RESEND_MS, type LoopbackResult, Pool, RESEND_MS } from './pool.ts';
import type { Candidate, RelayMemo, Source, Store } from './store.ts';

export interface Timing {
  /** How long the probe has to come back (§11.3a: 3 s). */
  echoMs: number;
  connectMs: number;
  /** After the first relay passes, how long to wait for a second before showing the code. */
  graceMs: number;
  nip11Ms: number;
  queryMs: number;
  /** Pause before working through the sources again when nothing has passed. */
  retryMs: number;
  /** How often an outstanding message of the session goes out again (§11.5). */
  resendMs: number;
  /** How long a session's last message (an ACK, an ABORT) keeps going out after it ends. */
  finalMs: number;
}

export const DEFAULT_TIMING: Timing = {
  echoMs: 3000,
  connectMs: 5000,
  graceMs: 1200,
  nip11Ms: 2500,
  queryMs: 4000,
  retryMs: 4000,
  resendMs: RESEND_MS,
  finalMs: FINAL_RESEND_MS,
};

/** Relays to list when that many pass. The QR may carry up to four (§11.2). */
export const TARGET_RELAYS = 3;

const STAGE_SIZE = 8;
const DISCOVERY_SOURCES = 8;
const DISCOVERY_TESTS = 6;
const DISCOVERY_MAX_AGE = 30 * 24 * 3600;
const KIND_RELAY_DISCOVERY = 30166;

export type ProgressState = 'testing' | 'listed' | 'spare' | 'failed';

export interface RelayProgress {
  url: string;
  source: Source;
  state: ProgressState;
  why?: string;
}

export interface Net {
  fetchImpl?: typeof fetch;
  WebSocketImpl?: typeof WebSocket;
  /** Tests only: let discovery propose a relay on this machine. */
  allowLoopbackDiscovery?: boolean;
}

// ---- NIP-11 ---------------------------------------------------------------------------

export interface RelayInfo {
  maxMessageLength?: number;
  maxContentLength?: number;
  paymentRequired?: boolean;
}

/** Reads the limits a relay advertises (§11.6). Undefined when it advertises nothing reachable. */
export async function relayInfo(url: string, ms: number, net: Net = {}): Promise<RelayInfo | undefined> {
  const doFetch = net.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const response = await doFetch(url.replace(/^ws/, 'http'), {
      headers: { Accept: 'application/nostr+json' },
      signal: controller.signal,
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
    if (!response.ok) return undefined;
    const doc = (await response.json()) as { limitation?: Record<string, unknown> } | null;
    const limits = doc?.limitation;
    if (typeof limits !== 'object' || limits === null) return {};
    const number = (v: unknown) => (typeof v === 'number' && v > 0 ? v : undefined);
    const info: RelayInfo = {};
    const message = number(limits.max_message_length);
    const content = number(limits.max_content_length);
    if (message !== undefined) info.maxMessageLength = message;
    if (content !== undefined) info.maxContentLength = content;
    if (limits.payment_required === true) info.paymentRequired = true;
    return info;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

/** Why a relay's advertised limits rule it out for this probe, or undefined if they do not. */
export function ruledOutBy(info: RelayInfo | undefined, probe: NostrEvent): string | undefined {
  if (!info) return undefined;
  if (info.paymentRequired) return 'requires payment';
  if (info.maxContentLength !== undefined && probe.content.length > info.maxContentLength) {
    return `advertises a content limit of ${info.maxContentLength}, below what this profile needs`;
  }
  const bytes = new TextEncoder().encode(JSON.stringify(['EVENT', probe])).length;
  if (info.maxMessageLength !== undefined && bytes > info.maxMessageLength) {
    return `advertises a message limit of ${info.maxMessageLength}, below what this profile needs`;
  }
  return undefined;
}

// ---- NIP-66 discovery -----------------------------------------------------------------

/** One REQ on a short-lived socket. Resolves with whatever arrived before EOSE or the timeout. */
export function queryRelay(url: string, filter: Record<string, unknown>, ms: number, net: Net = {}): Promise<unknown[]> {
  return new Promise((resolve) => {
    const Impl = net.WebSocketImpl ?? WebSocket;
    const events: unknown[] = [];
    let ws: WebSocket;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        ws?.close();
      } catch {
        // already closed
      }
      resolve(events);
    };
    const timer = setTimeout(finish, ms);
    try {
      ws = new Impl(url);
    } catch {
      return finish();
    }
    ws.onopen = () => ws.send(JSON.stringify(['REQ', 'd', filter]));
    ws.onmessage = (m) => {
      try {
        const message = JSON.parse(String(m.data)) as unknown[];
        if (message[0] === 'EVENT' && message[1] === 'd') events.push(message[2]);
        else if (message[0] === 'EOSE' || message[0] === 'CLOSED') finish();
      } catch {
        // not for us
      }
    };
    ws.onerror = finish;
    ws.onclose = finish;
  });
}

const tagValues = (e: { tags: string[][] }, name: string) => e.tags.filter((t) => t[0] === name).map((t) => t[1] ?? '');

/**
 * Turns NIP-66 relay discovery events into an ordered list of relays worth testing.
 *
 * The events are not verified and need not be: a monitor may be wrong or hostile
 * either way, and what it reports only decides the order in which relays are tested.
 */
export function rankDiscovered(
  events: unknown[],
  now: number,
  random: () => number = Math.random,
  allowLoopback = false,
): string[] {
  const seen = new Map<string, { score: number; monitors: Set<string> }>();
  for (const e of events) {
    if (!isEventShape(e) || e.kind !== KIND_RELAY_DISCOVERY) continue;
    if (now - e.created_at > DISCOVERY_MAX_AGE) continue;
    const url = normalizeRelayUrl(firstTag(e, 'd') ?? '');
    // A report must never be able to point this page at a service on the user's own machine.
    if (!url || (!url.startsWith('wss://') && !allowLoopback)) continue;
    const host = new URL(url).hostname;
    if (/\.(onion|i2p|loki)$/.test(host)) continue;
    if (isPrivateHost(host) && !allowLoopback) continue;
    const networks = tagValues(e, 'n');
    if (networks.length > 0 && !networks.includes('clearnet')) continue;
    const requirements = tagValues(e, 'R');
    if (requirements.includes('payment')) continue;
    // Kind 21059 is ephemeral, so a monitor that lists accepted kinds rarely names it;
    // one that says it is refused is still worth believing.
    const kinds = tagValues(e, 'k');
    if (kinds.includes(`!${KINDS.WRAP}`)) continue;

    let score = 0;
    if (requirements.includes('!payment')) score += 1;
    if (requirements.includes('!auth')) score += 1;
    if (kinds.includes(String(KINDS.WRAP))) score += 1;
    const rtt = Number(firstTag(e, 'rtt-open'));
    if (Number.isFinite(rtt) && rtt > 0) score += rtt < 300 ? 1 : rtt < 1000 ? 0.5 : 0;

    const entry = seen.get(url) ?? { score: 0, monitors: new Set<string>() };
    entry.score = Math.max(entry.score, score);
    entry.monitors.add(e.pubkey);
    seen.set(url, entry);
  }
  return [...seen.entries()]
    .map(([url, v]) => ({ url, score: v.score + (v.monitors.size > 1 ? 1 : 0), jitter: random() }))
    .sort((a, b) => b.score - a.score || a.jitter - b.jitter)
    .map((x) => x.url);
}

/** Asks relays this device already knows for NIP-66 discovery events and ranks what they describe. */
export async function discover(from: string[], now: number, ms: number, net: Net = {}): Promise<string[]> {
  const sources = from.slice(0, DISCOVERY_SOURCES);
  const batches = await Promise.all(
    sources.map((url) => queryRelay(url, { kinds: [KIND_RELAY_DISCOVERY], limit: 300 }, ms, net)),
  );
  return rankDiscovered(batches.flat(), now, Math.random, net.allowLoopbackDiscovery === true).filter(
    (url) => !from.includes(url),
  );
}

// ---- selection ------------------------------------------------------------------------

export interface SelectOptions {
  pool: Pool;
  store: Store;
  /**
   * Makes the session's probe wrap, one per relay tested, the pool already ignoring its
   * id. Fresh each time: selection can go on for minutes, and a relay may refuse an
   * ephemeral event more than a minute old.
   */
  probe(): NostrEvent;
  now(): number;
  onProgress(progress: RelayProgress[]): void;
  /** Extra relays to ask for discovery events, beyond the ones this device knows. */
  discoveryHints?: readonly string[];
  timing?: Partial<Timing>;
  net?: Net;
}

const originOf = (c: Candidate, memos: RelayMemo[]): RelayMemo['origin'] =>
  c.source === 'remembered' ? (memos.find((m) => m.url === c.url)?.origin ?? 'seed') : c.source;

/**
 * Finds relays that pass the loopback test and resolves with the ones to list in the
 * QR, at least one. It keeps working through its sources until one passes or the
 * pool is closed; in the second case it resolves with an empty list.
 */
export async function selectRelays(options: SelectOptions): Promise<string[]> {
  const { pool, store } = options;
  const timing = { ...DEFAULT_TIMING, ...options.timing };
  const net = options.net ?? {};
  const progress = new Map<string, RelayProgress>();
  const listed: string[] = [];
  let frozen = false;
  let cancelled = false;
  let firstPassAt: number | undefined;
  let wake: () => void = () => {};
  // Failures are written to memory only once something has passed in the same run.
  // If nothing passes, the likelier explanation is this device's own connection, and
  // forgetting every relay it knows would be the wrong lesson to draw from that.
  const failures = new Map<string, { origin: RelayMemo['origin']; why: string }>();
  let anyPassed = false;
  const noteFail = (url: string, origin: RelayMemo['origin'], why: string) => {
    if (anyPassed) store.noteFail(url, origin, why);
    else failures.set(url, { origin, why });
  };
  const notePass = (url: string, origin: RelayMemo['origin']) => {
    store.notePass(url, origin);
    failures.delete(url);
    if (anyPassed) return;
    anyPassed = true;
    for (const [failed, f] of failures) store.noteFail(failed, f.origin, f.why);
    failures.clear();
  };

  const report = () => options.onProgress([...progress.values()]);

  const test = async (c: Candidate): Promise<void> => {
    progress.set(c.url, { url: c.url, source: c.source, state: 'testing' });
    report();
    const origin = originOf(c, store.memos());
    let probe: NostrEvent;
    try {
      probe = options.probe();
    } catch {
      // The session ended between two tests.
      cancelled = true;
      wake();
      return;
    }
    const [loop, info] = await Promise.all([
      pool.loopback(c.url, probe, timing.echoMs, timing.connectMs),
      relayInfo(c.url, timing.nip11Ms, net),
    ]);
    let result: LoopbackResult = loop;
    if (loop.reason === 'cancelled') {
      cancelled = true;
      wake();
      return;
    }
    // §11.6: skip a relay whose advertised limits cannot carry the profile's maximum.
    const ruledOut = loop.ok ? ruledOutBy(info, probe) : undefined;
    if (ruledOut) {
      pool.remove(c.url);
      result = { ok: false, reason: ruledOut };
    }
    if (!result.ok) {
      noteFail(c.url, origin, result.reason ?? 'failed');
      progress.set(c.url, { url: c.url, source: c.source, state: 'failed', why: result.reason ?? 'failed' });
    } else {
      notePass(c.url, origin);
      if (!frozen && listed.length < Math.min(TARGET_RELAYS, MAX_RELAYS)) {
        listed.push(c.url);
        firstPassAt ??= Date.now();
        progress.set(c.url, { url: c.url, source: c.source, state: 'listed' });
      } else {
        // Passed, but the code is already on screen or already full. Remembered for next time.
        pool.remove(c.url);
        progress.set(c.url, { url: c.url, source: c.source, state: 'spare' });
      }
    }
    report();
  };

  /** Tests a batch and returns when there is enough to show a code, or the batch is spent. */
  const stage = async (batch: Candidate[]): Promise<void> => {
    const fresh = batch.filter((c) => progress.get(c.url)?.state !== 'testing' && !listed.includes(c.url));
    if (fresh.length === 0) return;
    let pending = fresh.length;
    for (const c of fresh) {
      void test(c).finally(() => {
        pending--;
        wake();
      });
    }
    for (;;) {
      if (cancelled || pending === 0 || listed.length >= TARGET_RELAYS) return;
      if (firstPassAt !== undefined && Date.now() - firstPassAt >= timing.graceMs) return;
      await new Promise<void>((resolve) => {
        const wait = firstPassAt === undefined ? 250 : Math.max(10, timing.graceMs - (Date.now() - firstPassAt));
        const timer = setTimeout(resolve, wait);
        wake = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  };

  const bySource = (...sources: Source[]) => store.candidates().filter((c) => sources.includes(c.source));

  for (;;) {
    if (pool.isClosed) return [];
    // Stage 1: configured, remembered, learned, and anything discovered earlier, a batch
    // at a time and all the way down the list: a live relay must not wait for ever
    // behind dead ones.
    const known = bySource('configured', 'remembered', 'learned', 'discovered');
    for (let i = 0; i < known.length && listed.length === 0 && !cancelled && !pool.isClosed; i += STAGE_SIZE) {
      await stage(known.slice(i, i + STAGE_SIZE));
    }

    if (!cancelled && listed.length === 0) {
      // Stage 2: seeds, and whatever monitors report through any relay this device knows.
      const seeds = bySource('seed').slice(0, STAGE_SIZE);
      const askable = [...new Set([...(options.discoveryHints ?? []), ...store.candidates().map((c) => c.url)])];
      const discovering = discover(askable, options.now(), timing.queryMs, net).then((urls) => {
        if (urls.length > 0) store.noteDiscovered(urls.slice(0, DISCOVERY_TESTS * 2));
        return urls.slice(0, DISCOVERY_TESTS).map((url): Candidate => ({ url, source: 'discovered' }));
      });
      await stage(seeds);
      if (!cancelled && listed.length === 0) await stage(await discovering);
    }

    if (cancelled) return [];
    if (listed.length > 0) break;
    // Nothing passed. §11.3a: keep working through the sources and retesting those that failed.
    await new Promise((resolve) => setTimeout(resolve, timing.retryMs));
    if (pool.isClosed) return [];
    for (const [url, p] of progress) if (p.state === 'failed') progress.delete(url);
  }

  frozen = true;
  report();
  return [...listed];
}

/**
 * The loopback test with a throwaway burner, for testing a relay outside a session:
 * the "test" control in the relay list, and topping up what this device remembers.
 */
export async function loopbackOnce<T>(
  url: string,
  profile: Profile<T>,
  env: Env,
  options: { timing?: Partial<Timing>; net?: Net } = {},
): Promise<LoopbackResult> {
  const timing = { ...DEFAULT_TIMING, ...options.timing };
  const session = new Session<T>({
    role: 'receiver',
    showing: true,
    profile,
    secretKey: generateSecretKey(env.random),
    env,
  });
  const pool = new Pool({
    filter: session.filter(),
    signAuth: (relay, challenge) => session.signAuth(relay, challenge),
    onEvent: () => {},
    ...(options.net?.WebSocketImpl ? { WebSocketImpl: options.net.WebSocketImpl } : {}),
  });
  try {
    const probe = session.probe();
    pool.ignore(probe.id);
    const [loop, info] = await Promise.all([
      pool.loopback(url, probe, timing.echoMs, timing.connectMs),
      relayInfo(url, timing.nip11Ms, options.net),
    ]);
    const ruledOut = loop.ok ? ruledOutBy(info, probe) : undefined;
    return ruledOut ? { ok: false, reason: ruledOut } : loop;
  } finally {
    pool.close();
    session.cancel();
  }
}

/**
 * Tops up what this device remembers, so that it does not come to depend on its
 * seeds: asks known relays what monitors report and tests a few it has never tried.
 * Run in the background, at most about once a day.
 */
export async function replenish<T>(
  store: Store,
  profile: Profile<T>,
  env: Env,
  options: { hints?: readonly string[]; timing?: Partial<Timing>; net?: Net; limit?: number } = {},
): Promise<number> {
  const timing = { ...DEFAULT_TIMING, ...options.timing };
  const known = store.candidates().map((c) => c.url);
  const found = await discover([...new Set([...(options.hints ?? []), ...known])], env.now(), timing.queryMs, options.net);
  const untried = found.filter((url) => !known.includes(url)).slice(0, options.limit ?? 3);
  let passed = 0;
  for (const url of untried) {
    const result = await loopbackOnce(url, profile, env, options);
    if (result.ok) {
      store.notePass(url, 'discovered');
      passed++;
    }
    // A relay that failed its first test is simply not remembered.
  }
  store.noteDiscovered([]);
  return passed;
}
