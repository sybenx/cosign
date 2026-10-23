// What this device remembers between sessions. All of it is local, none of it is
// secret, and every read survives storage that is missing, full or blocked.
//
//   - relays: which have passed the loopback test here before, and where each was heard of
//   - the restart throttle of §9.3
//   - the transfer log of §14

import {
  type CodeCheck,
  FAILED_SESSIONS_BEFORE_WARNING,
  isCodeCheck,
  THROTTLE_SECONDS,
  type TransferRecord,
  normalizeRelayUrl,
} from '../qrst-core/index.ts';

/** Where a relay came from, in the order of preference of §11.3a. */
export type Source = 'configured' | 'remembered' | 'learned' | 'discovered' | 'seed';

export interface Candidate {
  url: string;
  source: Source;
}

export interface RelayMemo {
  url: string;
  /** How this device first heard of the relay. */
  origin: Exclude<Source, 'remembered'>;
  /** Seconds since the epoch of the last passed loopback test, if any. */
  lastPass?: number;
  lastFail?: number;
  /** Consecutive failures since the last pass. */
  fails: number;
  /** The reason for the most recent failure. */
  why?: string;
}

export interface LoggedTransfer extends TransferRecord {
  transport: 'relay';
  relays: string[];
}

interface Data {
  relays: RelayMemo[];
  configured: string[];
  /** Null means "use the seeds this build ships". */
  seeds: string[] | null;
  blocked: Record<string, number>;
  failedSessions: number[];
  log: LoggedTransfer[];
  discoveredAt: number;
  /** How this device checks the code, if the user has chosen. */
  check?: CodeCheck;
}

export interface KeyValue {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const KEY = 'qrst.v1';
const MAX_MEMOS = 40;
const MAX_LOG = 50;
const FORGET_AFTER_FAILS = 6;

function empty(): Data {
  return { relays: [], configured: [], seeds: null, blocked: {}, failedSessions: [], log: [], discoveredAt: 0 };
}

function memoryStorage(): KeyValue {
  const map = new Map<string, string>();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

export class Store {
  /** Goes up every time something stored changes, so a view can tell when to redraw. */
  version = 0;
  private data: Data;
  private readonly storage: KeyValue;

  constructor(
    storage: KeyValue | undefined,
    private readonly now: () => number,
    private readonly shippedSeeds: readonly string[] = [],
    private readonly adopterRelays: readonly string[] = [],
  ) {
    this.storage = storage ?? memoryStorage();
    this.data = this.load();
  }

  private load(): Data {
    try {
      const raw = this.storage.getItem(KEY);
      if (!raw) return empty();
      const parsed = JSON.parse(raw) as Partial<Data>;
      return { ...empty(), ...parsed };
    } catch {
      return empty();
    }
  }

  private save(): void {
    this.version++;
    try {
      this.storage.setItem(KEY, JSON.stringify(this.data));
    } catch {
      // A full quota must not cost the throttle or the log: drop what is only informative and retry.
      try {
        for (const m of this.data.relays) delete m.why;
        this.storage.setItem(KEY, JSON.stringify(this.data));
      } catch {
        // Private browsing or a blocked store: carry on in memory.
      }
    }
  }

  // ---- the check ----------------------------------------------------------------------

  /** How this device checks the code, if the user has chosen. */
  check(): CodeCheck | undefined {
    return isCodeCheck(this.data.check) ? this.data.check : undefined;
  }

  setCheck(check: CodeCheck): void {
    this.data.check = check;
    this.save();
  }

  // ---- relays -------------------------------------------------------------------------

  /** Relays the user added here, after the ones the adopting page supplies. */
  configured(): string[] {
    return [...new Set([...this.adopterRelays, ...this.data.configured])];
  }

  userConfigured(): string[] {
    return [...this.data.configured];
  }

  addConfigured(input: string): string | undefined {
    const url = normalizeRelayUrl(input);
    if (!url) return undefined;
    if (!this.data.configured.includes(url)) this.data.configured.push(url);
    this.save();
    return url;
  }

  removeConfigured(url: string): void {
    this.data.configured = this.data.configured.filter((u) => u !== url);
    this.save();
  }

  seeds(): string[] {
    return [...(this.data.seeds ?? this.shippedSeeds)];
  }

  removeSeed(url: string): void {
    if (!this.seeds().includes(url)) return;
    this.data.seeds = this.seeds().filter((u) => u !== url);
    this.save();
  }

  restoreSeeds(): void {
    this.data.seeds = null;
    this.save();
  }

  memos(): RelayMemo[] {
    return this.data.relays.map((m) => ({ ...m }));
  }

  private memo(url: string, origin: RelayMemo['origin']): RelayMemo {
    let m = this.data.relays.find((r) => r.url === url);
    if (!m) {
      m = { url, origin, fails: 0 };
      this.data.relays.push(m);
    }
    return m;
  }

  notePass(url: string, origin: RelayMemo['origin']): void {
    const m = this.memo(url, origin);
    m.lastPass = this.now();
    m.fails = 0;
    delete m.why;
    this.trim();
    this.save();
  }

  noteFail(url: string, origin: RelayMemo['origin'], why: string): void {
    const m = this.memo(url, origin);
    m.lastFail = this.now();
    m.fails++;
    m.why = why.slice(0, 160);
    // A relay that keeps failing is forgotten unless the user or the page put it there.
    if (m.fails >= FORGET_AFTER_FAILS && m.origin !== 'configured') {
      this.data.relays = this.data.relays.filter((r) => r !== m);
    }
    this.save();
  }

  /** §11.3a "Learned": relays named in a QR this device scanned, where that session completed. */
  noteLearned(urls: string[]): void {
    for (const url of urls) this.memo(url, 'learned');
    this.trim();
    this.save();
  }

  noteDiscovered(urls: string[]): void {
    for (const url of urls) this.memo(url, 'discovered');
    this.data.discoveredAt = this.now();
    this.trim();
    this.save();
  }

  discoveryAge(): number {
    return this.now() - this.data.discoveredAt;
  }

  forgetRelay(url: string): void {
    this.data.relays = this.data.relays.filter((r) => r.url !== url);
    this.save();
  }

  private trim(): void {
    if (this.data.relays.length <= MAX_MEMOS) return;
    const score = (m: RelayMemo) => m.lastPass ?? 0;
    this.data.relays.sort((a, b) => score(b) - score(a));
    this.data.relays.length = MAX_MEMOS;
  }

  /**
   * Every relay this device could try, in the order §11.3a prefers: configured, then
   * those that passed here before (most recent first), then learned, discovered, seeds.
   */
  candidates(): Candidate[] {
    const out: Candidate[] = [];
    const add = (url: string, source: Source) => {
      if (!out.some((c) => c.url === url)) out.push({ url, source });
    };
    for (const url of this.configured()) add(url, 'configured');
    const passed = this.data.relays.filter((m) => m.lastPass !== undefined).sort((a, b) => b.lastPass! - a.lastPass!);
    for (const m of passed) add(m.url, 'remembered');
    for (const origin of ['learned', 'discovered'] as const) {
      for (const m of this.data.relays) if (m.lastPass === undefined && m.origin === origin) add(m.url, origin);
    }
    for (const url of this.seeds()) add(url, 'seed');
    return out;
  }

  // ---- §9.3 restart throttle ----------------------------------------------------------

  private prune(): void {
    const cutoff = this.now() - THROTTLE_SECONDS;
    for (const [pub, at] of Object.entries(this.data.blocked)) if (at < cutoff) delete this.data.blocked[pub];
    this.data.failedSessions = this.data.failedSessions.filter((at) => at >= cutoff);
  }

  /** A session ended with a failed code entry against these burners. */
  noteFailedSession(pubs: string[]): void {
    this.prune();
    for (const pub of pubs) this.data.blocked[pub] = this.now();
    this.data.failedSessions.push(this.now());
    this.save();
  }

  isBlocked(pub: string): boolean {
    const at = this.data.blocked[pub];
    return at !== undefined && at >= this.now() - THROTTLE_SECONDS;
  }

  /** True once repeated failures should be explained as possible interference (§9.3). */
  shouldWarnOfInterference(): boolean {
    this.prune();
    return this.data.failedSessions.length >= FAILED_SESSIONS_BEFORE_WARNING;
  }

  // ---- §14 transfer log ---------------------------------------------------------------

  /** §14. A record for the same peer burner and role replaces the earlier one: a session writes at release, then at its end. */
  addRecord(record: LoggedTransfer): void {
    this.data.log = this.data.log.filter((r) => !(r.peer === record.peer && r.role === record.role));
    this.data.log.unshift(record);
    this.data.log.length = Math.min(this.data.log.length, MAX_LOG);
    this.save();
  }

  records(): LoggedTransfer[] {
    return this.data.log.map((r) => ({ ...r }));
  }

  /** Forgets everything this page has stored on this device. */
  clear(): void {
    this.version++;
    this.data = empty();
    try {
      this.storage.removeItem(KEY);
    } catch {
      // nothing to remove
    }
  }
}
