// What a device needs from wherever its parts of the key are kept.
//
// The member library never holds a share. It asks for the public half of each step — a
// commitment, a partial signature, a point — and the host keeps the secrets wherever it
// keeps them: the Rust side of a Tauri app with the parts in the Keychain, an Android
// keystore, a browser's storage. That boundary is the point: a bug in this library can
// waste a round trip, but it cannot hand a share to anyone.

/** The key as the maths wants it: one entry per part, not per member. */
export interface Group { groupX: string; threshold: number; members: { idx: number; sharePub: string }[] }
export interface Commit { idx: number; D: string; E: string }

/** What the host knows about this device's place in the key. No secrets. */
export interface DeviceState {
  joined: boolean;
  /** True when the parts are there but can't be read (a re-signed app): join again. */
  unreadable?: boolean;
  idxs?: number[];
  sharePubs?: [number, string][];
  /** The account record this library keeps; opaque to the host. */
  group?: unknown;
  epoch?: number;
}

export interface ShareOps {
  state(): Promise<DeviceState>;
  /** This device's own key for member messages. Transport, not a part — but see the note in join(). */
  mailboxKey(): Promise<string>;

  /** A signing round: the nonces stay with the host, named by the handle that comes back. */
  commit(group: Group, idx: number, pending?: boolean): Promise<{ handle: string; commit: Commit }>;
  sign(group: Group, idx: number, handle: string, msg: string, commits: Commit[], pending?: boolean): Promise<string>;
  verifyPartial(group: Group, msg: string, commits: Commit[], idx: number, z: string): Promise<boolean>;
  aggregate(group: Group, msg: string, commits: Commit[], partials: [number, string][]): Promise<string>;

  /** This device's half of a shared secret with [peerX], and the sum of every half. */
  ecdhPartial(idx: number, participants: number[], peerX: string): Promise<string>;
  ecdhCombine(parts: string[]): Promise<string>;

  /** Helping add another device: the host asks for the person's lock itself. */
  repairStep1(group: Group, idx: number, helpers: number[], k: number, name?: string): Promise<[number, string][]>;
  repairStep2(deltas: string[]): Promise<string>;
  /** Being added: the new part is held by the host until commitParts. Returns its public point. */
  repairStep3(group: Group, sigmas: string[], k: number): Promise<string>;

  /**
   * A refresh: every part takes the deltas sent to it, from each dealer. The new parts are
   * held until commitParts, and every share's new point comes back. The host checks each
   * delta against its dealer's commitments.
   */
  refreshApply(group: Group, epoch: number, dealers: { commits: string[]; deltas: [number, string][] }[]): Promise<[number, string][]>;
  /** A refresh nobody committed: forget what was held for it. */
  dropPending(epoch: number): Promise<void>;

  /** What was held is final: this device has joined, or moved to [epoch]. */
  commitParts(group: unknown, epoch: number): Promise<void>;
  /** The account record changed (members, relays, which server answers fastest). */
  update(group: unknown): Promise<void>;
  /** The person's lock, for the things that need it. */
  lock(reason: string): Promise<void>;
  /** This device stops being one. */
  forget(ask: boolean): Promise<void>;
}
