// What a host gives a group: the only way the core reaches anything outside itself.
// The Node host (../server.ts) backs it with one relay pool and files; a Worker host
// would back it with a WebSocket and Workers KV (../HOSTS.md).

import type { Event } from 'nostr-tools/pure';
import type { Filter } from 'nostr-tools/filter';
import type { Ev } from '../policy.ts';
import type { Entry } from '../history.ts';

/** One group's state as it was last saved, handed to `openGroup`. */
export interface Loaded {
  /** state.json: this member's key and share(s), the group record, the signer key, sites, tickets, changes. */
  state: any;
  /** archive.json: every kept version of each list, newest first. */
  archive: Record<string, Ev[]>;
  /** history.jsonl and saved.jsonl, oldest first. */
  history: Entry[];
  saved: Ev[];
}

export interface Io {
  /** Put an event on this group's relays: a sealed member message, or an answer to a site. */
  publish(e: Event): void;
  /** Also listen (and publish) on these relays for this group: a site's own, a new device's. Resolves once they're up, or after `ms`. */
  listen(relays: string[], ms?: number): Promise<void>;
  /** Publish once to these relays and wait for them (your write relays, for an undo). */
  publishOut(relays: string[], e: Event): Promise<void>;
  /** Fetch stored events from these relays: the archive, a copy of what's being deleted. */
  query(relays: string[], filter: Filter, maxWait: number): Promise<Event[]>;
  /** Wake a device: POST "cosign:approve" to its push endpoint (ntfy). */
  push(url: string): Promise<unknown>;
  /** Milliseconds, by this machine's clock: timeouts and liveness. */
  now(): number;
  /** Seconds, by the network's time (../clock.ts): what counts as dated in the future. */
  trustedNow(): number;
  /** Keep it. Each is called after a change, with the whole of what changed. */
  save: {
    state(S: any): void;
    archive(byKey: Record<string, Ev[]>): void;
    entry(e: Entry): void;
    saved(e: Ev): void;
  };
  /** A line for the log (the group keeps its own list of recent ones for its page). */
  note(text: string): void;
  /** More detail, when the host wants it (DEBUG=1). */
  debug?(text: string): void;
}
