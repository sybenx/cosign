// Everything signed, and for whom, so it can be undone: one site's work, however much
// of it there is. A list change also keeps the version it replaced, so putting a list
// back never depends on how much of the archive is left. Deleted events are kept too,
// so a deletion (which Nostr can't take back) never loses the post itself. The host
// keeps both lists (history.jsonl and saved.jsonl, for the Node host), only ever adding.

import type { Ev } from './policy.ts';

export interface Entry {
  /** When it was signed (seconds). */
  at: number;
  /** The grant it was signed for (a site's or app's key), or '' for your own (Undo, …). */
  site: string;
  /** Who, in words: the site's origin or the app's name. */
  by: string;
  event: Ev;
  /** For a list or profile: the version this one replaced. */
  prev?: Ev;
}

export class History {
  private entries: Entry[] = [];
  private ids = new Set<string>();
  private saved = new Map<string, Ev>();
  private keep: { entry(e: Entry): void; saved(e: Ev): void };

  constructor(entries: Entry[], saved: Ev[], keep: { entry(e: Entry): void; saved(e: Ev): void }) {
    this.keep = keep;
    for (const e of entries) this.remember(e);
    for (const e of saved) if (e?.id) this.saved.set(e.id, e);
  }

  private remember(e: Entry) {
    if (!e.event?.id || this.ids.has(e.event.id)) return false;
    this.ids.add(e.event.id);
    this.entries.push(e);
    return true;
  }

  /** Keep it. False if it was already here. */
  add(e: Entry): boolean {
    if (!this.remember(e)) return false;
    this.keep.entry(e);
    return true;
  }

  bySite(site: string, since = 0): Entry[] { return this.entries.filter(e => e.site === site && e.at >= since); }
  event(id: string): Ev | undefined { return this.entries.find(e => e.event.id === id)?.event ?? this.saved.get(id); }

  /** A copy of something about to be deleted, kept for good. */
  save(e: Ev) {
    if (!e.id || this.saved.has(e.id)) return;
    this.saved.set(e.id, e);
    this.keep.saved(e);
  }
  savedCopy(id: string): Ev | undefined { return this.saved.get(id); }
  allSaved(): Ev[] { return [...this.saved.values()]; }
}
