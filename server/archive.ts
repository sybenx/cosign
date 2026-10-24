// Every version of the lists that matter, so a change can be judged against what it
// replaces, and undone by signing the old one again. Where it's kept is the host's
// business (archive.json, for the Node host): it hands in what it had and how to keep it.

import { AHEAD, ARCHIVED, keyOf, type Ev } from './policy.ts';

const KEEP = 25; // versions per list

export class Archive {
  private byKey: Record<string, Ev[]> = {};
  private persist: (byKey: Record<string, Ev[]>) => void;
  /** The network's time, in seconds: one from the future is judged by it. */
  private now: () => number;

  constructor(byKey: Record<string, Ev[]> | undefined, persist: (byKey: Record<string, Ev[]>) => void, now: () => number) {
    this.byKey = byKey ?? {}; this.persist = persist; this.now = now;
  }

  private save() { this.persist(this.byKey); }

  /** The newest version that isn't dated ahead: one from the future is never "the" version. */
  latest(key: string): Ev | undefined { const t = this.now(); return this.byKey[key]?.find(e => e.created_at <= t + AHEAD); }
  /** Versions dated in the future, which would block every change on relays that took them. */
  future(): Ev[] { const t = this.now(); return this.all().filter(e => e.created_at > t + AHEAD); }
  forget(id: string) { for (const k of Object.keys(this.byKey)) this.byKey[k] = this.byKey[k].filter(e => e.id !== id); this.save(); }
  history(key: string): Ev[] { return this.byKey[key] ?? []; }
  find(id: string): Ev | undefined {
    for (const list of Object.values(this.byKey)) { const e = list.find(x => x.id === id); if (e) return e; }
  }

  /** Keep a signed version. Newest first; duplicates and older-than-kept versions are ignored. */
  record(e: Ev): boolean {
    if (!ARCHIVED.has(e.kind) || !e.id || !e.sig) return false;
    const key = keyOf(e);
    const list = (this.byKey[key] ??= []);
    if (list.some(x => x.id === e.id)) return false;
    list.push(e);
    list.sort((a, b) => b.created_at - a.created_at);
    list.length = Math.min(list.length, KEEP);
    this.save();
    return true;
  }

  all(): Ev[] { return Object.values(this.byKey).flat(); }
}
