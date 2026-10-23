// Every version of the lists that matter, so a change can be judged against what it
// replaces, and undone by signing the old one again.

import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { ARCHIVED, keyOf, type Ev } from './policy.ts';

const KEEP = 25; // versions per list

export class Archive {
  private byKey: Record<string, Ev[]> = {};
  private file: string;

  constructor(file: string) {
    this.file = file;
    if (existsSync(file)) {
      try { this.byKey = JSON.parse(readFileSync(file, 'utf8')); } catch { this.byKey = {}; }
    }
  }

  private save() {
    writeFileSync(this.file + '.tmp', JSON.stringify(this.byKey), { mode: 0o600 });
    renameSync(this.file + '.tmp', this.file);
  }

  latest(key: string): Ev | undefined { return this.byKey[key]?.[0]; }
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
