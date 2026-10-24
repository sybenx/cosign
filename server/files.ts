// A group on disk, for the Node host: the same files a server has always kept, so a
// directory setup.ts made (data/a) and one a shared server made (data/groups/<id>) read
// the same way.
//
//   state.json      this member's key and share, the group, the signer key, sites…
//   archive.json    every kept version of each list
//   history.jsonl   everything signed, one per line, only ever added to
//   saved.jsonl     copies of deleted events

import { readFileSync, writeFileSync, renameSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Loaded, Io } from './core/io.ts';

const lines = (f: string) => {
  const out: any[] = [];
  if (!existsSync(f)) return out;
  for (const line of readFileSync(f, 'utf8').split('\n')) { if (line) try { out.push(JSON.parse(line)); } catch { /* a torn last line */ } }
  return out;
};

const writeJson = (f: string, value: unknown, pretty = false) => {
  writeFileSync(f + '.tmp', JSON.stringify(value, null, pretty ? 2 : undefined), { mode: 0o600 });
  renameSync(f + '.tmp', f);
};

export const isGroupDir = (dir: string) => existsSync(join(dir, 'state.json'));

export function loadGroup(dir: string): Loaded {
  let archive = {};
  if (existsSync(join(dir, 'archive.json'))) try { archive = JSON.parse(readFileSync(join(dir, 'archive.json'), 'utf8')); } catch { archive = {}; }
  return {
    state: JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8')),
    archive,
    history: lines(join(dir, 'history.jsonl')),
    saved: lines(join(dir, 'saved.jsonl')),
  };
}

export function groupFiles(dir: string): Io['save'] {
  return {
    state: S => writeJson(join(dir, 'state.json'), S, true),
    archive: byKey => writeJson(join(dir, 'archive.json'), byKey),
    entry: e => appendFileSync(join(dir, 'history.jsonl'), JSON.stringify(e) + '\n', { mode: 0o600 }),
    saved: e => appendFileSync(join(dir, 'saved.jsonl'), JSON.stringify(e) + '\n', { mode: 0o600 }),
  };
}

/** A new group's directory, with its state; nothing else exists yet. */
export function createGroup(dir: string, state: object) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeJson(join(dir, 'state.json'), state, true);
}

export { writeJson };
