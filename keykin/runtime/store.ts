// Durable storage for a server's or device's state (core §2): one file per account, written atomically
// (a temporary file, fsync, rename, fsync of the directory), so a crash leaves the old state or the new
// one, never half of either. What goes in is the node's own snapshot; nonces never do (§5.2).

import { openSync, writeSync, fsyncSync, closeSync, renameSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

export class FileStore {
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; mkdirSync(dir, { recursive: true }); }
  #path(key: string) {
    if (!/^[0-9a-z_-]{1,128}$/.test(key)) throw new Error(`store key: ${key}`);
    return join(this.dir, `${key}.json`);
  }
  save(key: string, text: string) {
    const p = this.#path(key), tmp = `${p}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try { writeSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, p);
    const d = openSync(dirname(p), 'r');
    try { fsyncSync(d); } finally { closeSync(d); }
  }
  load(key: string): string | null { const p = this.#path(key); return existsSync(p) ? readFileSync(p, 'utf8') : null; }
}
