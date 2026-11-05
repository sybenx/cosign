// Durable storage for a server's or device's state (core §2, §7.3): one file per record, sealed with
// AES-256-GCM under a key of its own that lives in a separate key ring, outside anything that keeps
// history (volume snapshots, backups, the old blocks a rename leaves). Every save seals under a fresh key
// and deletes the old one, so a /data snapshot from before can't be opened with today's key ring: what
// was destroyed since (an enrol secret past 13 months, a deleted account) stays destroyed (review 9 M3,
// review 10 M2). Writes are atomic (a temporary file of its own, every byte written, fsync, rename,
// fsync of the directory): the new key goes in first, then the record naming it, then the old keys go,
// so a crash leaves the old record or the new one, each with its key. Nonces never go in.

import { openSync, writeSync, fsyncSync, closeSync, renameSync, readFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, utf8ToBytes, bytesToHex, hexToBytes, KeykinError, concatBytes } from '../src/bytes.ts';

const keyName = (key: string) => { if (!/^[0-9a-z_-]{1,128}$/.test(key)) throw new Error(`store key: ${key}`); return key; };

function writeAtomic(p: string, data: Uint8Array, mode: number) {
  const tmp = `${p}.${process.pid}.${bytesToHex(randomBytes(6))}.tmp`;
  const fd = openSync(tmp, 'wx', mode);
  try {
    for (let off = 0; off < data.length;) off += writeSync(fd, data, off, data.length - off);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  renameSync(tmp, p);
  const d = openSync(dirname(p), 'r');
  try { fsyncSync(d); } finally { closeSync(d); }
}

/** The key ring: keys named `<record>.<key id>`. In a deployment it is its own small volume or secret
 *  store, never inside the data volume and never in a backup. */
export class KeyRing {
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; mkdirSync(dir, { recursive: true, mode: 0o700 }); }
  #p(key: string, id: string) { return join(this.dir, `${keyName(key)}.${id}`); }
  /** A fresh key for `key`; the caller drops the others once the record naming it is written. */
  fresh(key: string): { id: string; k: Uint8Array } {
    const id = bytesToHex(randomBytes(8)), k = randomBytes(32);
    writeAtomic(this.#p(key, id), utf8ToBytes(bytesToHex(k)), 0o600);
    return { id, k };
  }
  get(key: string, id: string): Uint8Array | null {
    if (!/^[0-9a-f]{16}$/.test(id)) return null;
    const p = this.#p(key, id);
    return existsSync(p) ? hexToBytes(readFileSync(p, 'utf8').trim()) : null;
  }
  /** Delete every key of `key` but `keep`. */
  drop(key: string, keep?: string) {
    for (const f of readdirSync(this.dir)) if (f.startsWith(`${keyName(key)}.`) && f !== `${key}.${keep}` && !f.endsWith('.tmp')) unlinkSync(join(this.dir, f));
  }
}

const MAGIC = utf8ToBytes('kks2');

export class FileStore {
  readonly dir: string; readonly keys: KeyRing;
  constructor(dir: string, keys: KeyRing) {
    if (!keys) throw new Error('a FileStore needs a key ring outside its directory');
    this.dir = dir; this.keys = keys; mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  #path(key: string) { return join(this.dir, `${keyName(key)}.kks`); }
  save(key: string, text: string) {
    const { id, k } = this.keys.fresh(key), nonce = randomBytes(12);
    const ct = gcm(k, nonce, utf8ToBytes(`${key}.${id}`)).encrypt(utf8ToBytes(text));
    writeAtomic(this.#path(key), concatBytes(MAGIC, hexToBytes(id), nonce, ct), 0o600);
    this.keys.drop(key, id);
  }
  /** The stored text, or null if there is none; a damaged file, one moved under another name or one
   *  whose key was destroyed is refused, never half-read. */
  load(key: string): string | null {
    const p = this.#path(key);
    if (!existsSync(p)) return null;
    const b = new Uint8Array(readFileSync(p));
    const bad = () => new KeykinError('malformed', 'store: unreadable record');
    if (b.length < 4 + 8 + 12 + 16 || !MAGIC.every((x, i) => b[i] === x)) throw bad();
    const id = bytesToHex(b.slice(4, 12)), k = this.keys.get(key, id);
    if (!k) throw bad();
    try { return new TextDecoder('utf-8', { fatal: true }).decode(gcm(k, b.slice(12, 24), utf8ToBytes(`${key}.${id}`)).decrypt(b.slice(24))); }
    catch { throw bad(); }
  }
  /** Every record's key. */
  list(): string[] { return readdirSync(this.dir).filter((f) => f.endsWith('.kks')).map((f) => f.slice(0, -4)); }
  /** Destroy a record: its keys first, then the file. */
  destroy(key: string) { this.keys.drop(key); const p = this.#path(key); if (existsSync(p)) unlinkSync(p); }
}
