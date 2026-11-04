// Durable storage for a server's or device's state (core §2, §7.3): one file per account, sealed with
// AES-256-GCM under a key of its own that lives in a separate key ring, outside anything that keeps
// history (volume snapshots, backups, the old blocks a rename leaves). Destroying a record deletes its
// key, so whatever ciphertext history kept can't be read (review 9 M3). Writes are atomic (a temporary
// file of its own, every byte written, fsync, rename, fsync of the directory), so a crash leaves the
// old state or the new one (review 9 L6). What goes in is the node's own snapshot; nonces never do.

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

/** The key ring: one 32-byte key per record. In a deployment it is its own small volume or secret
 *  store, never inside the data volume and never in a backup. */
export class KeyRing {
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; mkdirSync(dir, { recursive: true, mode: 0o700 }); }
  get(key: string, create: boolean): Uint8Array | null {
    const p = join(this.dir, keyName(key));
    if (existsSync(p)) return hexToBytes(readFileSync(p, 'utf8').trim());
    if (!create) return null;
    const k = randomBytes(32);
    writeAtomic(p, utf8ToBytes(bytesToHex(k)), 0o600);
    return k;
  }
  destroy(key: string) { const p = join(this.dir, keyName(key)); if (existsSync(p)) unlinkSync(p); }
}

const MAGIC = utf8ToBytes('kks1');

export class FileStore {
  readonly dir: string; readonly keys: KeyRing;
  constructor(dir: string, keys: KeyRing) {
    if (!keys) throw new Error('a FileStore needs a key ring outside its directory');
    this.dir = dir; this.keys = keys; mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  #path(key: string) { return join(this.dir, `${keyName(key)}.kks`); }
  save(key: string, text: string) {
    const k = this.keys.get(key, true)!, nonce = randomBytes(12);
    const ct = gcm(k, nonce, utf8ToBytes(key)).encrypt(utf8ToBytes(text));
    writeAtomic(this.#path(key), concatBytes(MAGIC, nonce, ct), 0o600);
  }
  /** The stored text, or null if there is none; a damaged file, one moved under another name or one
   *  whose key was destroyed is refused, never half-read. */
  load(key: string): string | null {
    const p = this.#path(key);
    if (!existsSync(p)) return null;
    const b = new Uint8Array(readFileSync(p));
    const k = this.keys.get(key, false);
    if (!k || b.length < 4 + 12 + 16 || !MAGIC.every((x, i) => b[i] === x)) throw new KeykinError('malformed', 'store: unreadable record');
    try { return new TextDecoder('utf-8', { fatal: true }).decode(gcm(k, b.slice(4, 16), utf8ToBytes(key)).decrypt(b.slice(16))); }
    catch { throw new KeykinError('malformed', 'store: unreadable record'); }
  }
  /** Every record's key. */
  list(): string[] { return readdirSync(this.dir).filter((f) => f.endsWith('.kks')).map((f) => f.slice(0, -4)); }
  /** Destroy a record: its key first, then the file. */
  destroy(key: string) { this.keys.destroy(key); const p = this.#path(key); if (existsSync(p)) unlinkSync(p); }
}
