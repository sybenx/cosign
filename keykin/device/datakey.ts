// The data key (core §4.5), as another library calls it: the account's own encryption key for data only
// its devices read (notes, photos, files: the encrypted-sync spec in ~/nostr-sync-nip is the first user).
//
//   const keys = device.dataKeys;
//   const { state, key } = keys.current();      // write new data under `key`, naming `state` with it
//   const old = keys.forState(state);           // read data written under an older state, or null
//   keys.onRotate(({ state }) => …);             // a redeal moved it on: re-encrypt lazily
//
// `dk(S) = HKDF("keykin-dk/1", base data key ‖ seeds of S, sorted)`. Every redeal brings a new seed, sent
// to devices only, so the key rotates with every redeal and a removed device never gets a later one.
// Devices hold it whole; helpers, servers and backups never get it (the backup material carries the base
// key and seeds so a recovery loses no data, §7.2). The keys come from the device's own state, which an
// app keeps in storage that is never backed up or synced (Android `noBackupFilesDir` and a Keystore key
// that needs no unlock; iPhone "this device only", never iCloud Keychain). Never published, never sent.

import { bytesToHex, hexToBytes, shaHex, KeykinError, utf8ToBytes, concatBytes } from '../src/bytes.ts';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { domainFault, isRegistered } from './membersig.ts';
import { dataKey, stateHash } from '../src/codes.ts';
import type { DeviceNode } from './node.ts';

export interface DataKey { state: string; key: Uint8Array }

export class DataKeys {
  readonly d: DeviceNode;
  /** The id sets of every state this device has held, oldest first (core §4.5: older keys read older data). */
  history: string[][] = [];
  #listeners = new Set<(k: DataKey) => void>();
  constructor(d: DeviceNode) { this.d = d; }

  /** The seed of each redeal this device holds one for, by redeal id: a seed is known by its hash, which
   *  the redeal names (`dk`), so a stray or forged seed is never used. */
  #seedsByRedeal(): Map<string, string> {
    const byHash = new Map(this.d.dkSeeds.map((s) => [shaHex(hexToBytes(s)), s]));
    const out = new Map<string, string>();
    for (const [id, x] of this.d.m?.redeals ?? []) { const s = byHash.get(x.r.dk); if (s) out.set(id, s); }
    return out;
  }
  #derive(ids: string[]): Uint8Array | null {
    if (!this.d.baseDk || this.d.wiped) return null;
    const seeds = this.#seedsByRedeal();
    const got = ids.map((id) => seeds.get(id));
    if (got.some((s) => !s)) return null;
    return hexToBytes(dataKey(this.d.baseDk, got as string[]));
  }

  /** The key new data is written under, and the state hash the data names. */
  current(): DataKey {
    this.note();
    const ids = [...(this.d.state?.ids ?? [])];
    const key = this.#derive(ids);
    if (!key) throw new KeykinError('no_data_key', this.d.wiped ? 'this device was removed or wiped' : 'this device holds no data key (a helper, or a seed still missing)');
    return { state: stateHash(ids), key };
  }
  /** The key for data written under `state`, if this device held that state; null otherwise. */
  forState(state: string): Uint8Array | null {
    this.note();
    const ids = this.#candidates().find((x) => stateHash(x) === state);
    return ids ? this.#derive(ids) : null;
  }
  /** Every state the account has been at, as far as this device can tell: the ones it held, the record's
   *  empty state, and each redeal's base plus itself. A device that joined or recovered late holds the
   *  seeds of earlier redeals too (core §7.2), so it reads what was written before it (review 12 R1). */
  #candidates(): string[][] {
    const out = [...this.history, [...(this.d.state?.ids ?? [])], []];
    for (const [id, x] of this.d.m?.redeals ?? []) out.push([...new Set([...(x.r.base ?? []), id])].sort());
    return out;
  }
  /** Every state whose data this device can read, oldest first. */
  states(): string[] { this.note(); return [...new Set(this.#candidates().filter((ids) => this.#derive(ids)).map(stateHash))]; }
  /** Called with the new key whenever a redeal moves it on. Returns a function that stops it. */
  onRotate(cb: (k: DataKey) => void): () => void { this.#listeners.add(cb); return () => void this.#listeners.delete(cb); }
  /** Called when this device holds no data key any more (wiped, or removed from the account): a library
   *  stops using any key it cached (review 12 L3). Listeners run before the device saves its state. */
  onGone(cb: () => void): () => void { this.#gone.add(cb); return () => void this.#gone.delete(cb); }
  #gone = new Set<() => void>();

  /** The device moved to a state (core §6.7.1): remember it, and tell listeners if the key changed. */
  note() {
    if (this.d.wiped || !this.d.state || !this.d.baseDk) return;
    const ids = [...this.d.state.ids].sort();
    const last = this.history[this.history.length - 1];
    if (last && stateHash(last) === stateHash(ids)) return;
    this.history.push(ids);
    const k = this.#derive(ids);
    if (k) for (const cb of this.#listeners) { try { cb({ state: stateHash(ids), key: k }); } catch { /* a listener never wedges the device */ } }
  }
  // --- core 14.21 §4.5: what an app gets. Never dk(S): keys derived from it under a granted domain, for a real state.
  /** `HKDF-SHA256(salt = empty, ikm = dk(S), info = utf8(domain) ‖ 0x00 ‖ bytes, L = 32)` for the state named by the
   *  sorted redeal ids `ids`, any state whose seeds this device holds. Refuses a list that isn't a state (every id a
   *  co-signed redeal whose `base` is inside the list, none beside a redeal that abandons it) and a missing seed; it
   *  never asks other devices for one on an app's behalf. */
  derive(ids: string[], domain: string, bytes: Uint8Array): Uint8Array {
    const f = domainFault(domain); if (f) throw new KeykinError('bad_domain', f);
    if (!isRegistered(domain)) throw new KeykinError('bad_domain', `${domain} is not granted`);
    if (!Array.isArray(ids) || ids.some((x, k) => typeof x !== 'string' || (k > 0 && x <= ids[k - 1]))) throw new KeykinError('not_a_state', 'sorted redeal ids, once each');
    const reds = this.d.m?.redeals;
    const set = new Set(ids);
    for (const id of ids) {
      const r = reds?.get(id)?.r;
      if (!r) throw new KeykinError('not_a_state', `${id} is no co-signed redeal`);
      if ((r.base ?? []).some((b: string) => !set.has(b))) throw new KeykinError('not_a_state', `${id}'s base isn't in the list`);
      if ((r.abandons ?? []).some((a: string) => set.has(a))) throw new KeykinError('not_a_state', `${id} abandons a redeal in the list`);
    }
    const dk = this.#derive([...ids]);
    if (!dk) throw new KeykinError('missing_seed', 'this device lacks a seed of that state');
    return hkdf(sha256, dk, new Uint8Array(0), concatBytes(utf8ToBytes(domain), new Uint8Array([0]), bytes), 32);
  }
  /** The app's view: the device's current state (its ids and hash), never a key. */
  forApps() {
    return {
      derive: (ids: string[], domain: string, bytes: Uint8Array) => this.derive(ids, domain, bytes),
      current: () => { const ids = [...(this.d.state?.ids ?? [])].sort(); return { ids, state: stateHash(ids) }; },
      states: () => [...this.history].reverse().map((ids) => ({ ids, state: stateHash(ids) })),
      onRotate: (cb: (x: { ids: string[]; state: string }) => void) => this.onRotate(() => { const ids = [...(this.d.state?.ids ?? [])].sort(); cb({ ids, state: stateHash(ids) }); }),
    };
  }
  dump() { return this.history; }
  load(x: unknown) { this.history = Array.isArray(x) ? (x as string[][]) : []; }
  clear() { this.history = []; for (const cb of this.#gone) { try { cb(); } catch { /* never wedges the wipe */ } } }
}
export { bytesToHex };
