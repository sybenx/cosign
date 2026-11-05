// Device names (Account admin §2, "Names"): a device names itself; the name and its model are kept in one account-
// signed kind 30078 event per device, `d = "keykin-labels:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF(base data key,
// "keykin-labels-d/1"), member key))` (relays can't link it to a member key), its content XChaCha20-Poly1305 under
// HKDF-SHA256(dk(S), "keykin-labels/1") with associated data `g ‖ d ‖ state hash`, as base64(nonce ‖ ciphertext), and
// inside, the label signed by the named device's own member key. Devices show only a name signed by the device it
// names, always with its model, and flag two devices with the same name (a stolen device passing itself off as another).
//
// "Last seen" is this device's own observation (a message it took from that device), never published: nothing on the
// relays says when a device was online. A label's `at` changes only when the name does.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { bytesToHex, hexToBytes, randomBytes, sha, strictJson, utf8ToBytes, utf8Strict, concatBytes, refuse, jcs, hkdf32 } from '../src/bytes.ts';
import { schnorrSign, schnorrVerify, verifyEvent, type KeyPair, type NostrEvent } from '../src/event.ts';
import { KIND_GRANTS } from './grants.ts';

export const KIND_LABELS = KIND_GRANTS;   // 30078, under the `keykin-` guard (Doors and grants §2)
export interface Label { name: string; model: string; at: number }
const MAX = 64;

export const labelD = (baseDk: string, member: string) =>
  'keykin-labels:' + bytesToHex(hmac(sha256, hkdf32(hexToBytes(baseDk), 'keykin-labels-d/1'), hexToBytes(member)).slice(0, 16));
const contentKey = (dk: Uint8Array) => hkdf32(dk, 'keykin-labels/1');
const aad = (g: string, d: string, state: string) => concatBytes(hexToBytes(g), utf8ToBytes(d), hexToBytes(state));
export const labelDigest = (g: string, member: string, l: Label) => sha('keykin-label/1', hexToBytes(g), hexToBytes(member), sha(jcs({ name: l.name, model: l.model, at: l.at })));
const ok = (s: unknown) => typeof s === 'string' && s.length <= MAX && !/[\u0000-\u001f\u007f]/.test(s);

/** A name as the person typed it: trimmed, at most 64 characters, no control characters. */
export function cleanLabel(name: string, model: string): { name: string; model: string } {
  const n = String(name ?? '').trim(), m = String(model ?? '').trim();
  if (!n || !ok(n) || !ok(m)) refuse('malformed', 'a name of 1–64 characters, and a model of at most 64');
  return { name: n, model: m };
}

/** This device's label event, unsigned (the account signs it). */
export function labelEvent(g: string, member: KeyPair, baseDk: string, dk: { state: string; key: Uint8Array }, l: Label, createdAt: number) {
  const d = labelD(baseDk, member.pub);
  const text = jcs({ name: l.name, model: l.model, at: l.at, sig: schnorrSign(labelDigest(g, member.pub, l), member.sk) });
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(contentKey(dk.key), nonce, aad(g, d, dk.state)).encrypt(utf8ToBytes(text));
  return { pubkey: g, created_at: createdAt, kind: KIND_LABELS, tags: [['d', d], ['state', dk.state]], content: base64.encode(concatBytes(nonce, ct)) };
}

/** `member`'s label among `events`: account-signed, opened under its state's data key, signed by `member`; of those,
 *  the highest `at` (`created_at` breaks a tie). Any device can publish at another's `d` (the events are the account's),
 *  so a replayed older label, still verifying, must never win over a newer one (Account admin draft 9 §2). */
export function readLabel(g: string, member: string, baseDk: string, keyFor: (state: string) => Uint8Array | null, events: NostrEvent[]): (Label & { state: string; created_at: number }) | null {
  const d = labelD(baseDk, member);
  const mine = events.filter((e) => e?.kind === KIND_LABELS && e.pubkey === g && e.tags.find((t) => t[0] === 'd')?.[1] === d && verifyEvent(e));
  let best: (Label & { state: string; created_at: number }) | null = null;
  for (const e of mine) {
    try {
      const state = e.tags.find((t) => t[0] === 'state')?.[1] ?? '';
      const key = keyFor(state); if (!key) continue;
      const b = base64.decode(e.content);
      const x = strictJson(utf8Strict(xchacha20poly1305(contentKey(key), b.slice(0, 24), aad(g, d, state)).decrypt(b.slice(24))));
      if (!ok(x.name) || !x.name || !ok(x.model) || !Number.isSafeInteger(x.at)) continue;
      const l: Label = { name: x.name, model: x.model, at: x.at };
      if (!schnorrVerify(x.sig, labelDigest(g, member, l), member)) continue;
      if (!best || l.at > best.at || (l.at === best.at && e.created_at > best.created_at)) best = { ...l, state, created_at: e.created_at };
    } catch { /* one we can't open, or a forgery */ }
  }
  return best;
}
