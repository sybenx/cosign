// Sealing and gift-wrapping (spec §11.4).
//
// Every QRST message is an unsigned rumor, sealed (kind 13, signed by the sending
// burner, NIP-44 to the recipient burner) and gift-wrapped (kind 21059, NIP-59's
// ephemeral gift wrap: a random one-time signing key, `p` tag set to the recipient
// burner). There are no exceptions.
//
// Kind 21059 rather than 1059: relays treat 1059 as a stored direct message and keep
// serving it after it lapses, while a relay MUST NOT store 21059. The price is that a
// wrap reaches only the subscribers connected when it is published, so the host
// re-sends what is outstanding (§11.5, pool.ts), each time in a fresh wrap around the
// same seal: see `giftWrap`.
//
// Two departures from NIP-59, both required by §11.4:
//   - every timestamp is the true current time, never a randomised past value;
//   - the wrap carries a NIP-40 `expiration` tag of now + 600. NIP-40 says expiration
//     does not apply to ephemeral events, so on a relay that honours 21059 it costs
//     nothing; it is kept for a relay that does not treat 21059 as ephemeral and
//     stores it, which then still has a reason to drop it.

import { isHex32, wipe } from './bytes.ts';
import { KINDS, SESSION_SECONDS } from './constants.ts';
import {
  type Env,
  type EventTemplate,
  type NostrEvent,
  type Rumor,
  eventId,
  generateSecretKey,
  isEventShape,
  publicKey,
  rumor as makeRumor,
  sign,
  verify,
} from './event.ts';
import { conversationKey, decrypt, encrypt } from './nip44.ts';

export interface RumorInput {
  kind: number;
  tags?: string[][];
  content?: string;
}

/** Builds a rumor from the sending burner. Its `pubkey` is the attribution §11.4 checks. */
export function buildRumor(input: RumorInput, senderPub: string, now: number): Rumor {
  return makeRumor({
    pubkey: senderPub,
    created_at: now,
    kind: input.kind,
    tags: input.tags ?? [],
    content: input.content ?? '',
  });
}

/** Seals a rumor to `recipientPub` and wraps the seal. Returns the kind 21059 event to publish. */
export function wrap(r: Rumor, senderSecret: Uint8Array, recipientPub: string, env: Env): NostrEvent {
  return giftWrap(seal(r, senderSecret, recipientPub, env), recipientPub, env);
}

/** The kind 13 seal: the rumor, NIP-44 to `recipientPub`, signed by the sending burner. */
export function seal(r: Rumor, senderSecret: Uint8Array, recipientPub: string, env: Env): NostrEvent {
  if (!isHex32(recipientPub)) throw new Error('wrap: bad recipient');
  const now = env.now();
  const sealKey = conversationKey(senderSecret, recipientPub);
  const sealed = sign(
    {
      pubkey: publicKey(senderSecret),
      created_at: now,
      kind: KINDS.SEAL,
      tags: [],
      content: encrypt(JSON.stringify(r), sealKey, env.random(32)),
    },
    senderSecret,
    env.random,
  );
  wipe(sealKey);
  return sealed;
}

/**
 * Wraps a seal for `recipientPub` under a fresh one-time key, timestamped now.
 *
 * A re-send calls this again on the seal it already has. Every call gives a new event
 * id and a current `created_at`, which a relay needs: some answer "duplicate" to an
 * id they have seen and deliver nothing, and some refuse an ephemeral event more than
 * a minute old. The seal needs no burner, so a message can go again after the
 * session has wiped its key; the rumor inside is unchanged, and the recipient
 * recognises it by the rumor's id.
 */
export function giftWrap(sealed: NostrEvent, recipientPub: string, env: Env): NostrEvent {
  if (!isHex32(recipientPub)) throw new Error('wrap: bad recipient');
  const now = env.now();
  const oneTime = generateSecretKey(env.random);
  const wrapKey = conversationKey(oneTime, recipientPub);
  const wrapped = sign(
    {
      pubkey: publicKey(oneTime),
      created_at: now,
      kind: KINDS.WRAP,
      tags: [
        ['p', recipientPub],
        ['expiration', String(now + SESSION_SECONDS)],
      ],
      content: encrypt(JSON.stringify(sealed), wrapKey, env.random(32)),
    },
    oneTime,
    env.random,
  );
  wipe(oneTime, wrapKey);
  return wrapped;
}

export type UnwrapFailure =
  | 'not-a-wrap'
  | 'not-for-us'
  | 'bad-wrap-signature'
  | 'undecryptable'
  | 'bad-seal'
  | 'bad-rumor'
  | 'attribution';

export type Unwrapped = { ok: true; rumor: Rumor } | { ok: false; reason: UnwrapFailure };

function open(secret: Uint8Array, peerPub: string, content: string): string | undefined {
  let key: Uint8Array | undefined;
  try {
    key = conversationKey(secret, peerPub);
    return decrypt(content, key);
  } catch {
    return undefined;
  } finally {
    wipe(key);
  }
}

function parse(json: string): unknown {
  try {
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

/**
 * Opens a gift wrap addressed to `recipientSecret`.
 *
 * On success the rumor's `pubkey` is the burner that signed the seal: that equality is
 * the attribution check (T5), and nothing else in the event says who sent it. A relay
 * can drop or replay a wrap but cannot produce one that passes here.
 */
export function unwrap(event: unknown, recipientSecret: Uint8Array): Unwrapped {
  if (!isEventShape(event) || event.kind !== KINDS.WRAP) return { ok: false, reason: 'not-a-wrap' };
  const own = publicKey(recipientSecret);
  if (!event.tags.some((t) => t[0] === 'p' && t[1] === own)) return { ok: false, reason: 'not-for-us' };
  if (!verify(event)) return { ok: false, reason: 'bad-wrap-signature' };

  const sealJson = open(recipientSecret, event.pubkey, event.content);
  if (sealJson === undefined) return { ok: false, reason: 'undecryptable' };
  const seal = parse(sealJson);
  if (!isEventShape(seal) || seal.kind !== KINDS.SEAL || !verify(seal)) return { ok: false, reason: 'bad-seal' };

  const rumorJson = open(recipientSecret, seal.pubkey, seal.content);
  if (rumorJson === undefined) return { ok: false, reason: 'undecryptable' };
  const inner = parse(rumorJson);
  if (!isEventShape(inner)) return { ok: false, reason: 'bad-rumor' };
  const template: EventTemplate = {
    pubkey: inner.pubkey,
    created_at: inner.created_at,
    kind: inner.kind,
    tags: inner.tags,
    content: inner.content,
  };
  // The sending burner appears in no other field (§11.4, attribution check).
  if (template.pubkey !== seal.pubkey) return { ok: false, reason: 'attribution' };
  const id = eventId(template);
  if (inner.id !== undefined && inner.id !== id) return { ok: false, reason: 'bad-rumor' };
  return { ok: true, rumor: { ...template, id } };
}
