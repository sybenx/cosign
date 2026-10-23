// Profiles (spec §5). A profile defines one kind of payload; the mechanism never
// parses a payload itself (P3) and learns everything about it through this interface.

import { base64 } from '@scure/base';
import { utf8Decode, utf8Encode } from './bytes.ts';
import type { CodeCheck } from './constants.ts';
import { DEFAULT_MAX_PAYLOAD, PROFILE_ID } from './constants.ts';

export type Check<T> = { ok: true; value: T } | { ok: false; reason: string };

export interface ReleaseWording {
  /** Contradicts the mental model of someone who believes they are signing in (§9.1). */
  heading: string;
  /** What leaves this device, in the profile's words (§5 item 5). */
  body: string;
  /** The affirmative control. It describes the transfer; it never just agrees (§9.1). */
  confirm(origin: string | undefined): string;
  decline: string;
}

export interface Profile<T> {
  /** `[a-z0-9-]{1,24}`, carried in the QR and hashed into the code. */
  readonly id: string;
  /** P1: the largest payload, in bytes of binary. */
  readonly maxPayloadBytes: number;
  /** Whether a released secret can be withdrawn afterwards. Drives the wording of §9.1. */
  readonly revocable: boolean;
  /** The lowest check level this profile permits (§5, item 7). Unstated means `compare`. */
  readonly minCheck?: CodeCheck;
  /** Value to the content of the PAYLOAD message. Throws if the value does not fit. */
  encode(value: T): string;
  /** P4: does this content belong to this profile? */
  check(content: string): Check<T>;
  /** P5: a human-meaningful rendering, shown before the payload is kept. */
  render(value: T): string;
  /** The line that accompanies a QR, by the mode of the code (§11.2b). */
  readonly direction: { offer: string; request: string };
  readonly release: ReleaseWording;
  /** What the Receiver is asked before it keeps the payload (§9.4). Not alarming. */
  readonly accept: { heading: string; confirm: string; decline: string };
}

export function assertProfile(p: Profile<unknown>): void {
  if (!PROFILE_ID.test(p.id)) throw new Error('profile: identifier must match [a-z0-9-]{1,24}');
  if (!Number.isInteger(p.maxPayloadBytes) || p.maxPayloadBytes < 1) throw new Error('profile: bad maximum size');
}

/** How many characters of a secret the rendering may show: enough to recognise, never most of it. */
function previewLength(characters: number): number {
  return Math.min(3, Math.floor(characters / 4));
}

/**
 * The demo profile: a short piece of text, such as an API key or a recovery phrase.
 *
 * Payload: the text as UTF-8, base64. Default maximum size.
 * P4: valid base64 of 1 to 2048 bytes that decodes as UTF-8.
 * P5: its length, and its first few characters when it is long enough to spare them.
 * Not revocable: the mechanism cannot know what the text is, so it assumes the worst.
 */
export const demoText: Profile<string> = {
  id: 'qrst-demo-text',
  maxPayloadBytes: DEFAULT_MAX_PAYLOAD,
  revocable: false,
  // The spec advises against `none` for what cannot be revoked. This profile carries
  // made-up demo text and exists to show every level, so it permits all three.
  minCheck: 'none',

  encode(value) {
    const bytes = utf8Encode(value);
    if (bytes.length < 1) throw new Error('There is nothing to send.');
    if (bytes.length > this.maxPayloadBytes) {
      throw new Error(`That is ${bytes.length} bytes; the most this profile carries is ${this.maxPayloadBytes}.`);
    }
    return base64.encode(bytes);
  },

  check(content) {
    let bytes: Uint8Array;
    try {
      bytes = base64.decode(content);
    } catch {
      return { ok: false, reason: 'not base64' };
    }
    if (bytes.length < 1 || bytes.length > this.maxPayloadBytes) return { ok: false, reason: 'size out of range' };
    try {
      return { ok: true, value: utf8Decode(bytes) };
    } catch {
      return { ok: false, reason: 'not text' };
    }
  },

  render(value) {
    const characters = Array.from(value);
    const count = `${characters.length} character${characters.length === 1 ? '' : 's'}`;
    const shown = previewLength(characters.length);
    if (shown === 0) return count;
    const start = characters
      .slice(0, shown)
      .join('')
      .replace(/\s/g, '␣');
    return `${count}, starting with “${start}”`;
  },

  direction: {
    offer: 'Scanning this QR code sends a text from your other device to this one.',
    request: 'This device is sending a text. Scan this QR code to receive it.',
  },

  release: {
    heading: 'This is not a login. You are about to give your text to another device.',
    body: 'The text itself leaves this device and is delivered to the device described below. Once it is sent it cannot be taken back.',
    confirm: (origin) => (origin ? `Send my text to the device at ${origin}` : 'Send my text to that device'),
    decline: 'Don’t send',
  },

  accept: {
    heading: 'Your other device sent a text',
    confirm: 'Keep it',
    decline: 'Discard it',
  },
};
