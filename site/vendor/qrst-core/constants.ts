// Every number the specification fixes, in one place.
//
// The message kinds are PROVISIONAL (spec §11.4): chosen from the ephemeral range and
// checked free of collision, but not reserved by a NIP. They live here and nowhere
// else so that a change is a one-line change. SEAL and WRAP are NIP-59's; WRAP is its
// ephemeral gift wrap (NIP-59 §4), which a relay delivers live and does not store.

export const KINDS = {
  SEAL: 13,
  WRAP: 21059,
  AUTH: 22242,
  HELLO: 24401,
  REQUEST: 24402,
  NONCE: 24403,
  REVEAL: 24404,
  PAYLOAD: 24405,
  ACK: 24406,
  ABORT: 24407,
} as const;

/** Protocol version carried in the QR as `v=1` and hashed as a single byte (§6). */
export const VERSION = 1;

/** A session lives ten minutes (§2). */
export const SESSION_SECONDS = 600;

/** Tolerance at each end of the session window, in seconds. Normative (§11.4). */
export const SLACK_SECONDS = 120;

/** The Sender zeroizes its burner on ACK or after this long (§7 step 18, §8 step 18). */
export const ACK_WAIT_SECONDS = 60;

/** Code-entry attempts per session (§9.2). */
export const MAX_ATTEMPTS = 5;

/** Responders a Receiver that showed the QR answers over the whole session (§13). */
export const MAX_HELD = 3;

/** Responders a Sender that showed the QR answers over the whole session (§8, §13). */
export const MAX_PENDING = 5;

/** Default maximum payload, in bytes of binary (§4, P1). */
export const DEFAULT_MAX_PAYLOAD = 2048;

/** A Sender remembers peer burners it failed a code against for at least this long (§9.3). */
export const THROTTLE_SECONDS = 3600;

/** Failed sessions within THROTTLE_SECONDS before the interference warning (§9.3). */
export const FAILED_SESSIONS_BEFORE_WARNING = 3;

/** Relays a QR may name (§11.2). */
export const MAX_RELAYS = 4;

export const PROFILE_ID = /^[a-z0-9-]{1,24}$/;

/**
 * How the Sender makes sure it is releasing to the device in front of the user,
 * weakest first (spec §9.2).
 *
 *   none     No code. Release on consent alone: whoever answers the code gets it,
 *            and a second device answering ends the session.
 *   compare  Both devices show the code and the user says whether they match.
 *   type     The Receiver shows the code and the user types it on the Sender.
 *
 * Each device has its own setting and the stricter of the two applies.
 */
export const CODE_CHECKS = ['none', 'compare', 'type'] as const;
export type CodeCheck = (typeof CODE_CHECKS)[number];

export function isCodeCheck(value: unknown): value is CodeCheck {
  return typeof value === 'string' && (CODE_CHECKS as readonly string[]).includes(value);
}

/** The stricter of two settings. */
export function stricter(a: CodeCheck, b: CodeCheck): CodeCheck {
  return CODE_CHECKS.indexOf(a) >= CODE_CHECKS.indexOf(b) ? a : b;
}

/**
 * Bytes of the token a pairing link carries, which whoever answers must echo inside
 * its first sealed message. The burner key is not secret (a relay sees it), so the
 * token is what shows that a responder actually saw the code.
 */
export const TOKEN_BYTES = 16;
