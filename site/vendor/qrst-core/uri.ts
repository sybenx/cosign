// The pairing address of spec §11.2: one https link whose every parameter lives in
// the fragment, so that neither the burner key nor the relay list reaches the host.
//
//   https://<host>/<path>#v=1&mode=<offer|request>&p=<profile-id>&npub=<npub>
//                         &check=<none|compare|type>&token=<32 hex>
//                         [&relay=<wss url>]*[&origin=<claimed-origin>]
//
// `check` and `token` are new in 1.5-draft.

import { type CodeCheck, MAX_RELAYS, PROFILE_ID, TOKEN_BYTES, VERSION, isCodeCheck } from './constants.ts';
import { npubDecode, npubEncode } from './event.ts';

/** `offer`: the showing device is the Receiver (Flow A). `request`: it is the Sender (Flow B). */
export type Mode = 'offer' | 'request';
export type Role = 'sender' | 'receiver';

export interface PairingParams {
  v: typeof VERSION;
  mode: Mode;
  profile: string;
  /** Burner public key of the device showing the code, 32 bytes of hex. */
  pub: string;
  /** How the showing device wants the code checked. The stricter of the two devices' settings applies. */
  check: CodeCheck;
  /** Echoed by whoever answers, to show it saw the code: hex, TOKEN_BYTES long. */
  token: string;
  /** One to four relays the showing device is listening on. */
  relays: string[];
  /** Present if and only if the showing device is a web client. An unverified claim. */
  origin?: string;
}

export type UriErrorCode =
  | 'not-a-pairing-link'
  | 'unknown-version'
  | 'missing-mode'
  | 'missing-profile'
  | 'bad-key'
  | 'bad-token'
  | 'no-relays'
  | 'bad-relay'
  | 'bad-origin';

export class UriError extends Error {
  constructor(public readonly code: UriErrorCode) {
    super(`pairing link: ${code}`);
    this.name = 'UriError';
  }
}

const TOKEN = new RegExp(`^[0-9a-f]{${TOKEN_BYTES * 2}}$`);

/** True for a token of the right length in lowercase hex. */
export function isToken(value: unknown): value is string {
  return typeof value === 'string' && TOKEN.test(value);
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Whether a relay on this machine may be used at all. Off unless the host turns it
 * on, which a page does only when it is itself served from this machine: a pairing
 * link must not be able to point a public page at a service on the user's computer.
 */
export const relayPolicy = { loopback: false };

/**
 * True for a host on this machine or a private network, where no public relay lives:
 * §11.3a's private-network address, plus Tailscale's names, which resolve only on a tailnet.
 */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  if (LOOPBACK.has(h) || /\.(localhost|local|internal|home\.arpa|ts\.net)$/.test(h)) return true;
  if (h.startsWith('[')) {
    // An IPv4-mapped address, which URL parsing writes as [::ffff:a00:1], is the IPv4 address it maps.
    const mapped = /^\[::ffff:([0-9a-f]{1,4}):[0-9a-f]{1,4}\]$/.exec(h);
    if (mapped) {
      const high = parseInt(mapped[1]!, 16);
      return isPrivateIpv4(high >> 8, high & 0xff);
    }
    return /^\[(::1|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/.test(h);
  }
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(h);
  return m !== null && isPrivateIpv4(Number(m[1]), Number(m[2]));
}

/** Whether an IPv4 address with these first two octets is in a §11.3a private range. */
function isPrivateIpv4(a: number, b: number): boolean {
  return (
    a === 10 || a === 127 || a === 0 ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

/**
 * Canonical form of a relay URL, or undefined if it is not one this client will use.
 * `wss:` anywhere; `ws:` only to loopback, and only where `relayPolicy` allows it.
 */
export function normalizeRelayUrl(input: string): string | undefined {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    return undefined;
  }
  const local = LOOPBACK.has(u.hostname);
  if (local && !relayPolicy.loopback) return undefined;
  if (u.protocol !== 'wss:' && !(u.protocol === 'ws:' && local)) return undefined;
  if (u.username || u.password) return undefined;
  const path = u.pathname === '/' ? '' : u.pathname;
  return `${u.protocol}//${u.host}${path}${u.search}`;
}

/** Canonical origin (ASCII, so a non-ASCII host is shown as punycode per §9.1), or undefined. */
export function normalizeOrigin(input: string): string | undefined {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    return undefined;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
  // A name longer than DNS allows is not an origin; it is an attempt to fill the prompt.
  if (u.hostname.length > 253 || u.hostname.split('.').some((label) => label.length > 63)) return undefined;
  return u.origin === 'null' ? undefined : u.origin;
}

// Colons and slashes are legal in a fragment and left alone; every byte saved is a
// smaller, easier QR. Everything URLSearchParams treats as syntax stays escaped.
function enc(value: string): string {
  return encodeURIComponent(value).replace(/%3A/gi, ':').replace(/%2F/gi, '/');
}

/** Builds the link. `base` is the https address of the bounce page, without a fragment. */
export function buildUri(base: string, p: PairingParams): string {
  if (!PROFILE_ID.test(p.profile)) throw new Error('pairing link: bad profile identifier');
  if (p.relays.length < 1 || p.relays.length > MAX_RELAYS) throw new Error('pairing link: needs 1 to 4 relays');
  if (!isCodeCheck(p.check)) throw new Error('pairing link: bad check');
  if (!isToken(p.token)) throw new Error('pairing link: bad token');
  const parts = [`v=${p.v}`, `mode=${p.mode}`, `p=${p.profile}`, `npub=${npubEncode(p.pub)}`, `check=${p.check}`, `token=${p.token}`];
  for (const relay of p.relays) {
    const normal = normalizeRelayUrl(relay);
    if (!normal) throw new Error('pairing link: bad relay');
    parts.push(`relay=${enc(normal)}`);
  }
  if (p.origin !== undefined) {
    const origin = normalizeOrigin(p.origin);
    if (!origin) throw new Error('pairing link: bad origin');
    parts.push(`origin=${enc(origin)}`);
  }
  const hashAt = base.indexOf('#');
  return `${hashAt < 0 ? base : base.slice(0, hashAt)}#${parts.join('&')}`;
}

/** The scheme every implementation registers, by which a bounce page hands a code to an installed app (§11.2c). */
export const HANDOFF_SCHEME = 'qrst';

/** `<scheme>://<npub>?<parameters>`: the form of §11.2c and §12.3. */
const SCHEME_FORM = /^([a-z][a-z0-9+.-]*):\/\/(npub1[02-9ac-hj-np-z]+)\/?\?([^#]*)$/i;

/**
 * The same pairing URI in the `qrst:` handoff form (§11.2c). For handing to an app on
 * this device only: never shown as a QR, never offered for copying.
 */
export function buildHandoffUri(p: PairingParams): string {
  const fragment = buildUri('', p).slice(1);
  const npub = npubEncode(p.pub);
  const rest = fragment.split('&').filter((part) => part !== `npub=${npub}`);
  return `${HANDOFF_SCHEME}://${npub}?${rest.join('&')}`;
}

/** True for a pairing URI that arrived in the `qrst:` handoff form (§11.2c). */
export function isHandoff(text: string): boolean {
  const m = SCHEME_FORM.exec(text.trim());
  return m !== null && m[1]!.toLowerCase() === HANDOFF_SCHEME;
}

/**
 * The parameters of a pairing URI in whichever carrier it came: the https fragment
 * (§11.2), or `qrst:` (§11.2c). This client registers no profile scheme of its own
 * (§12.3), so any other scheme is not a pairing link here.
 */
function parameters(text: string): string | undefined {
  const m = SCHEME_FORM.exec(text);
  if (m) {
    const scheme = m[1]!.toLowerCase();
    return scheme === HANDOFF_SCHEME ? `npub=${m[2]!.toLowerCase()}&${m[3]}` : undefined;
  }
  return text.includes('#') ? text.slice(text.indexOf('#') + 1) : text;
}

/** True when a string plausibly carries pairing parameters, so the page can offer to act on it. */
export function looksLikePairing(text: string): boolean {
  const fragment = parameters(text.trim());
  return fragment !== undefined && /(^|&)npub=npub1/.test(fragment) && /(^|&)v=/.test(fragment);
}

/**
 * Parses a pairing link, its `qrst:` handoff form, a bare fragment, or the parameters alone.
 *
 * Rejects an unknown `v`, a missing `mode` and a missing `p` as §11.2 requires, and
 * verifies the bech32 checksum on the key, which is what catches a transcription error
 * in a pasted link (§12.1). Unknown parameters are ignored. A missing or unknown
 * `check` reads as `type`, the strictest: a link never buys leniency by leaving
 * something out.
 */
export function parseUri(input: string): PairingParams {
  const text = input.trim();
  if (!looksLikePairing(text)) throw new UriError('not-a-pairing-link');
  const q = new URLSearchParams(parameters(text)!);

  if (q.get('v') !== String(VERSION)) throw new UriError('unknown-version');
  const mode = q.get('mode');
  if (mode !== 'offer' && mode !== 'request') throw new UriError('missing-mode');
  const profile = q.get('p');
  if (profile === null || !PROFILE_ID.test(profile)) throw new UriError('missing-profile');

  let pub: string;
  try {
    pub = npubDecode(q.get('npub') ?? '');
  } catch {
    throw new UriError('bad-key');
  }

  const token = q.get('token');
  if (!isToken(token)) throw new UriError('bad-token');
  const rawCheck = q.get('check');
  const check: CodeCheck = isCodeCheck(rawCheck) ? rawCheck : 'type';

  const relays: string[] = [];
  for (const raw of q.getAll('relay')) {
    const relay = normalizeRelayUrl(raw);
    if (!relay) throw new UriError('bad-relay');
    if (!relays.includes(relay)) relays.push(relay);
  }
  if (relays.length === 0) throw new UriError('no-relays');
  relays.length = Math.min(relays.length, MAX_RELAYS);

  const params: PairingParams = { v: VERSION, mode, profile, pub, check, token, relays };
  const rawOrigin = q.get('origin');
  if (rawOrigin !== null) {
    const origin = normalizeOrigin(rawOrigin);
    if (!origin) throw new UriError('bad-origin');
    params.origin = origin;
  }
  return params;
}

/** The role a device takes when it scans a code of this mode. */
export function scannerRole(mode: Mode): Role {
  return mode === 'offer' ? 'sender' : 'receiver';
}

/** The mode of the code a device shows when it has this role. */
export function showingMode(role: Role): Mode {
  return role === 'receiver' ? 'offer' : 'request';
}
