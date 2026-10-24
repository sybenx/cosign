// Signing in with your phone: the site shows a QRST code, your phone answers it with
// a ticket, and the site redeems the ticket with your servers.
//
// This is all a site needs. It never sees a key of yours: what it keeps is its own
// key, which your servers recognise until your phone removes it.
//
// With `nostrconnect`, the same code also carries a nostrconnect:// sign-in (`nc` in the
// link's fragment), for people whose signer app isn't Cosign: their camera opens the
// link's page, which hands `nc` to their signer. Whichever answers first signs you in.
//
// No website is needed for any of it. The code's https address (`baseUrl`, by default
// cosign.aaro.cc) only matters to a phone's camera app; Cosign's own scanner reads the
// code whatever host it names. On the same phone, `ui.open` gets the code in QRST's
// neutral `qrst:` form, which opens any app that implements the profile directly.

import { generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure';
import { BunkerSigner, createNostrConnectURI, type BunkerPointer } from 'nostr-tools/nip46';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { Store, Transfer, browserEnv, type KeyValue } from '../vendor/qrst-web/index.ts';
import { parseUri, buildHandoffUri } from '../vendor/qrst-core/uri.ts';
import { signerTicket, type Ticket } from './ticket.ts';
import { SignerClient, newSession, type Session } from './client.ts';

/** What a signed-in site can do, whichever way it signed in. */
export interface Signer {
  getPublicKey(): Promise<string>;
  signEvent(t: { kind: number; content: string; tags: string[][]; created_at?: number }): Promise<Event>;
  nip44Encrypt(pubkey: string, text: string): Promise<string>;
  nip44Decrypt(pubkey: string, text: string): Promise<string>;
  /** Sign out for good: the grant goes, and so does its line on your phone. Closes too. */
  logout(): Promise<unknown>;
  close(): unknown;
}

/** Relays a site tries first when it shows a code. Your phone uses whichever pass. */
export const DEFAULT_RELAYS = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
/** Where a code points when a page names no other: only a phone's camera app ever opens it. */
export const DEFAULT_BOUNCE = 'https://cosign.aaro.cc/';
const SESSION_KEY = 'cosign.session';
const NC_KEY = 'cosign.nostrconnect';

/**
 * A code as a link for an app on this same device, with no website in between: QRST's
 * `qrst:` form (§11.2c), keeping any nostrconnect fallback. Never draw this as a QR.
 */
export function handoffLink(link: string): string {
  const [base, nc] = link.split('&nc=');
  return buildHandoffUri(parseUri(base)) + (nc ? `&nc=${nc}` : '');
}

/** One link for both: the Cosign sign-in, with a nostrconnect:// fallback in its fragment. */
export function signInLink(cosignUri: string, nostrconnectUri: string): string {
  return `${cosignUri}&nc=${encodeURIComponent(nostrconnectUri)}`;
}

export interface PairUi {
  /** Draw this as a QR code. Called again if it changes. */
  code(uri: string): void;
  /** For an "Open Cosign" button on this same device: the code as a `qrst:` link. */
  open?(link: string): void;
  /** Your phone sent a ticket: say whose it is and ask before using it (QRST §9.4). */
  confirm(rendering: string, yes: () => void, no: () => void): void;
  status(text: string): void;
}

export interface PairOptions {
  /** This page's origin. Your phone shows it, as a claim, when it asks you. */
  origin: string;
  /** Where the code points if a phone's camera app opens it (QRST §11.2a). Default DEFAULT_BOUNCE. */
  baseUrl?: string;
  storage?: KeyValue;
  relays?: string[];
  /** Also offer a nostrconnect sign-in in the same code, for any NIP-46 signer app. */
  nostrconnect?: { name: string; url?: string; image?: string };
  ui: PairUi;
}

/** Show a code, wait for your phone, redeem what it sends. Resolves signed in. */
export function pair(o: PairOptions): { done: Promise<Signer>; cancel(): void } {
  if (!o.nostrconnect) return pairCosign(o);
  // Both at once, under one code. The first to finish wins; the other is stopped.
  const sk = generateSecretKey();
  const nc = createNostrConnectURI({
    clientPubkey: getPublicKey(sk), relays: o.relays ?? DEFAULT_RELAYS, secret: bytesToHex(randomBytes(8)),
    name: o.nostrconnect.name, url: o.nostrconnect.url ?? o.origin, image: o.nostrconnect.image,
  });
  const abort = new AbortController();
  const cosign = pairCosign({ ...o, ui: { ...o.ui, code: uri => o.ui.code(signInLink(uri, nc)), open: o.ui.open && (l => o.ui.open!(`${l}&nc=${encodeURIComponent(nc)}`)) } });
  const other = BunkerSigner.fromURI(sk, nc, {}, abort.signal).then(signer => {
    o.storage?.setItem(NC_KEY, JSON.stringify({ sk: bytesToHex(sk), bp: signer.bp }));
    return signer as Signer;
  });
  const done = Promise.any([cosign.done, other]).then(
    signer => { cosign.cancel(); abort.abort(); return signer; },
    (e: AggregateError) => { throw e.errors[0]; },
  );
  return { done, cancel: () => { cosign.cancel(); abort.abort(); } };
}

function pairCosign(o: PairOptions): { done: Promise<SignerClient>; cancel(): void } {
  const store = new Store(o.storage, () => Math.floor(Date.now() / 1000), [], o.relays ?? DEFAULT_RELAYS);
  const t = Transfer.show({ profile: signerTicket, store, env: browserEnv(), baseUrl: o.baseUrl ?? DEFAULT_BOUNCE, origin: o.origin, check: 'none' }, 'receiver');
  let shown = '', asked = false;

  const ticket = new Promise<Ticket>((resolve, reject) => {
    t.onChange = () => {
      const v = t.view();
      if (v.stage === 'relays' && !shown) o.ui.status('Finding relays that work from here…');
      if (v.uri && v.uri !== shown) { shown = v.uri; o.ui.code(v.uri); o.ui.open?.(handoffLink(v.uri)); o.ui.status('Scan this with Cosign on your phone.'); }
      if (v.session.phase === 'accept' && v.session.rendering && !asked) {
        asked = true;
        o.ui.confirm(v.session.rendering, () => t.accept(), () => t.decline());
      }
      if (v.stage === 'ended') {
        if (v.value) resolve(v.value);
        else reject(new Error(v.session.outcome === 'second-responder'
          ? 'Two devices answered that code, so nothing was sent. Show a new code.'
          : `Not signed in (${v.session.outcome ?? 'ended'}).`));
      }
    };
  });

  const done = ticket.then(async tk => {
    o.ui.status('Signing in through your servers…');
    const session = newSession(tk.signer, tk.relays);
    const client = new SignerClient(session);
    // A refused ticket ends it: close the client, or it keeps its relays open for good.
    try {
      await client.connect(tk.t);
      session.pubkey = await client.getPublicKey();
    } catch (e) { client.close(); throw e; }
    o.storage?.setItem(SESSION_KEY, JSON.stringify(session));
    return client;
  });

  return { done, cancel: () => t.dispose() };
}

/** Pick up where a previous visit left off. Your phone may have removed it since. */
export function restore(storage: KeyValue): Signer | undefined {
  try {
    const s = JSON.parse(storage.getItem(SESSION_KEY) ?? 'null') as Session | null;
    if (s?.sk && s.signer) return new SignerClient(s);
    const n = JSON.parse(storage.getItem(NC_KEY) ?? 'null') as { sk: string; bp: BunkerPointer } | null;
    return n ? BunkerSigner.fromBunker(hexToBytes(n.sk), n.bp) : undefined;
  } catch { return undefined; }
}

export function forget(storage: KeyValue) { storage.removeItem(SESSION_KEY); storage.removeItem(NC_KEY); }
