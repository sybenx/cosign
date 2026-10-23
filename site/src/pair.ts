// Signing in with your phone: the site shows a QRST code, your phone answers it with
// a ticket, and the site redeems the ticket with your servers.
//
// This is all a site needs. It never sees a key of yours: what it keeps is its own
// key, which your servers recognise until your phone removes it.

import { Store, Transfer, browserEnv, type KeyValue } from '../vendor/qrst-web/index.ts';
import { signerTicket, type Ticket } from './ticket.ts';
import { SignerClient, newSession, type Session } from './client.ts';

/** Relays a site tries first when it shows a code. Your phone uses whichever pass. */
export const DEFAULT_RELAYS = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
const SESSION_KEY = 'cosign.session';

export interface PairUi {
  /** Draw this as a QR code (and offer it as a link). Called again if it changes. */
  code(uri: string): void;
  /** Your phone sent a ticket: say whose it is and ask before using it (QRST §9.4). */
  confirm(rendering: string, yes: () => void, no: () => void): void;
  status(text: string): void;
}

export interface PairOptions {
  /** This page's origin. Your phone shows it, as a claim, when it asks you. */
  origin: string;
  /** Where the code points if a phone's camera app opens it (QRST §11.2a). */
  baseUrl: string;
  storage?: KeyValue;
  relays?: string[];
  ui: PairUi;
}

/** Show a code, wait for your phone, redeem what it sends. Resolves signed in. */
export function pair(o: PairOptions): { done: Promise<SignerClient>; cancel(): void } {
  const store = new Store(o.storage, () => Math.floor(Date.now() / 1000), [], o.relays ?? DEFAULT_RELAYS);
  const t = Transfer.show({ profile: signerTicket, store, env: browserEnv(), baseUrl: o.baseUrl, origin: o.origin, check: 'none' }, 'receiver');
  let shown = '', asked = false;

  const ticket = new Promise<Ticket>((resolve, reject) => {
    t.onChange = () => {
      const v = t.view();
      if (v.stage === 'relays' && !shown) o.ui.status('Finding relays that work from here…');
      if (v.uri && v.uri !== shown) { shown = v.uri; o.ui.code(v.uri); o.ui.status('Scan this with Cosign on your phone.'); }
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
    await client.connect(tk.t);
    session.pubkey = await client.getPublicKey();
    o.storage?.setItem(SESSION_KEY, JSON.stringify(session));
    return client;
  });

  return { done, cancel: () => t.dispose() };
}

/** Pick up where a previous visit left off. Your phone may have removed it since. */
export function restore(storage: KeyValue): SignerClient | undefined {
  try {
    const s = JSON.parse(storage.getItem(SESSION_KEY) ?? 'null') as Session | null;
    return s?.sk && s.signer ? new SignerClient(s) : undefined;
  } catch { return undefined; }
}

export function forget(storage: KeyValue) { storage.removeItem(SESSION_KEY); }
