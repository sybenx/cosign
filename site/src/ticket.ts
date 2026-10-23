// QRST profile `signer-ticket`: what your phone hands a site so it can sign as you.
//
// A ticket, in the shape of QRST §5.2, not a secret of yours. The site redeems it with
// your servers for access of its own, which your phone can remove at any time. The
// phone's share never leaves it, and neither do the servers'.
//
//   Payload: base64 of JSON { v, pubkey, signer, relays, t, expires }
//     pubkey   who the site will sign as (x-only hex)
//     signer   the key your servers answer as
//     relays   where your servers listen
//     t        the one-time ticket (16 bytes hex), redeemed as the NIP-46 connect secret
//     expires  unix seconds; a ticket not redeemed by then is worthless
//
//   P4: well-formed, unexpired, and every relay a wss:// URL.
//   P5: who you'll sign as, and through which signer: §5.2 item 4 requires a site
//       with no signer configured to name it before redeeming.
//   Lowest check: `none`, for a code read by the phone's own camera. §5.2 item 5 says a
//       ticket profile SHOULD NOT permit `none`, because a stranger released to redeems
//       first. Here the phone answers only the code its camera read, and the ticket is
//       sealed to that code's burner, so a photograph of the code gets nothing; the
//       risk left is a substituted code, which needs the screen you're looking at. The
//       same reasoning lets frost-share use `none`. A pasted link needs `compare`.

import { base64 } from '@scure/base';
import { nip19 } from 'nostr-tools';
import type { Profile } from '../vendor/qrst-core/index.ts';

export interface Ticket { v: 1; pubkey: string; signer: string; relays: string[]; t: string; expires: number }

const HEX32 = /^[0-9a-f]{64}$/;
const short = (pk: string) => { const n = nip19.npubEncode(pk); return `${n.slice(0, 12)}…${n.slice(-6)}`; };

export const signerTicket: Profile<Ticket> = {
  id: 'signer-ticket',
  maxPayloadBytes: 2048,
  revocable: true,
  minCheck: 'none',

  encode(value) {
    const text = JSON.stringify(value);
    if (text.length > this.maxPayloadBytes) throw new Error('ticket too large');
    return base64.encode(new TextEncoder().encode(text));
  },

  check(content) {
    let v: any;
    try { v = JSON.parse(new TextDecoder().decode(base64.decode(content))); } catch { return { ok: false, reason: 'not a ticket' }; }
    if (v?.v !== 1 || !HEX32.test(v.pubkey) || !HEX32.test(v.signer) || !/^[0-9a-f]{32}$/.test(v.t)) return { ok: false, reason: 'malformed ticket' };
    if (!Array.isArray(v.relays) || v.relays.length < 1 || v.relays.length > 6 || !v.relays.every((r: unknown) => typeof r === 'string' && /^wss:\/\/[^\s]+$/.test(r)))
      return { ok: false, reason: 'bad relays' };
    if (typeof v.expires !== 'number' || v.expires < Date.now() / 1000) return { ok: false, reason: 'expired' };
    return { ok: true, value: v as Ticket };
  },

  render(v) {
    return `Sign in as ${short(v.pubkey)}, through your signer ${v.signer.slice(0, 8)}… on ${v.relays.map(r => r.replace('wss://', '')).join(', ')}`;
  },

  direction: {
    offer: 'Scan this with your phone to sign in. Your key stays where it is.',
    request: 'Your phone is offering this site access.',
  },
  release: {
    heading: 'Let this site sign as you?',
    body: 'It gets its own access, through your servers. Everyday things sign automatically; anything destructive comes to this phone first. You can remove it here any time; removing it stops future signing, not what it already signed.',
    confirm: (origin) => (origin ? `Connect ${origin}` : 'Connect this site'),
    decline: 'Don’t connect',
  },
  accept: { heading: 'Sign in?', confirm: 'Sign in', decline: 'Cancel' },
};
