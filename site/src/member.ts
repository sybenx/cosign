// QRST profile `cosign-member`: a phone's place in a key, handed to it by the page that
// dealt the key (site/src/import.ts, moving a key out of a web app into Cosign).
//
//   Payload: base64 of JSON { v, group, idx, shares, signer, claim }
//     group    { groupX, npub, threshold, relays, members }, as the servers have it
//     idx      which member the phone becomes (a device, with several shares)
//     shares   [{ idx, secret }]: that member's shares (3 of a weighted key)
//     signer   the key the servers answer sites as
//     claim    the token the phone sends each server (pair_ack) to become that member
//
//   P4: well-formed; the member exists, isn't a server, and its share indices are the
//       ones sent. Whether each share lies on the key is checked by the app (curve math).
//   P5: whose key, and with which servers.
//   Lowest check: `type`. Like an nsec, these shares and a server are your key, and the
//       payload is shown on a screen anyone nearby can photograph (QRST §9.2).

import { base64 } from '@scure/base';
import { nip19 } from 'nostr-tools';
import type { Profile } from '../vendor/qrst-core/index.ts';

export interface MemberMove {
  v: 1;
  group: { groupX: string; npub: string; threshold: number; relays: string[]; members: { idx: number; name: string; role: string; pk: string | null; sharePub: string; shares?: { idx: number; sharePub: string }[] }[] };
  idx: number;
  shares: { idx: number; secret: string }[];
  signer: string;
  claim: string;
}

const HEX32 = /^[0-9a-f]{64}$/;
const short = (pk: string) => { const n = nip19.npubEncode(pk); return `${n.slice(0, 12)}…${n.slice(-6)}`; };

export const cosignMember: Profile<MemberMove> = {
  id: 'cosign-member',
  maxPayloadBytes: 8192,
  revocable: false,
  minCheck: 'type',

  encode(value) {
    const text = JSON.stringify(value);
    if (text.length > this.maxPayloadBytes) throw new Error('too large');
    return base64.encode(new TextEncoder().encode(text));
  },

  check(content) {
    let v: any;
    try { v = JSON.parse(new TextDecoder().decode(base64.decode(content))); } catch { return { ok: false, reason: 'not a key move' }; }
    const g = v?.group;
    if (v?.v !== 1 || !g || !HEX32.test(g.groupX) || !Number.isInteger(g.threshold) || !Array.isArray(g.members) || !Array.isArray(g.relays)
      || !HEX32.test(v.signer) || !/^[0-9a-f]{32}$/.test(v.claim) || !Array.isArray(v.shares)) return { ok: false, reason: 'malformed' };
    const me = g.members.find((m: any) => m.idx === v.idx);
    const idxs = me?.shares?.map((s: any) => s.idx) ?? (me ? [me.idx] : []);
    if (!me || me.role === 'server' || v.shares.length !== idxs.length || !v.shares.every((s: any) => idxs.includes(s.idx) && HEX32.test(s.secret)))
      return { ok: false, reason: 'the shares aren’t that member’s' };
    if (!g.relays.length || !g.relays.every((r: unknown) => typeof r === 'string' && /^wss:\/\/[^\s]+$/.test(r))) return { ok: false, reason: 'bad relays' };
    return { ok: true, value: v as MemberMove };
  },

  render(v) {
    const servers = v.group.members.filter(m => m.role === 'server').map(m => m.name);
    return `Keep ${short(v.group.groupX)} on this phone: it holds ${v.shares.length} of its shares, with ${servers.join(', ') || 'no server'}`;
  },

  direction: {
    offer: 'Scan this with the phone that will hold your key.',
    request: 'Scan this with your phone to move your account there.',
  },
  release: {
    heading: 'Move your key to your phone?',
    body: 'Your phone and your servers will hold it together, and this page won’t hold it any more. Type the five digits your phone shows.',
    confirm: () => 'Move it',
    decline: 'Not now',
  },
  accept: { heading: 'Keep this key?', confirm: 'Keep it', decline: 'Discard' },
};
