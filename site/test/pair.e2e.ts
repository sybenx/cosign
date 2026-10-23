// QRST sign-in end to end over public relays: the site shows a code, a stand-in phone
// (the reference implementation, as Sender) answers it with a ticket at check `none`,
// the site confirms, redeems, and signs.
//
//   (servers running, fake phone paired)
//   node --experimental-transform-types test/pair.e2e.ts

import { readFileSync } from 'node:fs';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Store, Transfer, browserEnv } from '../vendor/qrst-web/index.ts';
import { parseUri } from '../vendor/qrst-core/index.ts';
import { signerTicket, type Ticket } from '../src/ticket.ts';
import { pair } from '../src/pair.ts';
import { Pool, sealTo } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const ctl = new Pool(phone.group.relays, () => {});
ctl.start([{ kinds: [28001], '#p': [phone.group.members.find((m: any) => m.idx === phone.idx).pk] }]);
await new Promise(r => setTimeout(r, 1500));

const mem = () => { const m = new Map<string, string>(); return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) }; };
const t0 = Date.now(), ms = () => `${((Date.now() - t0) / 1000).toFixed(1)} s`;

// The site.
let uri = '';
const site = pair({
  origin: 'https://demo.example',
  baseUrl: 'https://qrst.aaro.cc/',
  storage: mem(),
  ui: {
    code: u => { uri = u; console.log(`[site] showing code (${ms()})`); },
    confirm: (rendering, yes) => { console.log(`[site] phone sent: "${rendering}" — signing in (${ms()})`); yes(); },
    status: s => console.log(`[site] ${s}`),
  },
});

// The phone: wait for the code, mint a ticket, tell the servers, hand it over.
while (!uri) await new Promise(r => setTimeout(r, 200));
const params = parseUri(uri);
console.log(`[phone] scanned: profile ${params.profile}, check ${params.check}, origin ${params.origin}, ${params.relays.length} relay(s)`);
const ticket: Ticket = { v: 1, pubkey: phone.group.groupX, signer: phone.signer, relays: phone.group.relays, t: bytesToHex(randomBytes(16)), expires: Math.floor(Date.now() / 1000) + 900 };
for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, { type: 'ticket', t: ticket.t, origin: params.origin, expires: ticket.expires }));
const sender = Transfer.join({ profile: signerTicket, store: new Store(mem(), () => Math.floor(Date.now() / 1000)), env: browserEnv(), baseUrl: '', origin: '', check: 'none' }, params, { viaCamera: true }, ticket);
let released = false;
sender.onChange = () => {
  const v = sender.view();
  if (v.session.phase === 'release' && !released) { released = true; console.log(`[phone] "Connect ${params.origin}" tapped (${ms()})`); sender.release(); }
  if (v.stage === 'ended') console.log(`[phone] session ${v.session.outcome} (${ms()})`);
};

const client = await site.done;
console.log(`[site] signed in as ${client.session.pubkey?.slice(0, 12)}… (${ms()})`);
const note = await client.signEvent({ kind: 1, content: 'signed in with QRST', tags: [] });
console.log(`[site] note: ${verifyEvent(note) ? 'VALID' : 'INVALID'} (${ms()})`);
client.close(); sender.dispose();
process.exit(verifyEvent(note) ? 0 : 1);
