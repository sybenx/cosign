// Events dated in the future: a list or profile dated ahead is refused outright, a
// note dated ahead (a scheduled post) waits for the phone, and a list dated ahead that's
// already out there is found and removed by its id.
//
//   (test servers made with `setup.ts --legacy --nsec <NSEC>`, fake phone paired)
//   NSEC=nsec1… node test/future.e2e.ts

import { readFileSync } from 'node:fs';
import { finalizeEvent, verifyEvent } from 'nostr-tools/pure';
import { decode } from 'nostr-tools/nip19';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const stateB = JSON.parse(readFileSync(new URL('../../server/test-data/b/state.json', import.meta.url), 'utf8'));
const groupSk = decode(process.env.NSEC!).data as Uint8Array;
const states = new Map<string, any>(); // the newest from each server: the phone shows them together
const parts = new Parts(); // big state messages come in parts
const ctl = new Pool(phone.group.relays, e => { const m = parts.take(e.pubkey, openFrom(phone.sk, e)); if (m?.type === 'state') states.set(e.pubkey, m); });
ctl.start([{ kinds: [KIND_MEMBER], '#p': [phone.group.members.find((m: any) => m.idx === phone.idx).pk] }]);
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const y2099 = Math.floor(Date.UTC(2099, 0, 1) / 1000);

await sleep(2000);
const t = bytesToHex(randomBytes(16));
asPhone({ type: 'ticket', t, origin: 'future.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);
const site = new SignerClient(newSession(phone.signer, phone.group.relays));
await site.connect(t);

const profile = await site.signEvent({ kind: 0, content: '{"name":"from the future"}', tags: [], created_at: y2099 }).catch(e => e);
check('a profile dated 2099 is refused', String(profile).includes('refused: Profile dated 2099-01-01'), String(profile));
const follows = await site.signEvent({ kind: 3, content: '', tags: [['p', bytesToHex(randomBytes(32))]], created_at: Math.floor(Date.now() / 1000) + 1800 }).catch(e => e);
check('a follow list dated 30 minutes ahead is refused', String(follows).includes('refused: Follow list dated'), String(follows));
const note = await site.signEvent({ kind: 1, content: 'scheduled for 2099', tags: [], created_at: y2099 }).catch(e => e);
check('a note dated 2099 asks the phone, then signs', verifyEvent(note) && note.created_at === y2099, verifyEvent(note) ? 'approved' : String(note));

// One that got out before Cosign: a follow list dated 2099, signed with the key itself.
const leaked = finalizeEvent({ kind: 3, content: '', tags: [['p', bytesToHex(randomBytes(32))]], created_at: y2099 }, groupSk);
for (const s of servers) if (s.idx !== stateB.self.idx) ctl.publish(sealTo(stateB.self.sk, s.pk, { type: 'sync', archive: [leaked] }));
await sleep(3000);
asPhone({ type: 'state_req' });
await sleep(2500);
const flagged = [...states.values()].flatMap(st => st.future ?? []).find((f: any) => f.id === leaked.id);
check('the server finds it and tells the phone', !!flagged, flagged?.text);

asPhone({ type: 'remove_future', id: leaked.id });
let gone = false;
for (let i = 0; i < 8 && !gone; i++) { await sleep(2500); asPhone({ type: 'state_req' }); await sleep(1000); gone = ![...states.values()].some(st => st.future?.some((f: any) => f.id === leaked.id)); }
check('one tap removes it (a deletion by its id)', gone);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
