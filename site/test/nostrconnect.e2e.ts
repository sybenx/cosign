// nostrconnect, end to end, with nostr-tools' own NIP-46 client standing in for an
// ordinary site: it shows a nostrconnect:// code on a relay your servers don't use, the
// phone "scans" it, and the site signs, encrypts, waits for the phone on something
// destructive, and is removed.
//
//   (servers running, fake phone paired)   node test/nostrconnect.e2e.ts [relay]

import { readFileSync } from 'node:fs';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { BunkerSigner, createNostrConnectURI } from 'nostr-tools/nip46';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealTo, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const siteRelay = process.argv[2] ?? 'wss://relay.ditto.pub';

let latestState: any = null, connected: any = null;
const parts = new Parts(); // big state messages come in parts
const ctl = new Pool(phone.group.relays, e => {
  if (e.kind !== KIND_MEMBER) return;
  const m = parts.take(e.pubkey, openFrom(phone.sk, e));
  if (m?.type === 'state') latestState = m;
  if (m?.type === 'connected') connected = m;
});
ctl.start([{ kinds: [KIND_MEMBER], '#p': [phone.group.members.find((m: any) => m.idx === phone.idx).pk] }]);
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const time = async <T>(f: () => Promise<T>) => { const t = Date.now(); const v = await f(); return [v, Date.now() - t] as const; };
const within = <T>(ms: number, p: Promise<T>) => Promise.race([p, sleep(ms).then(() => { throw new Error(`no answer in ${ms / 1000} s`); })]);

await sleep(2000);

// The site: nothing of ours, just nostr-tools.
const clientSk = generateSecretKey();
const clientPk = getPublicKey(clientSk);
const uri = createNostrConnectURI({ clientPubkey: clientPk, relays: [siteRelay], secret: bytesToHex(randomBytes(8)), name: 'Plain NIP-46 site', url: 'https://nc.test' });
console.log(`site shows ${uri.slice(0, 60)}…`);
const signerP = BunkerSigner.fromURI(clientSk, uri, {}, 60_000);

// The phone scans it, and repeats itself until it hears back, as the app does.
const started = Date.now();
const nudge = setInterval(() => { if (!connected) asPhone({ type: 'nostrconnect', uri, origin: 'nc.test' }); }, 4000);
asPhone({ type: 'nostrconnect', uri, origin: 'nc.test' });
const signer = await signerP;
clearInterval(nudge);
check('site connects from its nostrconnect code', true, `${Date.now() - started} ms, relays now ${signer.bp.relays.join(' ')}`);
check('the phone hears it connected', await (async () => { for (let i = 0; i < 20 && !connected; i++) await sleep(250); return connected?.pk === clientPk; })());

const [pubkey, ms0] = await time(() => within(15_000, signer.getPublicKey()));
check('get_public_key is your key', pubkey === phone.group.groupX, `${ms0} ms`);

const [note, ms1] = await time(() => within(20_000, signer.signEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), content: 'cosign nostrconnect test', tags: [] })));
check('a note signs automatically', verifyEvent(note) && note.pubkey === pubkey, `${ms1} ms`);

const friend = generateSecretKey();
const [ct, ms2] = await time(() => within(20_000, signer.nip44Encrypt(getPublicKey(friend), 'hello friend')));
check('nip44_encrypt to someone else', nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(friend, pubkey)) === 'hello friend', `${ms2} ms`);
const back = nip44.v2.encrypt('hello you', nip44.v2.utils.getConversationKey(friend, pubkey));
check('nip44_decrypt from someone else', await within(20_000, signer.nip44Decrypt(getPublicKey(friend), back)) === 'hello you');

const follows = Array.from({ length: 12 }, () => ['p', bytesToHex(randomBytes(32))]);
await within(20_000, signer.signEvent({ kind: 3, created_at: Math.floor(Date.now() / 1000), content: '', tags: follows }));
const [emptied, ms3] = await time(() => within(70_000, signer.signEvent({ kind: 3, created_at: Math.floor(Date.now() / 1000) + 1, content: '', tags: [] })).catch(e => e));
check('emptying the follow list waits for the phone', verifyEvent(emptied as any) || String(emptied).includes('declined'), `${ms3} ms, ${verifyEvent(emptied as any) ? 'approved' : String(emptied)}`);

asPhone({ type: 'state_req' });
await sleep(2500);
check('the phone lists the site', !!latestState?.sites.some((s: any) => s.pk === clientPk && s.origin === 'nc.test'));

asPhone({ type: 'revoke', pk: clientPk });
await sleep(2500);
const after = await within(20_000, signer.signEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), content: 'should not sign', tags: [] })).catch(e => e);
check('removed on the phone: the site is refused', String(after).includes('removed'), String(after));

await signer.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
