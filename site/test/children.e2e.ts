// A connected site adding grants under itself (the browser extension, one per website):
// cosign_add_site, the phone's view, removing one, and removing the parent with all of them.
//
//   (servers running, fake phone paired)   node test/children.e2e.ts

import { readFileSync } from 'node:fs';
import { getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, openFrom, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
let latestState: any = null;
const ctl = new Pool(phone.group.relays, e => { const m = openFrom(phone.sk, e); if (m?.type === 'state') latestState = m; });
ctl.start([{ kinds: [KIND_MEMBER], '#p': [phone.group.members.find((m: any) => m.idx === phone.idx).pk] }]);
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const client = () => { const c = new SignerClient(newSession(phone.signer, phone.group.relays)); return { c, pk: getPublicKey(hexToBytes((c as any).session.sk)) }; };
const err = (p: Promise<unknown>) => p.then(() => '', (e: Error) => e.message);
const note = (c: SignerClient) => c.signEvent({ kind: 1, content: 'child test', tags: [] });

await sleep(2000);
const t = bytesToHex(randomBytes(16));
asPhone({ type: 'ticket', t, origin: 'Firefox on MacBook', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);
const ext = client();
await ext.c.connect(t);

const tube = client(), other = client();
check('the extension adds a website', await ext.c.call('cosign_add_site', [tube.pk, 'https://tube.syb.lol', 'Firefox on MacBook']) === 'ack');
check('adding it again is fine', await ext.c.call('cosign_add_site', [tube.pk, 'https://tube.syb.lol', 'Firefox on MacBook']) === 'ack');
check('the website signs with its own key', verifyEvent(await note(tube.c)));
check('a website can’t add others', (await err(tube.c.call('cosign_add_site', [client().pk, 'https://x.test', 'x']))).startsWith('not-allowed:'));
check('a key nobody connected is refused', (await err(note(client().c))).startsWith('not-connected:'));

asPhone({ type: 'state_req' });
await sleep(2500);
const listed = latestState?.sites.find((s: any) => s.pk === tube.pk);
check('your phone sees it under the website, via the extension', listed?.origin === 'https://tube.syb.lol' && listed?.parent === ext.pk && listed?.via === 'Firefox on MacBook');

asPhone({ type: 'revoke', pk: tube.pk });
await sleep(2500);
check('removing the website stops it', (await err(note(tube.c))).startsWith('revoked:'));
check('… and not the extension', verifyEvent(await note(ext.c)));
check('a removed website can’t be added back by the extension', (await err(ext.c.call('cosign_add_site', [tube.pk, 'https://tube.syb.lol', 'x']))).startsWith('revoked:'));

check('another website', await ext.c.call('cosign_add_site', [other.pk, 'https://other.test', 'Firefox on MacBook']) === 'ack' && verifyEvent(await note(other.c)));
asPhone({ type: 'revoke', pk: ext.pk });
await sleep(2500);
check('removing the extension stops it', (await err(note(ext.c))).startsWith('revoked:'));
check('… and every website it added', (await err(note(other.c))).startsWith('revoked:'));

for (const x of [ext, tube, other]) x.c.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
