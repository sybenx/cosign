// The server, end to end over public relays, without QRST: the phone mints a ticket,
// a site redeems it and signs, something destructive waits for the phone, the phone
// removes the site, and an undo puts a list back.
//
//   (servers running, fake phone paired)   node test/server.e2e.ts

import { readFileSync } from 'node:fs';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const steps = process.argv.slice(2);
const want = (s: string) => steps.length === 0 || steps.includes(s);

// Talk as the phone's control half.
let latestState: any = null;
const parts = new Parts(); // big state messages come in parts
const ctl = new Pool(phone.group.relays, e => {
  if (e.kind !== KIND_MEMBER) return;
  const m = parts.take(e.pubkey, openFrom(phone.sk, e));
  if (m?.type === 'state') latestState = m;
});
ctl.start([{ kinds: [KIND_MEMBER], '#p': [require_pk()] }]);
function require_pk() { return phone.group.members.find((m: any) => m.idx === phone.idx).pk; }
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const p = (n: number) => Array.from({ length: n }, (_, i) => ['p', bytesToHex(randomBytes(32)).replace(/^./, String(i % 10))]);

let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const time = async <T>(f: () => Promise<T>) => { const t = Date.now(); const v = await f(); return [v, Date.now() - t] as const; };

await sleep(2000);
const t = bytesToHex(randomBytes(16));
asPhone({ type: 'ticket', t, origin: 'demo.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);

const site = new SignerClient(newSession(phone.signer, phone.group.relays));
const [ack, ms0] = await time(() => site.connect(t));
check('redeem the ticket', ack === 'ack', `${ms0} ms`);
check('second redemption of the same ticket refused', await new SignerClient(newSession(phone.signer, phone.group.relays)).connect(t).then(() => false, () => true));
const pubkey = await site.getPublicKey();
check('get_public_key is the group key', pubkey === phone.group.groupX);

const follows30 = p(30);
if (want('sign')) {
  const [note, ms1] = await time(() => site.signEvent({ kind: 1, content: 'cosign v2 test', tags: [] }));
  check('note signs automatically', verifyEvent(note) && note.pubkey === pubkey, `${ms1} ms`);
  const [f30, ms2] = await time(() => site.signEvent({ kind: 3, content: '', tags: follows30 }));
  check('follow list of 30 signs automatically', verifyEvent(f30), `${ms2} ms`);
  const [f31] = await time(() => site.signEvent({ kind: 3, content: '', tags: [...follows30, ...p(1)] }));
  check('following one more signs automatically', verifyEvent(f31));
  const [f0, ms3] = await time(() => site.signEvent({ kind: 3, content: '', tags: [] }).catch(e => e));
  const approved = f0 && !(f0 instanceof Error) && verifyEvent(f0);
  check('emptying the follow list waits for the phone', approved || String(f0).includes('declined'), `${ms3} ms, ${approved ? 'approved' : String(f0)}`);

  if (want('undo') && approved) {
    asPhone({ type: 'state_req' });
    await sleep(2500);
    const change = latestState?.changes?.find((c: any) => c.id === f0.id);
    check('the phone sees the change', !!change, change?.text);
    asPhone({ type: 'undo', id: f0.id });
    let after: any;
    for (let i = 0; i < 6 && !after?.undone; i++) { // republishing can take a while on slow relays
      await sleep(2500);
      asPhone({ type: 'state_req' });
      await sleep(1000);
      after = latestState?.changes?.find((c: any) => c.id === f0.id);
    }
    check('undo puts the follow list back', !!after?.undone);
  }
}

if (want('ecdh')) {
  const { schnorr } = await import('@noble/curves/secp256k1.js');
  const nip44 = await import('nostr-tools/nip44');
  const third = randomBytes(32), thirdPk = bytesToHex(schnorr.getPublicKey(third));
  const ct = await site.nip44.encrypt(thirdPk, 'hello');
  check('nip44 through the servers', nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(third, pubkey)) === 'hello');
}

if (want('revoke')) {
  asPhone({ type: 'revoke', pk: (await import('nostr-tools/pure')).getPublicKey(Buffer.from(site.session.sk, 'hex')) });
  await sleep(3000);
  const refused = await site.signEvent({ kind: 1, content: 'after removal', tags: [] }).then(() => '', e => String(e.message));
  check('a removed site is refused', refused.includes('removed'), refused);
}

site.close();
console.log(failures ? `\n${failures} failed` : '\nall passed');
process.exit(failures ? 1 : 0);
