// A minimal NIP-46 client: what a Nostr app does when you log in with a bunker link.
//
//   node test/client.ts '<bunker://...>' [kinds...]     e.g. 1 0

import { finalizeEvent, verifyEvent, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as F from '../frost.ts';
import { Pool, KIND_NIP46 } from '../net.ts';

const uri = new URL(process.argv[2].replace('bunker://', 'https://'));
const bunkerPk = uri.hostname, secret = uri.searchParams.get('secret')!, relays = uri.searchParams.getAll('relay');
const kinds = process.argv.slice(3).map(Number);
const sk = process.env.CLIENT_SK ?? F.bytesToHex(F.randomBytes(32));
const ck = nip44.v2.utils.getConversationKey(F.hexToBytes(sk), bunkerPk);

const waiting = new Map<string, (r: any) => void>();
const pool = new Pool(relays, (e: Event) => {
  if (e.kind !== KIND_NIP46 || e.pubkey !== bunkerPk) return;
  const r = JSON.parse(nip44.v2.decrypt(e.content, ck));
  waiting.get(r.id)?.(r); waiting.delete(r.id);
});
const me = schnorr.getPublicKey(F.hexToBytes(sk));
pool.start([{ kinds: [KIND_NIP46], '#p': [F.bytesToHex(me)] }]);

function call(method: string, params: string[], ms = 70_000): Promise<any> {
  const id = F.bytesToHex(F.randomBytes(6));
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${method}: timeout`)), ms);
    waiting.set(id, r => { clearTimeout(t); r.error ? reject(new Error(`${method}: ${r.error}`)) : resolve(r.result); });
    pool.publish(finalizeEvent({ kind: KIND_NIP46, created_at: Math.floor(Date.now() / 1000), tags: [['p', bunkerPk]],
      content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), ck) }, F.hexToBytes(sk)));
  });
}

await new Promise(r => setTimeout(r, 2000));
const t0 = Date.now();
const ms = () => `${Date.now() - t0}ms`;
let failed = 0;
try {
  console.log('connect:', await call('connect', [bunkerPk, secret]), ms());
  const pub = await call('get_public_key', []);
  console.log('pubkey:', pub, ms());
  for (const kind of kinds) {
    const t = Date.now();
    try {
      const signed = JSON.parse(await call('sign_event', [JSON.stringify({ kind, content: `cosign test ${kind} ${new Date().toISOString()}`, tags: [], created_at: Math.floor(Date.now() / 1000) })]));
      const good = verifyEvent(signed) && signed.pubkey === pub;
      console.log(`sign kind ${kind}: ${good ? 'VALID' : 'INVALID'} (${Date.now() - t}ms)`);
      if (!good) failed++;
    } catch (e: any) { console.log(`sign kind ${kind}: refused — ${e.message} (${Date.now() - t}ms)`); failed++; }
  }
  if (process.env.ECDH) {
    // Round-trip NIP-44 through a third party, to prove the group's ECDH is right.
    const third = F.randomBytes(32);
    const thirdPk = F.bytesToHex(schnorr.getPublicKey(third));
    const ct = await call('nip44_encrypt', [thirdPk, 'hello from the group']);
    const pt = nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(third, pub));
    console.log(`nip44 to a third party: ${pt === 'hello from the group' ? 'OK' : 'WRONG'}`, ms());
    const back = nip44.v2.encrypt('hello back', nip44.v2.utils.getConversationKey(third, pub));
    console.log(`nip44 decrypt: ${(await call('nip44_decrypt', [thirdPk, back])) === 'hello back' ? 'OK' : 'WRONG'}`, ms());
  }
} catch (e: any) { console.log('ERROR', e.message); failed++; }
process.exit(failed ? 1 : 0);
