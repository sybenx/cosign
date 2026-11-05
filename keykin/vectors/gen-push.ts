// Web Push vectors (core §8.2–§8.3), for every port: a server's signed, padded payload encrypted to a
// device's address (RFC 8291 aes128gcm, fixed sender key and salt), and tampered bodies a device refuses.
// Run: node vectors/gen-push.ts > vectors/push.json
import { p256 } from '@noble/curves/nist.js';
import { encryptPush } from '../src/webpush.ts';
import { pushPayload } from '../src/inbox.ts';
import { bytesToHex, hexToBytes, b64u } from '../src/bytes.ts';
import { pubOf } from '../src/event.ts';

const uaSk = hexToBytes('21'.repeat(32)), auth = hexToBytes('0f'.repeat(16));
const asSk = hexToBytes('32'.repeat(32)), salt = hexToBytes('a5'.repeat(16));
const hostSk = hexToBytes('43'.repeat(32));
const host = { sk: hostSk, pub: pubOf(hostSk) };
const to = { p256dh: b64u(p256.getPublicKey(uaSk, false)), auth: b64u(auth) };
const plain = pushPayload(host, 'ask', 'ab'.repeat(16));
const body = encryptPush(plain, to, { asSk, salt });
const flip = (b: Uint8Array, k: number) => { const c = b.slice(); c[k] ^= 1; return bytesToHex(c); };
console.log(JSON.stringify({
  note: 'body = RFC 8291 aes128gcm of plain to (ua_sk, auth); plain is the server-signed payload padded with spaces. Refused bodies must not decrypt.',
  ua_sk: bytesToHex(uaSk), auth: bytesToHex(auth), p256dh: to.p256dh, host_key: host.pub,
  plain: bytesToHex(plain), body: bytesToHex(body),
  refused: [flip(body, 0), flip(body, 100), flip(body, body.length - 1), bytesToHex(body.slice(0, 90))],
}, null, 1));
