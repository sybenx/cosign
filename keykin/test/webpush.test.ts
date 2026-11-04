// Core §8.2–§8.3: RFC 8291 aes128gcm with RFC 8291's own example, the fixed body length, the signed
// payload read back, and RFC 8292 VAPID as a gateway checks it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { p256 } from '@noble/curves/nist.js';
import { encryptPush, decryptPush, vapidHeader, checkVapid } from '../src/webpush.ts';
import { pushPayload, readPush, PUSH_BODY } from '../src/inbox.ts';
import { fromB64u, b64u, utf8ToBytes, bytesToHex, randomBytes } from '../src/bytes.ts';
import { newKey } from '../src/event.ts';

// RFC 8291 Appendix A.
const A = {
  plain: 'When I grow up, I want to be a watermelon',
  uaSk: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  uaPub: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  asSk: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  body: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
};

test('RFC 8291 Appendix A: our encryption gives the RFC\'s body, and our decryption reads it', () => {
  const body = encryptPush(utf8ToBytes(A.plain), { p256dh: A.uaPub, auth: A.auth }, { asSk: fromB64u(A.asSk), salt: fromB64u(A.salt) });
  assert.equal(b64u(body), A.body);
  assert.equal(new TextDecoder().decode(decryptPush(fromB64u(A.body), fromB64u(A.uaSk), fromB64u(A.auth))), A.plain);
});

test('§8.2: every encrypted body is the same 2,400 bytes; the device reads and checks the payload', () => {
  const host = newKey();
  const uaSk = p256.utils.randomSecretKey(), auth = randomBytes(16);
  const to = { p256dh: b64u(p256.getPublicKey(uaSk, false)), auth: b64u(auth) };
  const lens = new Set<number>();
  for (const wrap of [undefined, { small: true }, { big: 'z'.repeat(5000) }]) {
    const body = encryptPush(pushPayload(host, 'ask', bytesToHex(randomBytes(16)), wrap), to);
    lens.add(body.length);
    const p = readPush(decryptPush(body, uaSk, auth), new Set([host.pub]));
    assert.equal(p.srv, host.pub);
    if (wrap?.big) assert.equal(p.wrap, undefined, 'a wrap that does not fit is left out');
  }
  assert.deepEqual([...lens], [PUSH_BODY]);
  // Another device's auth secret, a flipped byte, an unknown server: refused.
  const body = encryptPush(pushPayload(host, 'sign', 'aa'.repeat(16)), to);
  assert.throws(() => decryptPush(body, uaSk, randomBytes(16)), /bad_push/);
  const flipped = body.slice(); flipped[200] ^= 1;
  assert.throws(() => decryptPush(flipped, uaSk, auth), /bad_push/);
  assert.throws(() => readPush(decryptPush(body, uaSk, auth), new Set([newKey().pub])), /unknown_server/);
  assert.throws(() => encryptPush(new Uint8Array(10), { p256dh: to.p256dh, auth: b64u(randomBytes(15)) }), /bad_push/);
});

test('RFC 8292 VAPID: a gateway checks the pinned key, origin, expiry and signature', () => {
  const sk = p256.utils.randomSecretKey(), pinned = bytesToHex(p256.getPublicKey(sk, false));
  const url = 'https://push.example.net/a/8f3a', now = 1_800_000_000;
  const h = vapidHeader(url, sk, now);
  assert.equal(checkVapid(h, url, pinned, now), null);
  assert.equal(checkVapid(h, 'https://push.example.net/other', pinned, now), null, 'same origin, another address');
  assert.equal(checkVapid(h, 'https://evil.example/a/8f3a', pinned, now), 'vapid_aud');
  assert.equal(checkVapid(h, url, bytesToHex(p256.getPublicKey(p256.utils.randomSecretKey(), false)), now), 'vapid_key', 'another server\'s key');
  assert.equal(checkVapid(h, url, pinned, now + 13 * 3600), 'vapid_exp');
  assert.throws(() => vapidHeader(url, sk, now, undefined, 25 * 3600), /24 hours/);
  // A token claiming more than 24 hours, signed properly, is still refused.
  const enc = (o: unknown) => b64u(utf8ToBytes(JSON.stringify(o)));
  const sign = (head: unknown, claims: unknown) => { const input = `${enc(head)}.${enc(claims)}`; return `vapid t=${input}.${b64u(p256.sign(utf8ToBytes(input), sk, { format: 'compact' }))}, k=${b64u(p256.getPublicKey(sk, false))}`; };
  assert.equal(checkVapid(sign({ typ: 'JWT', alg: 'ES256' }, { aud: 'https://push.example.net', exp: now + 25 * 3600 }), url, pinned, now), 'vapid_exp');
  assert.equal(checkVapid(sign({ typ: 'JWT', alg: 'none' }, { aud: 'https://push.example.net', exp: now + 60 }), url, pinned, now), 'vapid_alg');
  const t = h.split(' ')[1].split('.'); t[1] = enc({ aud: 'https://push.example.net', exp: now + 7200, sub: 'x' });
  assert.equal(checkVapid(`vapid ${t.join('.')} ${h.split(' ')[2]}`, url, pinned, now), 'vapid_sig', 'claims changed after signing');
  assert.equal(checkVapid('Bearer abc', url, pinned, now), 'vapid_header');
});

test('§8.1–§8.3 in the simulation: a device registers with every server; a hold notice reaches it as an ask push from each', async () => {
  const { create } = await import('../sim/account.ts');
  const { msg } = await import('../sim/nodes.ts');
  const acc = await create();
  assert.equal(await acc.A.registerPush(), 3);
  // One address per server and class, so nine, none shared.
  assert.equal(acc.A.pushKeys.size, 9);
  const vanish = { pubkey: acc.g, created_at: acc.bus.now, kind: 62, tags: [], content: '' };
  const { wireEvent } = await import('../src/event.ts');
  const n = await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, { ...msg('hold', acc.g, acc.epochId, 'member'), event: wireEvent(vanish) });
  assert.equal(n.kind, 'hold');
  const got = acc.A.readPushes();
  assert.deepEqual(got.map((p) => [p.cls, p.id, p.srv]), [['ask', n.wait, acc.servers[0].host.pub]]);
  assert.ok(acc.bus.pushes.every((p) => p.body.length === PUSH_BODY));
  // A gateway pinned to another server's VAPID key drops the push; so does the device for an unknown host.
  const [p] = acc.bus.pushes;
  const other = [...acc.A.pushKeys.values()].find((k) => k.vapid !== acc.servers[0].enrollR.vapid)!;
  assert.equal(checkVapid(p.authorization, p.url, other.vapid, acc.bus.now), 'vapid_key');
  // The newest set replaces the old; push_unregister removes them; a non-member cannot register.
  await acc.bus.send(acc.A.kp, acc.servers[0].kp.pub, msg('push_unregister', acc.g, acc.epochId, 'member', {}));
  assert.equal(acc.servers[0].pushReg.get(acc.A.kp.pub), null);
  const stranger = newKey();
  assert.equal((await acc.bus.send(stranger, acc.servers[0].kp.pub, msg('push_register', acc.g, acc.epochId, 'member', { addresses: [] }))).code, 'not_member');
});
