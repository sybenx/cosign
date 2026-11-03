// Server profile module §4: enrol replies, the signed list, the pick.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeEvent } from 'nostr-tools/pure';
import { enrollReply, checkEnroll, deriveMemberSk, deriveVapidSk, acceptList, pickOrder, LIST_D, type ServerList } from '../src/serverprofile.ts';
import { newKey, pubOf } from '../src/event.ts';
import { sha, bytesToHex } from '../src/bytes.ts';
import { create, replaceServer } from '../sim/account.ts';

const code = (f: () => unknown) => { try { f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };
const now = 1_800_000_000;

test('enrol reply: per-seat keys from the enrol secret, host-signed, aged by the co-signer', () => {
  const host = newKey(), g = pubOf(sha('g')), secret = sha('enrol secret');
  const { reply } = enrollReply(host, secret, '2026-11', g, '11'.repeat(16), { https: 'https://s.test', relays: [], operator: host.pub, issued: now });
  const e = { key: reply.member_key, host: host.pub, vapid: reply.vapid, enroll: reply };
  assert.equal(checkEnroll(e, g, now), null);
  assert.equal(checkEnroll(e, g, now + 31 * 86400), 'enroll_expired');
  assert.equal(checkEnroll(e, g), null, 'repair helpers check only the signature, so a seat never becomes unfillable');
  assert.equal(checkEnroll({ ...e, key: newKey().pub }, g, now), 'enroll_mismatch');
  assert.equal(checkEnroll({ ...e, enroll: { ...reply, https: 'https://evil.test' } }, g, now), 'enroll_sig');
  // A second reply (new nonce) gives fresh keys: one host, seated again, never reuses a member key (I7).
  assert.notEqual(enrollReply(host, secret, '2026-11', g, '22'.repeat(16), { https: '', relays: [], operator: host.pub, issued: now }).reply.member_key, reply.member_key);
});

test('vector (for vectors/): member and VAPID key derivation', () => {
  const secret = sha('keykin-test/enrol-secret'), g = pubOf(sha('keykin-test/group')), nonce = bytesToHex(sha('nonce')).slice(0, 32);
  const m = bytesToHex(deriveMemberSk(secret, g, nonce)), v = bytesToHex(deriveVapidSk(secret, g, nonce));
  // Printed for the spec session to pin in gen_vectors.py (Server profile §4).
  console.log(JSON.stringify({ enroll_keys: { enrol_secret: bytesToHex(secret), g, nonce, member_sk: m, vapid_sk: v } }));
  assert.equal(m.length, 64); assert.equal(v.length, 64);
});

test('a seat change whose new server has no valid enrol reply is refused at the co-sign', async () => {
  const acc = await create();
  acc.bus.kill(acc.servers[2].kp.pub);
  const { ServerNode } = await import('../sim/nodes.ts');
  const Y = acc.bus.add(new ServerNode(acc.bus, 'noenroll')) as any;   // never enrolled
  const list: any[] = [{ seat: { seat: 'server:8', new: Y.entry(8), replaces: acc.servers[2].kp.pub } }, { redeal: { dealer: acc.A.kp.pub } }];
  await assert.rejects(acc.A.submit(list, acc.A.approveLock(list)), /no_enroll/);
  // A fresh, valid one goes through (the sim's replaceServer enrols first).
  const Y2 = await replaceServer(acc, acc.A, 8, (l) => acc.A.approveLock(l));
  assert.equal(acc.A.m!.seats.get('server:8')!.holder!.key, Y2.kp.pub);
});

test('the signed public list: pinned key, no rollback, key_next; the deterministic pick and its fall-through', () => {
  const listKey = newKey();
  const ops = [newKey().pub, newKey().pub];
  const servers = Array.from({ length: 6 }, (_, k) => ({ host: newKey().pub, operator: ops[k % 2], https: `https://l${k}.test`, relays: [], versions: [1] })).sort((a, b) => (a.host < b.host ? -1 : 1));
  const mk = (l: ServerList, sk = listKey.sk) => finalizeEvent({ kind: 30078, created_at: now, tags: [['d', LIST_D]], content: JSON.stringify(l) }, sk) as any;
  const v1 = acceptList(mk({ version: 1, issued: now, servers }), { key: listKey.pub, newest: 0 });
  assert.equal(v1.newest, 1);
  assert.equal(code(() => acceptList(mk({ version: 1, issued: now, servers }), { key: listKey.pub, newest: 1 })), 'rollback');
  assert.equal(code(() => acceptList(mk({ version: 2, issued: now, servers }, newKey().sk), { key: listKey.pub, newest: 1 })), 'not_pinned');
  const g = pubOf(sha('acct')), dead = newKey().pub;
  const a = pickOrder(v1.list, [4, 7, 8], 7, g, dead, { seatedHosts: new Set(), seatedOperators: new Set() });
  const b = pickOrder(v1.list, [4, 7, 8], 7, g, dead, { seatedHosts: new Set(), seatedOperators: new Set() });
  assert.deepEqual(a.map((x) => x.host), b.map((x) => x.host), 'deterministic');
  // Seat 7's slice is the list's 2nd, 5th, … servers; the pick is one of them.
  assert.ok([servers[1].host, servers[4].host].includes(a[0].host));
  // Never two seats on one operator while another exists.
  const c = pickOrder(v1.list, [4, 7, 8], 7, g, dead, { seatedHosts: new Set(), seatedOperators: new Set([a[0].operator]) });
  assert.notEqual(c[0].operator, a[0].operator);
  // A closing server is left out before slicing; a seated host is skipped.
  const closed = { ...v1.list, servers: v1.list.servers.map((x) => (x.host === a[0].host ? { ...x, closing: true } : x)) };
  assert.ok(!pickOrder(closed, [4, 7, 8], 7, g, dead, { seatedHosts: new Set(), seatedOperators: new Set() }).some((x) => x.host === a[0].host));
  assert.ok(!pickOrder(v1.list, [4, 7, 8], 7, g, dead, { seatedHosts: new Set([a[0].host]), seatedOperators: new Set() }).some((x) => x.host === a[0].host));
});
