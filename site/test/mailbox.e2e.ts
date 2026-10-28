// A site's own mailbox, held only by your devices (COSIGN.md §6.1, core/bunker.ts).
//
// The phone opens the mailbox for a sign-in code; a plain NIP-46 client (written to the spec,
// as in nip46.e2e.ts) redeems the ticket and uses it. Everything a site asks — signatures and
// messages — is answered by the phone, which runs each round with one server under the site's
// grant. What this checks beyond nip46.e2e.ts:
//
//   - DMs work: nip44 and nip04, both ways, checked by the other person's own key.
//   - The servers never hold the mailbox's key, and what was in the requests never reaches
//     them: their files and logs are searched for the plaintext.
//   - They do know the mailbox's public key, which is how they wake the phone.
//   - nostrconnect:// sites get a mailbox of their own too.
//
//   node test/mailbox.e2e.ts      (sets up its own group in server/test-mailbox/)
//   COSIGN_TEST_RELAYS=ws://127.0.0.1:7777 COSIGN_RELAY_ALLOW=ws://127.0.0.1:7777 to run on a local relay.

import { readFileSync, openSync, mkdirSync, existsSync, rmSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, KIND_MEMBER, KIND_NIP46 } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-mailbox-phone.json';
const ticketFile = '/tmp/cosign-mailbox-ticket.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
const now = () => Math.floor(Date.now() / 1000);
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-mailbox']); process.exit(code); };

spawnSync('pkill', ['-f', 'server.ts.*test-mailbox']);
for (const f of [phoneFile, ticketFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-mailbox', '--port', '8796', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/mailbox-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-mailbox/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, DEBUG: '1' } }));
}
await sleep(3000);
const html = await (await fetch('http://localhost:8796/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phoneLog = openSync(`${serverDir}logs/mailbox-phone.log`, 'w');
kids.push(spawn('node', ['test/fake-phone.ts', uri], { cwd: serverDir, stdio: ['ignore', phoneLog, phoneLog], env: { ...process.env, PHONE_STATE: phoneFile, TICKET_FILE: ticketFile } }));
check('the phone and two servers make a key', await waitFor(() => existsSync(phoneFile) && !!json(phoneFile).group?.groupX, 60_000));
if (failures) done(1);
await sleep(5000);
const ph = json(phoneFile);
const myPk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const relays: string[] = ph.group.relays;

// The phone opens a mailbox for a sign-in code (scanning a site's code does this).
const ctl = new Pool(relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const toPhone = (m: object) => { for (const e of sealParts(ph.sk, myPk, m)) ctl.publish(e); };
toPhone({ type: 'test_ticket', origin: 'mailbox.test' });
check('the phone opens a mailbox for a sign-in code', await waitFor(() => existsSync(ticketFile), 15_000));
if (failures) done(1);
const ticket = json(ticketFile);
const signer: string = ticket.signer;
check('it is not the shared signer key', signer !== ph.signer);
await sleep(2500);

// A site, written to the spec.
let sk = randomBytes(32), pk = getPublicKey(sk);
const answers = new Map<string, any>();
const conv = (other: string) => nip44.v2.utils.getConversationKey(sk, other);
let target = signer;
const pool = new Pool(relays, (e: any) => {
  if (e.kind !== KIND_NIP46) return;
  for (const dec of [() => nip44.v2.decrypt(e.content, conv(e.pubkey)), () => nip04.decrypt(sk, e.pubkey, e.content)]) {
    try { const r = JSON.parse(dec()); if (r?.id) answers.set(r.id, { ...r, from: e.pubkey }); return; } catch { /* the other scheme */ }
  }
});
pool.start([{ kinds: [KIND_NIP46], '#p': [pk] }]);
await sleep(2000);
async function call(method: string, params: string[], scheme: 'nip44' | 'nip04' = 'nip44', ms = 20_000) {
  const id = hex(6);
  const body = JSON.stringify({ id, method, params });
  const content = scheme === 'nip44' ? nip44.v2.encrypt(body, conv(target)) : nip04.encrypt(sk, target, body);
  pool.publish(finalizeEvent({ kind: KIND_NIP46, created_at: now(), tags: [['p', target]], content }, sk));
  const until = Date.now() + ms;
  while (Date.now() < until) { const a = answers.get(id); if (a) return a; await sleep(200); }
  return { timeout: true } as any;
}
const errs = (a: any, code: string) => typeof a.error === 'string' && a.error.startsWith(code);
const signs = async (label: string, ev: any, ms = 20_000) => {
  const a = await call('sign_event', [JSON.stringify({ ...ev, created_at: now() })], 'nip44', ms);
  let s: any = null; try { s = JSON.parse(a.result); } catch { /* an error */ }
  check(`sign_event: ${label}`, !!s && verifyEvent(s) && s.pubkey === ph.group.groupX, a.error ?? (a.timeout ? 'no answer' : ''));
};

// --- Before connecting --------------------------------------------------------------------

check('connect with a wrong secret is refused', errs(await call('connect', [signer, 'deadbeef']), 'bad-ticket:'));
check('anything before connecting is refused', errs(await call('get_public_key', []), 'not-connected:'));

// --- Connected -----------------------------------------------------------------------------

check('connect with the ticket is acked', (await call('connect', [signer, ticket.t])).result === 'ack');
check('get_public_key is the account', (await call('get_public_key', [])).result === ph.group.groupX);
check('ping answers pong', (await call('ping', [])).result === 'pong');
await signs('a note', { kind: 1, content: 'from a site with its own mailbox', tags: [] });
await signs('a profile', { kind: 0, content: '{"name":"mailbox"}', tags: [] });
await signs('a deletion (after its undo window)', { kind: 5, content: '', tags: [['e', hex(32)]] }, 45_000);
const viaNip04 = await call('sign_event', [JSON.stringify({ kind: 1, content: 'nip04 request', tags: [], created_at: now() })], 'nip04');
check('a request in nip04 is answered', (() => { try { return verifyEvent(JSON.parse(viaNip04.result)); } catch { return false; } })(), viaNip04.error ?? '');

// --- Messages, checked by the other person's own key --------------------------------------

const friend = randomBytes(32), friendPk = getPublicKey(friend);
const friendKey = nip44.v2.utils.getConversationKey(friend, ph.group.groupX);
const secret44 = `nip44 secret ${hex(8)}`, secret04 = `nip04 secret ${hex(8)}`, incoming = `to you ${hex(8)}`;
const enc44 = await call('nip44_encrypt', [friendPk, secret44]);
check('nip44_encrypt: the friend can read it', (() => { try { return nip44.v2.decrypt(enc44.result, friendKey) === secret44; } catch { return false; } })(), enc44.error ?? '');
const dec44 = await call('nip44_decrypt', [friendPk, nip44.v2.encrypt(incoming, friendKey)]);
check('nip44_decrypt: reads what the friend wrote', dec44.result === incoming, dec44.error ?? '');
const enc04 = await call('nip04_encrypt', [friendPk, secret04]);
check('nip04_encrypt: the friend can read it', (() => { try { return nip04.decrypt(friend, ph.group.groupX, enc04.result) === secret04; } catch { return false; } })(), enc04.error ?? '');
const dec04 = await call('nip04_decrypt', [friendPk, nip04.encrypt(friend, ph.group.groupX, incoming)]);
check('nip04_decrypt: reads what the friend wrote', dec04.result === incoming, dec04.error ?? '');

// --- What the servers have, and don't -----------------------------------------------------

const ticketSk: string = json(phoneFile).siteKeys?.find((k: any) => k.pk === signer)?.sk ?? '';
const files = (dir: string): string[] => readdirSync(dir).flatMap(f => { const p = join(dir, f); return statSync(p).isDirectory() ? files(p) : [p]; });
const serverText = [...files(join(serverDir, 'test-mailbox')), ...['a', 'b'].map(s => `${serverDir}logs/mailbox-${s}.log`)].map(f => readFileSync(f, 'utf8')).join('\n');
check('the phone holds the mailbox key', /^[0-9a-f]{64}$/.test(ticketSk));
check('no server holds the mailbox key', !!ticketSk && !serverText.includes(ticketSk));
check('no server saw a message in plain text', ![secret44, secret04, incoming].some(x => serverText.includes(x)));
const stateA = json(join(serverDir, 'test-mailbox/a/state.json'));
const known = stateA.sites?.find((x: any) => x.pk === pk);
check('a server knows the site, and its mailbox by public key only', known?.signer === signer && Array.isArray(known?.holders) && known.holders.includes(ph.idx));
check('the servers saw the site write to the mailbox (and would wake the phone)', /a site wrote to a mailbox on your device/.test(serverText));

// --- Signing out ---------------------------------------------------------------------------

check('logout is acked', (await call('logout', [])).result === 'ack');
check('and then everything is refused', errs(await call('get_public_key', []), 'revoked:'));

// --- nostrconnect:// -------------------------------------------------------------------------

// A different site (a fresh key of its own), as a nostrconnect code always names.
const ncSecret = hex(8);
answers.clear();
sk = randomBytes(32); pk = getPublicKey(sk);
pool.setFilters([{ kinds: [KIND_NIP46], '#p': [pk] }]);
await sleep(1500);
const ncUri = `nostrconnect://${pk}?${relays.map(r => `relay=${encodeURIComponent(r)}`).join('&')}&secret=${ncSecret}&name=NC`;
toPhone({ type: 'test_nostrconnect', uri: ncUri, origin: 'nc.test' });
const hello = await waitFor(() => [...answers.values()].some(a => a.result === ncSecret), 20_000);
const ncSigner = [...answers.values()].find(a => a.result === ncSecret)?.from;
check('a nostrconnect site is answered from a mailbox of its own', hello && !!ncSigner && ncSigner !== signer && ncSigner !== ph.signer);
if (ncSigner) {
  target = ncSigner;
  await sleep(2000);
  await signs('a note, by nostrconnect', { kind: 1, content: 'nostrconnect, own mailbox', tags: [] });
  const e = await call('nip44_encrypt', [friendPk, secret44]);
  check('and messages work there too', (() => { try { return nip44.v2.decrypt(e.result, friendKey) === secret44; } catch { return false; } })(), e.error ?? '');
}

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
