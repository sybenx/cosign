// Who can join (server/join.ts, and the "Who can join" card on a server's page): the four
// modes, the npub proof, and the accounts list the operator sees — including stopping
// serving one.
//
// A two-server account, and three home servers: one that goes from "only me" to "people I
// follow", one that takes "people I invite", and one whose mode is fixed where it was
// started. A key the owner follows and invites, and a stranger's.
//
//   node test/join.e2e.ts     (sets everything up in server/test-join/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent, finalizeEvent } from 'nostr-tools/pure';
import { nip19 } from 'nostr-tools';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, pubOf, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-join-phone.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const waitAsync = async (pred: () => Promise<boolean>, ms: number) => { const until = Date.now() + ms; while (Date.now() < until) { if (await pred()) return true; await sleep(500); } return false; };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-join']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};
const start = (args: string[], log: string, env: Record<string, string> = {}) => {
  const l = openSync(`${serverDir}logs/${log}`, 'w');
  kids.push(spawn('node', args, { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, ...env } }));
};
const get = async (port: number, path: string) => await (await fetch(`http://localhost:${port}${path}`)).json() as any;
const post = async (port: number, path: string, body: object) =>
  await (await fetch(`http://localhost:${port}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json() as any;

spawnSync('pkill', ['-f', 'server.ts.*test-join']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('rm', ['-rf', serverDir + 'test-join']);
mkdirSync(serverDir + 'logs', { recursive: true });

// The owner of the home servers, the person they know, and a stranger.
const owner = bytesToHex(randomBytes(32)), known = bytesToHex(randomBytes(32)), stranger = bytesToHex(randomBytes(32));
const ownerPk = pubOf(owner), knownPk = pubOf(known), strangerPk = pubOf(stranger);

spawnSync('node', ['setup.ts', '--dir', 'test-join/own', '--port', '8764', '--weighted', '--force'], { cwd: serverDir });
for (const s of ['a', 'b']) start(['server.ts', `test-join/own/${s}`], `join-own-${s}.log`);
// Three home servers: two to set from their page, one fixed where it was started.
for (const [d, port] of [['follows', 8766], ['invite', 8768]] as const)
  start(['server.ts', '--root', `test-join/${d}`], `join-${d}.log`, { COSIGN_PORT: String(port), COSIGN_PROFILES_EVERY: '15000', COSIGN_PROFILE_AGE: '20', COSIGN_ADD_WAIT: '2' });
start(['server.ts', '--root', 'test-join/fixed'], 'join-fixed.log', { COSIGN_PORT: '8770', COSIGN_ENROLL: 'open' });
await sleep(4500);

// --- A fresh server takes nobody but its owner ------------------------------------------

const j1 = await get(8766, '/status');
check('a fresh server starts at "only me"', j1.join.enroll === 'owner' && j1.join.name === 'only me', j1.join?.name);
check('and announces itself as invite-only', j1.join.announced === 'invite');
check('one started with a mode of its own says so', (await get(8770, '/status')).join.pinned.enroll === true);
check('and its page can’t change it', !(await post(8770, '/settings', { enroll: 'owner' })).ok);
check('nor can junk be saved', !(await post(8766, '/settings', { enroll: 'everyone' })).ok);
check('nor something that isn’t an npub', !(await post(8766, '/settings', { owner: 'npub1nope' })).ok);
// Another site open in the same browser must not be able to change any of this.
const asForm = await fetch('http://localhost:8766/settings', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{"enroll":"open"}' });
check('a form from another site can’t change it', asForm.status === 403);
const asSite = await fetch('http://localhost:8766/settings', { method: 'POST', headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' }, body: '{"enroll":"open"}' });
check('nor a script on one', asSite.status === 403 && (await get(8766, '/status')).join.enroll === 'owner');

// --- The account ------------------------------------------------------------------------

const html = await (await fetch('http://localhost:8764/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('the phone and its two servers make an account', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };
const serversOf = () => json(phoneFile).group.members.filter((m: any) => m.role === 'server' && !m.removed);
const hostOf = (d: string) => json(`${serverDir}test-join/${d}/host.json`);
const groupsIn = (d: string) => { const r = spawnSync('ls', [`${serverDir}test-join/${d}/groups`]).stdout.toString().trim(); return r ? r.split('\n') : []; };

// "Only me": not even someone the owner knows gets in without a code from the page.
const h1 = hostOf('follows');
asPhone(phonePk, { type: 'test_add_server', host: h1.pk, relays: h1.relays, name: 'Follows server', proveWith: known });
await sleep(14_000);
check('"only me" turns away even someone it knows', phone.out().includes('ADD SERVER FAILED') && serversOf().length === 2, serversOf().length + ' servers');
check('and says to open its page for a code', /not-invited.*code/.test(phone.out()));

// --- "People I follow" --------------------------------------------------------------------

const list = finalizeEvent({ kind: 3, created_at: Math.floor(Date.now() / 1000), content: '', tags: [['p', knownPk]] }, hexToBytes(owner));
const pub = new Pool(h1.relays, () => {});
pub.start([]);
await sleep(1500);
pub.publish(list);
await sleep(2500);
const r1 = await post(8766, '/settings', { enroll: 'follows', owner: nip19.npubEncode(ownerPk) });
check('its page can set "people I follow"', r1.ok && r1.enroll === 'follows' && r1.owner === nip19.npubEncode(ownerPk), r1.reason ?? '');
check('the file keeps it', hostOf('follows').enroll === 'follows');

asPhone(phonePk, { type: 'test_add_server', host: h1.pk, relays: h1.relays, name: 'Follows server', proveWith: known });
check('someone the owner follows gets in', await waitFor(() => serversOf().length === 3, 90_000), serversOf().map((m: any) => m.name).join(', '));
check('it was asked for a proof first', phone.out().includes('wants to know whose account this is'));
check('the server holds one share of it', groupsIn('follows').length === 1);

// --- The accounts list, as whoever runs it sees it -------------------------------------------

const t1 = hex(16);
for (const s of serversOf()) asPhone(s.pk, { type: 'ticket', t: t1, origin: 'join.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(ph.signer, ph.group.relays));
try { await site.connect(t1); } catch (e) { check('a site connects', false, String(e)); done(1); }
const signs = async (label: string) => {
  const ev = await site.signEvent({ kind: 1, content: `${label} ${hex(4)}`, tags: [] }).catch(e => e);
  check(label, verifyEvent(ev), String(ev?.message ?? ''));
};
await signs('the account signs with the server it added');

const profile = await site.signEvent({ kind: 0, content: JSON.stringify({ name: 'A test account', picture: 'https://example.invalid/a.png' }), tags: [] });
pub.publish(profile);
const rowIn = async (port: number) => ((await get(port, '/status')).groups ?? [])[0];
check('the list shows the account’s name', await waitAsync(async () => (await rowIn(8766))?.name === 'A test account', 45_000), JSON.stringify(await rowIn(8766)));
const row = await rowIn(8766);
check('with its picture', row.picture === 'https://example.invalid/a.png', row.picture);
check('and how much else it has to sign with', row.devices === 1 && row.otherServers === 2, `${row.devices} devices, ${row.otherServers} other servers`);

// --- Stopping serving one ---------------------------------------------------------------

check('the page can stop serving it', (await post(8766, '/remove-account', { id: row.id })).ok);
check('the account is told', await waitFor(() => phone.out().includes('SERVER LEFT: Follows server'), 20_000));
check('its pieces are gone', await waitFor(() => groupsIn('follows').length === 0, 20_000));
check('and the list is empty again', (await get(8766, '/status')).groups.length === 0);
check('a made-up account can’t be removed', !(await post(8766, '/remove-account', { id: 'deadbeefdeadbeef' })).ok);
await signs('the account signs on with its other servers');

// --- "People I invite" --------------------------------------------------------------------

const h2 = hostOf('invite');
check('its page can set "people I invite"', (await post(8768, '/settings', { enroll: 'invite' })).ok);
asPhone(phonePk, { type: 'test_add_server', host: h2.pk, relays: h2.relays, name: 'Invite server' });
await sleep(14_000);
check('with no proof at all, it asks for one', /proof-needed/.test(phone.out()));
asPhone(phonePk, { type: 'test_add_server', host: h2.pk, relays: h2.relays, name: 'Invite server', proveWith: stranger });
await sleep(16_000);
check('a stranger who proves themselves is still turned away', groupsIn('invite').length === 0 && /not.*one of them/.test(phone.out()));
const r2 = await post(8768, '/settings', { invites: [nip19.npubEncode(knownPk), nip19.npubEncode(strangerPk)] });
check('npubs can be invited from its page', r2.ok && r2.invites.length === 2, (r2.invites ?? []).join(' '));
asPhone(phonePk, { type: 'test_add_server', host: h2.pk, relays: h2.relays, name: 'Invite server', proveWith: known });
check('an invited npub gets in', await waitFor(() => groupsIn('invite').length === 1, 90_000));
await signs('and the account signs with it too');

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
