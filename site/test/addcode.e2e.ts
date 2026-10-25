// Adding a server people can't find (COSIGN.md §9.6): a home server is unannounced and
// takes nobody by default, so it shows its own code on its page —
// `cosign:server?pk=<host key>&r=<relay>…&t=<code>`. A phone scans it, and the account
// gains that server by repair, as with any other. The code works once, and only there.
//
//   node test/addcode.e2e.ts     (sets up a two-server account in server/test-addcode/,
//                                 plus two invite-only hosts)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-addcode-phone.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-addcode']); process.exit(code); };
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
const codeOf = async (port: number) => (await (await fetch(`http://localhost:${port}/add-code`)).json()).uri as string;

spawnSync('pkill', ['-f', 'server.ts.*test-addcode']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('rm', ['-rf', serverDir + 'test-addcode']);
mkdirSync(serverDir + 'logs', { recursive: true });

// The account's own two servers, and two home servers that take nobody by default.
spawnSync('node', ['setup.ts', '--dir', 'test-addcode/own', '--port', '8794', '--weighted', '--force'], { cwd: serverDir });
for (const s of ['a', 'b']) start(['server.ts', `test-addcode/own/${s}`], `addcode-own-${s}.log`);
for (const [d, port] of [['home', 8796], ['other', 8798]] as const)
  start(['server.ts', '--root', `test-addcode/${d}`], `addcode-${d}.log`, { COSIGN_PORT: String(port), COSIGN_ENROLL: 'invite' });
await sleep(4000);

const html = await (await fetch('http://localhost:8794/')).text();
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

// --- The home server's code ----------------------------------------------------------

const home = JSON.parse(readFileSync(`${serverDir}test-addcode/home/host.json`, 'utf8'));
const code = await codeOf(8796);
check('its page shows a code for this server only', code.startsWith(`cosign:server?pk=${home.pk}&t=`), code.slice(0, 40) + '…');
const token = new URL(code.replace('cosign:', 'cosign://')).searchParams.get('t')!;
check('the same code while nobody has used it', (await codeOf(8796)) === code);
// What the phone will call it: the machine's name until its page says otherwise.
const named = (uri: string) => new URL(uri.replace('cosign:', 'cosign://')).searchParams.get('name') ?? '';
check('the code says what the server is called', named(code).length > 0, named(code));
await fetch('http://localhost:8796/settings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Home server' }) });
check('its page can change that', named(await codeOf(8796)) === 'Home server');

// Without it, a home server turns the phone away.
asPhone(phonePk, { type: 'test_add_server', host: home.pk, relays: home.relays, name: 'Home server' });
await sleep(12_000);
check('without the code, it is turned away', phone.out().includes('ADD SERVER FAILED') && serversOf().length === 2, serversOf().length + ' servers');

// With it: the account gains the server by repair.
asPhone(phonePk, { type: 'test_add_server', host: home.pk, relays: home.relays, name: 'Home server', token });
check('with the code, the account gains it', await waitFor(() => serversOf().length === 3, 90_000), serversOf().map((m: any) => m.name).join(', '));
check('the home server holds one share of it', await waitFor(() => {
  const dirs = spawnSync('ls', [`${serverDir}test-addcode/home/groups`]).stdout.toString().trim().split('\n').filter(Boolean);
  return dirs.length === 1 && json(`${serverDir}test-addcode/home/groups/${dirs[0]}/state.json`).group.groupX === ph.group.groupX;
}, 30_000));

// --- The code is spent, and was never good anywhere else ---------------------------------

check('the page now shows a different code', (await codeOf(8796)) !== code);
const other = JSON.parse(readFileSync(`${serverDir}test-addcode/other/host.json`, 'utf8'));
asPhone(phonePk, { type: 'test_add_server', host: other.pk, relays: other.relays, name: 'Another server', token });
await sleep(12_000);
const otherGroups = () => spawnSync('ls', [`${serverDir}test-addcode/other/groups`]).stdout.toString().trim();
check('the used code opens nothing else', serversOf().length === 3 && otherGroups() === '', otherGroups() || 'no accounts there');

// --- It signs ---------------------------------------------------------------------------

const added = serversOf().find((m: any) => m.name === 'Home server');
const t = hex(16);
for (const s of serversOf()) asPhone(s.pk, { type: 'ticket', t, origin: 'addcode.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(ph.signer, ph.group.relays));
try { await site.connect(t); } catch (e) { check('a site connects', false, String(e)); done(1); }
const note = await site.signEvent({ kind: 1, content: 'with the server I added', tags: [] }).catch(e => e);
check('the account signs as before', verifyEvent(note) && note.pubkey === ph.group.groupX, String(note?.message ?? ''));
check('the added server is a server of this account', !!added?.pk);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
