// Swapping out a server that has gone (COSIGN.md §7.7): a key with three servers loses
// one, a fresh one is added in its place by repair, and the next periodic refresh leaves
// the gone one out. No server takes a device's word for it — each checks the silence
// against what it has heard itself — and the key signs throughout.
//
//   node test/swap.e2e.ts    (sets up its own key in server/test-swap/; a server counts as
//                             gone after 25 s of silence here, and the minimum age is 15 s)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-swap-phone.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const state = (s: string) => json(`${serverDir}test-swap/${s}/state.json`);
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-swap']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};
const log = (name: string) => { try { return readFileSync(`${serverDir}logs/${name}`, 'utf8'); } catch { return ''; } };
const AGE = { COSIGN_REFRESH_MIN_AGE: '15', COSIGN_PENDING_DROP: '600', COSIGN_DEAD_AFTER: '25' };
const start = (args: string[], name: string, env: Record<string, string> = {}) => {
  const l = openSync(`${serverDir}logs/${name}`, 'w');
  const k = spawn('node', args, { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, ...AGE, ...env } });
  kids.push(k);
  return k;
};
const codeOf = async (port: number) => (await (await fetch(`http://localhost:${port}/add-code`)).json()).uri as string;
const tokenOf = (uri: string) => new URL(uri.replace('cosign:', 'cosign://')).searchParams.get('t')!;

spawnSync('pkill', ['-f', 'server.ts.*test-swap']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('rm', ['-rf', serverDir + 'test-swap']);
mkdirSync(serverDir + 'logs', { recursive: true });

// The key's own two servers, and two more that take a code: one to add now and lose, one to come in its place.
spawnSync('node', ['setup.ts', '--dir', 'test-swap/own', '--port', '8744', '--weighted', '--force'], { cwd: serverDir });
for (const s of ['a', 'b']) start(['server.ts', `test-swap/own/${s}`], `swap-own-${s}.log`);
const homes: Record<string, ChildProcess> = {};
for (const [d, port] of [['c', 8752], ['d', 8754]] as const)
  homes[d] = start(['server.ts', '--root', `test-swap/${d}`], `swap-${d}.log`, { COSIGN_PORT: String(port) });
await sleep(4500);

const html = await (await fetch('http://localhost:8744/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('a key with two servers', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };
const members = () => json(phoneFile).group.members;
const serversOf = () => members().filter((m: any) => m.role === 'server' && !m.removed);

// A third server, so losing one still leaves the key with more than it needs.
const host = (d: string) => json(`${serverDir}test-swap/${d}/host.json`);
const c = host('c');
asPhone(phonePk, { type: 'test_add_server', host: c.pk, relays: c.relays, name: 'Server C', token: tokenOf(await codeOf(8752)) });
check('a third server joins it', await waitFor(() => serversOf().length === 3, 90_000), serversOf().map((m: any) => m.name).join(', '));
const cIdx = serversOf().find((m: any) => m.name === 'Server C')!.idx;

const t = hex(16);
for (const s of serversOf()) asPhone(s.pk, { type: 'ticket', t, origin: 'swap.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(ph.signer, ph.group.relays));
try { await site.connect(t); } catch (e) { check('a site connects', false, String(e)); done(1); }
const signs = async (label: string) => {
  const ev = await site.signEvent({ kind: 1, content: `${label} ${hex(4)}`, tags: [] }).catch(e => e);
  check(label, verifyEvent(ev), String(ev?.message ?? ''));
};
await signs('the key signs with three servers');

// --- Nobody is gone while they are all answering -------------------------------------------

asPhone(phonePk, { type: 'test_swap' });
check('while they all answer, none is called gone', await waitFor(() => phone.out().includes('SWAP: none of your servers is gone'), 30_000));

// A plan that leaves out a server that is plainly there is refused by the servers themselves.
const bIdx = serversOf().find((m: any) => m.name === 'Server B')!.idx;
asPhone(phonePk, { type: 'test_periodic', drop: [bIdx] });
await sleep(14_000);
check('a plan that leaves out a live server is refused', log('swap-own-a.log').includes("hasn't been silent here") && !state('own/a').pending, log('swap-own-a.log').split('\n').find(l => l.includes('refused'))?.slice(0, 80) ?? 'nothing refused');
check('the server it names refuses it too', log('swap-own-b.log').includes("hasn't been silent here"));
check('everyone is still on epoch 0', !state('own/a').epoch && !state('own/b').epoch);

// --- One goes, and is swapped out ----------------------------------------------------------

homes.c.kill();
await sleep(30_000); // longer than COSIGN_DEAD_AFTER, so the other two have seen the silence
const d = host('d');
asPhone(phonePk, { type: 'test_swap', host: d.pk, relays: d.relays, name: 'Server D', token: tokenOf(await codeOf(8754)) });
check('the one that went is found gone', await waitFor(() => phone.out().includes(`SWAP: gone ${cIdx}`), 40_000), phone.out().split('\n').filter(l => l.includes('SWAP:')).pop() ?? '');
check('a fresh server comes in its place', await waitFor(() => members().some((m: any) => m.name === 'Server D' && !m.removed), 90_000));
check('the key moves to the next epoch without the one that went', await waitFor(() => state('own/a').epoch === 1 && state('own/b').epoch === 1, 90_000),
  `a: ${state('own/a').epoch}, b: ${state('own/b').epoch}`);
check('the servers mark it out of the key', await waitFor(() => {
  const m = state('own/a').group.members.find((x: any) => x.idx === cIdx);
  return !!m?.removed;
}, 20_000));
check('the phone has it out too', members().find((m: any) => m.idx === cIdx)?.removed > 0);
const dDir = spawnSync('ls', [`${serverDir}test-swap/d/groups`]).stdout.toString().trim();
check('the fresh server holds a share of the new epoch', !!dDir && state(`d/groups/${dDir}`).epoch === 1, `epoch ${dDir ? state(`d/groups/${dDir}`).epoch : '—'}`);
await signs('and the key signs on, with the servers it has now');

// What the one that went holds is of the old epoch, and combines with nothing.
check('the one that went was left where it was', state(`c/groups/${spawnSync('ls', [`${serverDir}test-swap/c/groups`]).stdout.toString().trim()}`).epoch === undefined);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
