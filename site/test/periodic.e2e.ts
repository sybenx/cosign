// Silent periodic refresh (COSIGN.md §7.7), on a weighted key with two servers, a phone, a
// tablet and a paper backup. A refresh nobody commits stays pending and is dropped, with
// everyone still on the old epoch and signing; one committed to one server only reaches
// the other through the servers, and the tablet, which only followed, catches up; a site
// signs throughout; and one asked for too soon after the last is refused.
//
//   node test/periodic.e2e.ts      (sets up its own group in server/test-periodic/; the
//                                   minimum age is 15 s and pending is dropped after 10 s here)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, pubOf, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-periodic-phone.json', tabletFile = '/tmp/cosign-periodic-tablet.json', paperFile = '/tmp/cosign-periodic-paper.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-periodic/${s}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-periodic/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-periodic/']);
for (const f of [phoneFile, tabletFile, paperFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-periodic', '--port', '8784', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/periodic-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-periodic/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_REFRESH_MIN_AGE: '15', COSIGN_PENDING_DROP: '10', COSIGN_ADD_WAIT: '2' } }));
}
await sleep(3000);

// --- The key: a phone, a paper, a tablet, and a site ------------------------------------

const html = await (await fetch('http://localhost:8784/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile, PAPER_FILE: paperFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };

asPhone(phonePk, { type: 'test_backup' });
check('a paper backup', await waitFor(() => phone.out().includes('PAPER made'), 40_000));
const tablet = run(['test/fake-device.ts', 'Test tablet'], { DEVICE_STATE: tabletFile });
await waitFor(() => tablet.out().includes('JOIN '), 10_000);
const j = new URL(tablet.out().split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
await sleep(2500);
asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
await sleep(1500);
asPhone(servers[0].pk, { type: 'add_device', id: hex(6), pk: j.searchParams.get('pk'), name: 'Test tablet', relays: j.searchParams.getAll('r'), lock: true });
check('a tablet joins', await waitFor(() => tablet.out().includes('JOINED'), 40_000));

const t = hex(16);
for (const s of servers) asPhone(s.pk, { type: 'ticket', t, origin: 'periodic.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(ph.signer, ph.group.relays));
try { await site.connect(t); } catch (e) { check('a site connects', false, String(e)); done(1); }
const signs = async (label: string) => {
  const ev = await site.signEvent({ kind: 1, content: `${label} ${hex(4)}`, tags: [] }).catch(e => e);
  check(label, verifyEvent(ev), String(ev?.message ?? ''));
};
await signs('a site signs');

// --- Pending that nobody commits is dropped ---------------------------------------------

asPhone(phonePk, { type: 'test_periodic', commitTo: 'none' });
check('a periodic refresh waits as pending on both servers', await waitFor(() => state('a').pending?.epoch === 1 && state('b').pending?.epoch === 1, 40_000));
check('the phone checked it with both servers', await waitFor(() => phone.out().includes('checked epoch 1 with 2 of 2 servers'), 30_000));
check('until committed, everyone stays on epoch 0', !state('a').epoch && !state('b').epoch && !json(phoneFile).epoch);
await signs('and signing goes on with the current shares');
check('nobody commits: it is dropped', await waitFor(() => !state('a').pending && !state('b').pending, 40_000));
check('still epoch 0 everywhere', !state('a').epoch && !state('b').epoch);
// A device that only followed must not have moved either: one that applied a refresh its
// servers never committed would be alone on an epoch, unable to sign and unable to catch up.
check('the tablet, which followed it, stayed where everyone else is', !json(tabletFile).epoch, `tablet epoch ${json(tabletFile).epoch ?? 0}`);
check('and it kept the shares it signs with', await waitFor(() => json(tabletFile).shares?.length === 3, 5000));
await signs('a site still signs');

// --- Committed to one server only: the other learns from it, the tablet catches up -------

asPhone(phonePk, { type: 'test_periodic', commitTo: 'first' });
check('committed to the first server only, both move to epoch 1', await waitFor(() => state('a').epoch === 1 && state('b').epoch === 1 && !state('a').pending && !state('b').pending, 60_000));
check('the phone moves too', await waitFor(() => json(phoneFile).epoch === 1, 20_000));
check('the tablet, which only followed, moves too', await waitFor(() => json(tabletFile).epoch === 1, 30_000));
check('their shares changed; the key didn’t', json(phoneFile).group.groupX === ph.group.groupX && JSON.stringify(json(phoneFile).shares) !== JSON.stringify(ph.shares));
check('the paper’s parts for epoch 1 are kept, from its two dealers', (state('a').backup?.parts ?? []).filter((p: any) => p.epoch === 1).length === 2);
await signs('a site signs on the new epoch');

// --- Too soon after the last ---------------------------------------------------------------

asPhone(phonePk, { type: 'test_periodic', commitTo: 'all' });
await sleep(6000);
check('one asked for too soon after the last is refused', state('a').epoch === 1 && !state('a').pending && !state('b').pending);

// --- The tablet's new shares really sign (the phone gone) ----------------------------------

phone.k.kill();
await sleep(14_000);
await signs('without the phone, the tablet (3) and a server (1) sign on epoch 1');

site.close();
void pubOf;
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
