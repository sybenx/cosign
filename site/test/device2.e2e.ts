// Two devices, no server: §5.1's first preference and §5.5, through the member library.
//
// The fake phone makes a weighted key with two servers, two library devices join it, and then
// the phone and both servers are killed. What is left is two devices, 3 points each, which is
// 6 — and they sign and work out a shared secret with nobody else alive. Nothing was set up for
// it and nothing was asked: each device says it is awake, and the other prefers it.
//
// It also checks what a device co-signing for a device must refuse: a digest that isn't the
// event's, and a second answer to a request it has already answered.
//
//   node test/device2.e2e.ts      (sets up its own group in server/test-d2d/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent, getEventHash } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../../server/net.ts';
import { openDevice } from '../src/member/index.ts';
import { hostFor, type Kept } from './member-host.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-d2d-phone.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-d2d/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-d2d/']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('node', ['setup.ts', '--dir', 'test-d2d', '--port', '8787', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
const servers: ChildProcess[] = [];
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/d2d-${s}.log`, 'w');
  const k = spawn('node', ['server.ts', `test-d2d/${s}`], { cwd: serverDir, stdio: ['ignore', l, l] });
  servers.push(k); kids.push(k);
}
await sleep(3000);

const html = await (await fetch('http://localhost:8787/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const members = ph.group.members.filter((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };

// --- Two devices join -----------------------------------------------------------------------

async function joinOne(name: string) {
  const kept: Kept = { mailboxKey: bytesToHex(randomBytes(32)), shares: [], epoch: 0 };
  const ops = hostFor(kept);
  const device = await openDevice({ ops, relays: ph.group.relays, name, onStatus: t => console.log(`[${name}] ${t}`) });
  let code = '';
  const joined = device.join({ onCode: u => { code = u; } }).then(() => null, (e: Error) => e);
  await waitFor(() => code.startsWith('cosign:join?'), 10_000);
  const j = new URL(code.replace('cosign:', 'cosign://'));
  asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
  await sleep(1500);
  asPhone(members[0].pk, { type: 'add_device', id: hex(6), pk: j.searchParams.get('pk'), name, relays: j.searchParams.getAll('r'), lock: true });
  const err = await Promise.race([joined, sleep(60_000).then(() => new Error('nothing happened in a minute'))]);
  check(`${name} joins`, err === null, String((err as Error)?.message ?? ''));
  return { device, kept, ops };
}

const mac = await joinOne('Test Mac');
if (failures) done(1);
await sleep(2000);
const laptop = await joinOne('Test laptop');
if (failures) done(1);

// The member list reaches both through the servers; each then knows who the other is.
check('each device knows the other is in the account', await waitFor(
  () => mac.device.status().members.some(m => m.name === 'Test laptop') && laptop.device.status().members.some(m => m.name === 'Test Mac'), 30_000));
check('and hears it is awake', await waitFor(
  () => mac.device.status().awake.some(m => m.name === 'Test laptop') && laptop.device.status().awake.some(m => m.name === 'Test Mac'), 30_000));

// --- Everything else dies ---------------------------------------------------------------------

phone.k.kill();
for (const s of servers) s.kill();
await sleep(3000);
check('the phone and both servers are gone', phone.k.killed && servers.every(s => s.killed));

const signs = async (label: string, d = mac.device) => {
  const ev = await d.sign({ kind: 1, content: `${label} ${hex(4)}`, tags: [] }).catch(e => e);
  check(label, verifyEvent(ev) && ev.pubkey === ph.group.groupX, String(ev?.message ?? ''));
};
await signs('with no server alive, two devices sign');
await signs('and the other way round', laptop.device);

const sealed = await mac.device.encryptToSelf('a note with no server in it').catch(e => e);
check('they work out the account’s own key together', typeof sealed === 'string', String(sealed?.message ?? ''));
check('and read back what was sealed', typeof sealed === 'string' && await mac.device.decryptFromSelf(sealed) === 'a note with no server in it');

// --- What a co-signing device must refuse -----------------------------------------------------
//
// Asked by hand, as the Mac, with its own mailbox key: the library would never send these.

const laptopPk = pubOf(laptop.kept.mailboxKey);
const parts = new Parts();
const heard: any[] = [];
const spy = new Pool(ph.group.relays, e => { const m = parts.take(e.pubkey, openFrom(mac.kept.mailboxKey, e)); if (m) heard.push(m); });
spy.start([{ kinds: [KIND_MEMBER], '#p': [pubOf(mac.kept.mailboxKey)] }]);
await sleep(2000);
const askLaptop = (msg: object) => { for (const e of sealParts(mac.kept.mailboxKey, laptopPk, msg)) spy.publish(e); };
const answerTo = (id: string) => heard.find(m => m.id === id && m.type === 'sign_res');

const real = { kind: 1, content: 'what the Mac showed', tags: [] as string[][], created_at: Math.floor(Date.now() / 1000), pubkey: ph.group.groupX };
const other = { ...real, content: 'what it would rather have signed' };
const macIdxs: number[] = mac.kept.shares.map(s => s.idx);
const lapIdxs: number[] = laptop.kept.shares.map(s => s.idx);
// Stand-in commitments: every one of these requests is refused before any maths touches them.
const commitsOf = (idxs: number[]) => idxs.map(idx => ({ idx, D: '02' + '11'.repeat(32), E: '02' + '22'.repeat(32) }));

const forgedId = hex(6);
askLaptop({ type: 'sign_req', id: forgedId, event: real, msg: getEventHash(other as any), participants: [...macIdxs, ...lapIdxs].sort((a, b) => a - b), epoch: 0, commits: commitsOf(macIdxs), frost: 2 });
check('a digest that isn’t the event’s is refused', await waitFor(() => /not the one the message names/.test(answerTo(forgedId)?.reason ?? ''), 15_000), answerTo(forgedId)?.reason ?? 'no answer');

const staleId = hex(6);
askLaptop({ type: 'sign_req', id: staleId, event: { ...real, created_at: real.created_at - 300 }, msg: getEventHash({ ...real, created_at: real.created_at - 300 } as any), participants: [...macIdxs, ...lapIdxs].sort((a, b) => a - b), epoch: 0, commits: commitsOf(macIdxs), frost: 2 });
check('and one a relay replayed from five minutes ago', await waitFor(() => /too old/.test(answerTo(staleId)?.reason ?? ''), 15_000), answerTo(staleId)?.reason ?? 'no answer');

const aheadId = hex(6);
askLaptop({ type: 'sign_req', id: aheadId, event: real, msg: getEventHash(real as any), participants: [...macIdxs, ...lapIdxs].sort((a, b) => a - b), epoch: 7, commits: commitsOf(macIdxs), frost: 2 });
check('and a round from an epoch it isn’t in', await waitFor(() => /epoch/.test(answerTo(aheadId)?.reason ?? ''), 15_000), answerTo(aheadId)?.reason ?? 'no answer');

const twice = answerTo(forgedId);
askLaptop({ type: 'sign_req', id: forgedId, event: real, msg: getEventHash(real as any), participants: [...macIdxs, ...lapIdxs].sort((a, b) => a - b), epoch: 0, commits: commitsOf(macIdxs), frost: 2 });
await sleep(4000);
check('asked again under the same id, the same answer and no second partial', JSON.stringify(answerTo(forgedId)) === JSON.stringify(twice));

mac.device.close(); laptop.device.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
