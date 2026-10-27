// A server that misses a refresh must say so, not go on answering rounds with partials
// nobody can verify (~/igloo/cosign-live-findings.md item 13). Server B is killed, the
// tablet is reported lost so the key refreshes without it, and B is started again: it
// learns from the sync that it is a generation behind, says so, and refuses to take part.
// Meanwhile the phone and server A still sign, so the account is not stuck.
//
//   node test/stale.e2e.ts      (sets up its own group in server/test-stale/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealParts, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-stale-phone.json', tabletFile = '/tmp/cosign-stale-tablet.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-stale/${s}/state.json`, 'utf8'));
const log = (s: string) => { try { return readFileSync(`${serverDir}logs/stale-${s}.log`, 'utf8'); } catch { return ''; } };
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-stale/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};
const serve = (s: string) => {
  const l = openSync(`${serverDir}logs/stale-${s}.log`, 'a');
  const k = spawn('node', ['server.ts', `test-stale/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_ADD_WAIT: '2' } });
  kids.push(k);
  return k;
};

spawnSync('pkill', ['-f', 'server.ts test-stale/']);
for (const f of [phoneFile, tabletFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-stale', '--port', '8768', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) if (existsSync(`${serverDir}logs/stale-${s}.log`)) rmSync(`${serverDir}logs/stale-${s}.log`);
const srv: Record<string, ReturnType<typeof serve>> = { a: serve('a'), b: serve('b') };
await sleep(3000);

const html = await (await fetch('http://localhost:8768/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);

const ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };

// A tablet, so there is something to report lost and so a refresh has a reason to run.
const tablet = run(['test/fake-device.ts', 'Test tablet'], { DEVICE_STATE: tabletFile });
await waitFor(() => tablet.out().includes('JOIN '), 10_000);
const j = new URL(tablet.out().split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
await sleep(2500);
asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
await sleep(1500);
asPhone(servers[0].pk, { type: 'add_device', id: hex(6), pk: j.searchParams.get('pk'), name: 'Test tablet', relays: j.searchParams.getAll('r'), lock: true });
check('a tablet joins', await waitFor(() => tablet.out().includes('JOINED'), 40_000));
await sleep(3000);

// Server B goes away, and the key refreshes without it.
const epochB = state('b').epoch ?? 0;
srv.b.kill();
await sleep(2000);
asPhone(phonePk, { type: 'test_report', idx: json(tabletFile).idx });
check('the key refreshes while B is away', await waitFor(() => (state('a').epoch ?? 0) > epochB, 90_000), `A ${state('a').epoch}, B ${state('b').epoch}`);
tablet.k.kill();
check('B is left on the old epoch', (state('b').epoch ?? 0) === epochB);
check('B was told nothing about it while it was away', !state('b').behindAt);

// Long enough away that the refresh is out of reach. The subscription only ever looks 60
// seconds back (`net.ts:92`, `since: now() - 60`) and no mail is held for a server, so a
// server that returns later than that never sees the plan or its part. Inside that minute
// it catches up by itself, which is why the wait is here and not a shortcut.
await sleep(75_000);
srv.b = serve('b');
check('B says it is a generation behind', await waitFor(() => !!state('b').behindAt, 90_000), `epoch ${state('b').epoch} vs ${state('a').epoch}`);
check('and says it in words a person could read', /generation behind/.test(log('b')), log('b').split('\n').filter(l => /behind/.test(l)).slice(-1)[0] ?? '');

// It refuses to take part rather than answering with a partial that cannot verify.
const before = log('b').length;
asPhone(servers[1].pk, { type: 'sign_req', id: hex(6), event: { kind: 1, content: 'through the stale server', tags: [], created_at: Math.floor(Date.now() / 1000) } });
await sleep(5000);
check('B signs nothing after it knows', !/signed/.test(log('b').slice(before)), log('b').slice(before).split('\n').filter(Boolean).slice(-2).join(' / '));
const status = await (await fetch('http://localhost:8769/status')).json().catch(() => ({ activity: [] })) as any;
check('and the status page says so', (status.activity ?? []).some((a: any) => /generation behind/.test(a.text ?? '')),
  (status.activity ?? []).map((a: any) => a.text).slice(0, 2).join(' / '));

// And the account is not stuck: the phone and A are the threshold between them.
const t = hex(16);
asPhone(servers[0].pk, { type: 'ticket', t, origin: 'stale.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(2000);
const site = new SignerClient(newSession(ph.signer, ph.group.relays));
try { await site.connect(t); } catch (e) { check('a site still connects', false, String(e)); done(1); }
const ev = await site.signEvent({ kind: 1, content: 'signed without the stale server', tags: [] }).catch(e => e);
check('the phone and A still sign', verifyEvent(ev) && ev.pubkey === ph.group.groupX, String(ev?.message ?? ''));

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
