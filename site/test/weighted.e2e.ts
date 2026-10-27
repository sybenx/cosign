// A weighted key, made with nobody ever holding it: a fresh group of two servers with no
// key, a phone scans A's code, and the three make one together (phone 3 shares, each
// server 1, any 4 sign). Then the phone and a server sign; the two servers alone can't.
//
//   node test/weighted.e2e.ts      (sets up its own group in server/test-weighted/)

import { readFileSync, openSync, mkdirSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-weighted-phone.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-weighted/${s}/state.json`, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kill = (pattern: string) => spawnSync('pkill', ['-f', pattern]);

kill('server.ts test-weighted/');
spawnSync('node', ['setup.ts', '--dir', 'test-weighted', '--port', '8751', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
const log = (n: string) => openSync(`${serverDir}logs/weighted-${n}.log`, 'w');
for (const s of ['a', 'b']) { const l = log(s); spawn('node', ['server.ts', `test-weighted/${s}`], { cwd: serverDir, stdio: ['ignore', l, l] }); }
check('set up with no key', state('a').group.groupX === null && state('a').self.shares.length === 0);

await sleep(3000);
const html = await (await fetch('http://localhost:8751/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const t0 = Date.now();
const phoneProc = spawn('node', ['test/fake-phone.ts', uri], { cwd: serverDir, env: { ...process.env, PHONE_STATE: phoneFile } });
let out = '';
phoneProc.stdout.on('data', d => { out += d; });
phoneProc.stderr.on('data', d => { out += d; });
while (!out.includes('made npub') && Date.now() - t0 < 60_000) await sleep(250);
check('the phone and both servers make a key', out.includes('made npub'), `${Date.now() - t0} ms`);
await sleep(6000);

const phone = JSON.parse(readFileSync(phoneFile, 'utf8'));
const [a, b] = [state('a'), state('b')];
check('all three have the same key', !!phone.group.groupX && a.group.groupX === phone.group.groupX && b.group.groupX === phone.group.groupX);
check('the phone holds 3 shares, each server 1', phone.shares.length === 3 && a.self.shares.length === 1 && b.self.shares.length === 1);
const secrets = [...phone.shares, ...a.self.shares, ...b.self.shares].map((s: any) => s.secret);
check('every share is different', new Set(secrets).size === 5);
check('nobody holds another’s share', !secrets.slice(0, 3).some(s => JSON.stringify(a).includes(s) || JSON.stringify(b).includes(s)) && !JSON.stringify(phone).includes(a.self.shares[0].secret));
check('A is done pairing; both servers know the phone', a.pairing === null && a.group.members[2].pk === phone.group.members[2].pk && b.group.members[2].pk === a.group.members[2].pk);

const servers = phone.group.members.filter((m: any) => m.role === 'server');
const ctl = new Pool(phone.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const t = bytesToHex(randomBytes(16));
for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, { type: 'ticket', t, origin: 'weighted.test', expires: Math.floor(Date.now() / 1000) + 900 }));
await sleep(1500);
const site = new SignerClient(newSession(phone.signer, phone.group.relays));
try { await site.connect(t); } catch (e) { check('a site connects', false, String(e)); kill('server.ts test-weighted/'); process.exit(1); }
check('a site gets the new key', (await site.getPublicKey()) === phone.group.groupX);
const ev = await site.signEvent({ kind: 1, content: 'made by nobody', tags: [] }).catch(e => e);
check('the phone (3) and a server (1) sign', verifyEvent(ev) && ev.pubkey === phone.group.groupX);

// A tablet joins: the phone vouches, and it gets 3 shares of its own by repair.
const dev = spawn('node', ['test/fake-device.ts', 'Test tablet'], { cwd: serverDir, env: { ...process.env } });
let devOut = '';
dev.stdout.on('data', d => { devOut += d; });
while (!devOut.includes('JOIN ')) await sleep(200);
const join = new URL(devOut.split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
await sleep(2500);
const t2 = Date.now();
// In the app your tap and your lock vouch for a new device; a test says so instead.
ctl.publish(sealTo(phone.sk, phone.group.members.find((m: any) => m.idx === phone.idx).pk, { type: 'test_vouch', pk: join.searchParams.get('pk') }));
await sleep(1500);
ctl.publish(sealTo(phone.sk, servers[0].pk, { type: 'add_device', id: `${Date.now()}w`, pk: join.searchParams.get('pk'), name: 'Test tablet', relays: join.searchParams.getAll('r'), lock: true }));
while (!devOut.includes('JOINED') && Date.now() - t2 < 40_000) await sleep(250);
check('the tablet gets 3 shares by repair', /JOINED .* with shares \d+, \d+, \d+/.test(devOut), `${Date.now() - t2} ms: ${devOut.split('\n').find(l => l.includes('JOINED')) ?? ''}`);
await sleep(2000);
const tablet = state('a').group.members.find((m: any) => m.pk === join.searchParams.get('pk'));
check('the servers list it with its 3 shares', tablet?.shares?.length === 3 && state('b').group.members.some((m: any) => m.pk === tablet.pk));

phoneProc.kill();
await sleep(12_000); // until the phone counts as gone
const ev2 = await site.signEvent({ kind: 1, content: 'from the tablet', tags: [] }).catch(e => e);
check('with the phone gone, the tablet (3) and a server (1) sign', verifyEvent(ev2) && ev2.pubkey === phone.group.groupX, String(ev2?.message ?? ''));

dev.kill();
await sleep(1000);
const t1 = Date.now();
const err = await site.signEvent({ kind: 1, content: 'servers alone', tags: [] }).then(() => null, e => e as Error);
check('the two servers alone (2 of 4) can’t', !!err, `${Date.now() - t1} ms: ${err?.message}`);

site.close();
kill('server.ts test-weighted/');
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
