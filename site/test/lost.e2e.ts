// Report lost (COSIGN.md §7.2) and the refresh after it (§7.3), on a weighted key: a
// phone, a tablet and a laptop (3 shares each) and two servers. The laptop is away. The
// phone reports the tablet lost: from then on nobody takes part in a round with it, and
// the phone and a server refresh everyone's shares. The laptop, back later, picks up its
// part from the servers and signs in the new epoch; the tablet can't sign with anyone.
//
//   node test/lost.e2e.ts      (sets up its own group in server/test-lost/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-lost-phone.json', tabletFile = '/tmp/cosign-lost-tablet.json', laptopFile = '/tmp/cosign-lost-laptop.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-lost/${s}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-lost/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-lost/']);
for (const f of [phoneFile, tabletFile, laptopFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-lost', '--port', '8755', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) { const l = openSync(`${serverDir}logs/lost-${s}.log`, 'w'); kids.push(spawn('node', ['server.ts', `test-lost/${s}`], { cwd: serverDir, stdio: ['ignore', l, l] })); }
await sleep(3000);

const html = await (await fetch('http://localhost:8755/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('the phone and servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
let ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (pk: string, msg: object) => ctl.publish(sealTo(ph.sk, pk, msg));

/** A new device, vouched for by the phone. */
async function addDevice(name: string, file: string) {
  const d = run(['test/fake-device.ts', name], { DEVICE_STATE: file });
  await waitFor(() => d.out().includes('JOIN '), 10_000);
  const j = new URL(d.out().split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
  await sleep(2500);
  asPhone(ph.group.members.find((m: any) => m.idx === ph.idx).pk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
  await sleep(1500);
  asPhone(servers[0].pk, { type: 'add_device', id: bytesToHex(randomBytes(6)), pk: j.searchParams.get('pk'), name, relays: j.searchParams.getAll('r'), lock: true });
  await waitFor(() => d.out().includes('JOINED'), 40_000);
  return d;
}
const tablet = await addDevice('Test tablet', tabletFile);
let laptop = await addDevice('Test laptop', laptopFile);
await sleep(4000);
const tab = json(tabletFile), lap = json(laptopFile);
check('a tablet and a laptop join, 3 shares each', tab.shares.length === 3 && lap.shares.length === 3);

// The laptop goes away. The phone reports the tablet lost.
laptop.k.kill();
await sleep(1000);
ph = json(phoneFile);
const shareBefore = state('a').self.shares[0].secret;
asPhone(ph.group.members.find((m: any) => m.idx === ph.idx).pk, { type: 'test_report', idx: tab.idx });
check('the tablet is blocked at once, at both servers', await waitFor(() => state('a').group.members.find((m: any) => m.idx === tab.idx)?.removed && state('b').group.members.find((m: any) => m.idx === tab.idx)?.removed, 20_000));
check('the tablet is told', await waitFor(() => tablet.out().includes('REMOVED by'), 15_000));
const t0 = Date.now();
check('the phone and both servers move to epoch 1', await waitFor(() => json(phoneFile).epoch === 1 && state('a').epoch === 1 && state('b').epoch === 1, 60_000), `${Date.now() - t0} ms`);
check('their shares changed; the key didn’t', state('a').self.shares[0].secret !== shareBefore && state('a').group.groupX === ph.group.groupX);

// A site, signing with the phone in the new epoch.
const t = bytesToHex(randomBytes(16));
for (const s of servers) asPhone(s.pk, { type: 'ticket', t, origin: 'lost.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);
const site = new SignerClient(newSession(ph.signer, ph.group.relays));
await site.connect(t);
const n1 = await site.signEvent({ kind: 1, content: 'after the refresh', tags: [] }).catch(e => e);
check('the phone (3) and a server (1) sign in the new epoch', verifyEvent(n1), String(n1?.message ?? ''));

// The laptop comes back: its part waits on the servers.
laptop = run(['test/fake-device.ts', '--resume'], { DEVICE_STATE: laptopFile });
check('the laptop, back, gets its part from the servers and refreshes', await waitFor(() => json(laptopFile).epoch === 1, 60_000), laptop.out().split('\n').filter(l => /refresh|back/.test(l)).join(' | '));

// Without the phone: the laptop signs, the tablet can't.
phone.k.kill();
await sleep(13_000);
const n2 = await site.signEvent({ kind: 1, content: 'phone away, laptop here', tags: [] }).catch(e => e);
check('the laptop (3) and a server (1) sign', verifyEvent(n2), String(n2?.message ?? ''));
laptop.k.kill();
await sleep(13_000);
const n3 = await site.signEvent({ kind: 1, content: 'only the lost tablet left', tags: [] }).then(() => null, e => e as Error);
check('the lost tablet can’t sign with anyone', !!n3 && !tablet.out().includes('co-signed'), n3?.message);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
