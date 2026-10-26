// The paper backup with two servers, so the paper holds 2 shares (COSIGN.md §3): after
// the phone is lost and the paper restores a new one, those 2 and one server aren't
// enough to sign, so the new phone grows a device's full 3 by repair with both servers
// (three parties), the old paper shares are refreshed away, and it signs with either.
//
//   node test/paper2.e2e.ts     (sets up its own group in server/test-paper2/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-paper2-phone.json', tabletFile = '/tmp/cosign-paper2-tablet.json', newFile = '/tmp/cosign-paper2-new.json', paperFile = '/tmp/cosign-paper2.json';
const state = () => JSON.parse(readFileSync(`${serverDir}test-paper2/a/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-paper2/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-paper2/']);
for (const f of [phoneFile, newFile, paperFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-paper2', '--port', '8759', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) { const l = openSync(`${serverDir}logs/paper2-${s}.log`, 'w'); kids.push(spawn('node', ['server.ts', `test-paper2/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_RECOVERY_WAIT: '8', COSIGN_ADD_WAIT: '2' } })); }
await sleep(3000);

const html = await (await fetch('http://localhost:8759/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
let phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile, PAPER_FILE: paperFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
ctl.publish(sealTo(ph.sk, phonePk, { type: 'test_backup' }));
check('a paper backup of 2 shares, with two servers', await waitFor(() => phone.out().includes('PAPER made'), 40_000) && state().group.members.find((m: any) => m.role === 'backup')?.shares?.length === 2);

phone.k.kill();
await sleep(1000);
const fresh = run(['test/fake-phone.ts', '--restore', paperFile], { PHONE_STATE: newFile });
check('a new phone restores from it after the wait', await waitFor(() => fresh.out().includes('RECOVERED'), 90_000));
check('it grows a device’s 3 shares, by repair with both servers', await waitFor(() => fresh.out().includes('GREW'), 60_000), fresh.out().split('\n').find(x => x.includes('GREW')));
check('then refreshes, so the paper’s 2 are useless', await waitFor(() => json(newFile).epoch === 1 && state().epoch === 1, 60_000));
await sleep(12_000);

const np = json(newFile);
const t = bytesToHex(randomBytes(16));
for (const x of servers) ctl.publish(sealTo(np.sk, x.pk, { type: 'ticket', t, origin: 'paper2.test', expires: Math.floor(Date.now() / 1000) + 900 }));
await sleep(1500);
const site = new SignerClient(newSession(np.signer, np.group.relays));
await site.connect(t);
const ev = await site.signEvent({ kind: 1, content: 'restored from a 2-share paper', tags: [] }).catch(e => e);
check('the restored phone (3) and a server (1) sign as the same key', verifyEvent(ev) && ev.pubkey === ph.group.groupX, String(ev?.message ?? ''));
site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
