// The paper backup (COSIGN.md §8), with two servers, so the paper holds 2 shares: the
// phone makes it; a tablet is added and reported lost, so the key refreshes and the
// paper's part of that is kept for it; the phone is lost. A new phone reads the paper:
// its first try is cancelled by a device still around, the second waits out the
// recovery wait and the paper's shares are its own, and it signs with the server.
//
//   node test/paper.e2e.ts      (sets up its own group in server/test-paper/; the wait is a few seconds here)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-paper-phone.json', tabletFile = '/tmp/cosign-paper-tablet.json', newFile = '/tmp/cosign-paper-new.json', paperFile = '/tmp/cosign-paper.json';
const state = () => JSON.parse(readFileSync(`${serverDir}test-paper/a/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-paper']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts.*test-paper']);
for (const f of [phoneFile, tabletFile, newFile, paperFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-paper', '--port', '8757', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) { const l = openSync(`${serverDir}logs/paper-${s}.log`, 'w'); kids.push(spawn('node', ['server.ts', `test-paper/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_RECOVERY_WAIT: '12', COSIGN_ADD_WAIT: '2' } })); }
await sleep(3000);

const html = await (await fetch('http://localhost:8757/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
let phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile, PAPER_FILE: paperFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const server = ph.group.members.find((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const asPhone = (pk: string, msg: object) => ctl.publish(sealTo(ph.sk, pk, msg));

asPhone(phonePk, { type: 'test_backup' });
check('the phone makes a paper backup', await waitFor(() => phone.out().includes('PAPER made'), 40_000));
await sleep(2000);
const paperMember = state().group.members.find((m: any) => m.role === 'backup');
check('2 shares for the paper; nobody holds them', paperMember?.shares?.length === 2 && !JSON.stringify(state()).includes(json(paperFile).sk));

// A tablet, reported lost: the key refreshes, and the paper's part is kept for it.
const tablet = run(['test/fake-device.ts', 'Test tablet'], { DEVICE_STATE: tabletFile });
await waitFor(() => tablet.out().includes('JOIN '), 10_000);
const j = new URL(tablet.out().split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
await sleep(2500);
asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
await sleep(1500);
asPhone(server.pk, { type: 'add_device', id: bytesToHex(randomBytes(6)), pk: j.searchParams.get('pk'), name: 'Test tablet', relays: j.searchParams.getAll('r'), lock: true });
await waitFor(() => tablet.out().includes('JOINED'), 40_000);
await sleep(3000);
asPhone(phonePk, { type: 'test_report', idx: json(tabletFile).idx });
check('a refresh after the tablet is lost; the paper’s part is kept', await waitFor(() => state().epoch === 1 && state().backup?.parts?.length >= 2, 60_000), `${state().backup?.parts?.length} parts`);
tablet.k.kill();
// A refresh the phone started and that never ran leaves its part for the paper behind:
// it must not count (the restore would make wrong shares from it).
asPhone(server.pk, { type: 'backup_store', epoch: 2, content: 'a part of a refresh that never ran' });
await sleep(3000);

// A new phone reads the paper while the old one is still around: it cancels.
phone.k.kill();
await sleep(500);
phone = run(['test/fake-phone.ts'], { PHONE_STATE: phoneFile, CANCEL_RECOVERY: '1' });
await sleep(3000);
let fresh = run(['test/fake-phone.ts', '--restore', paperFile], { PHONE_STATE: newFile });
check('the new phone reads the paper, refresh and all', await waitFor(() => fresh.out().includes('paper read'), 30_000), fresh.out().split('\n').find(x => /paper read|PAPER FAILED/.test(x)));
check('a device still around cancels it', await waitFor(() => fresh.out().includes('CANCELLED by'), 30_000));
fresh.k.kill();

// The old phone is lost for real. The second try waits out the wait.
phone.k.kill();
await sleep(1000);
const t0 = Date.now();
fresh = run(['test/fake-phone.ts', '--restore', paperFile], { PHONE_STATE: newFile });
check('after the wait, the paper’s shares are the new phone’s', await waitFor(() => fresh.out().includes('RECOVERED'), 90_000), `${Date.now() - t0} ms`);
check('the server knows it as a device; no paper left', await waitFor(() => !state().group.members.some((m: any) => m.role === 'backup' && !m.removed) && !state().backup, 10_000));
await sleep(12_000); // pings

const np = json(newFile);
const t = bytesToHex(randomBytes(16));
ctl.publish(sealTo(np.sk, server.pk, { type: 'ticket', t, origin: 'paper.test', expires: Math.floor(Date.now() / 1000) + 900 }));
await sleep(1500);
const site = new SignerClient(newSession(np.signer, np.group.relays));
await site.connect(t);
const ev = await site.signEvent({ kind: 1, content: 'restored from paper', tags: [] }).catch(e => e);
check('the restored phone (3) and the server (1) sign as the same key', verifyEvent(ev) && ev.pubkey === ph.group.groupX,
  String(ev?.message ?? '') + ' | phone: ' + fresh.out().split('\n').filter(Boolean).slice(-4).join(' / '));

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
