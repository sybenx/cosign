// Two attacks that today's servers allowed, each run for real and then refused.
//
// 1. A server writes the member list. One server of the account sends the others a list
//    containing a "device" whose key it holds; they used to treat it as one of the user's
//    devices, so it could report the real phone lost — instant and final. It is sent here
//    with a server's own member key, read from that server's state file, so it is exactly
//    what a breached server can do.
// 2. A paper backup was made on one device's word. Its 2 shares go to a key that device
//    chose, which with the device's own 3 is the threshold: the whole key, from one device.
//    It now waits, every device is told, and any of them can stop it.
//
//   node test/hardening.e2e.ts      (sets up its own group in server/test-hard/; the add
//                                    wait is 6 s here)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, pubOf, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-hard-phone.json', paperFile = '/tmp/cosign-hard-paper.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-hard/${s}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-hard']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts.*test-hard']);
for (const f of [phoneFile, paperFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-hard', '--port', '8788', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/hard-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-hard/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_ADD_WAIT: '6' } }));
}
await sleep(3000);

const html = await (await fetch('http://localhost:8788/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile, PAPER_FILE: paperFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const phoneIdx = ph.idx;
const phonePk = ph.group.members.find((m: any) => m.idx === phoneIdx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const send = (sk: string, to: string, msg: object) => { for (const e of sealParts(sk, to, msg)) ctl.publish(e); };
const asPhone = (to: string, msg: object) => send(ph.sk, to, msg);
const memberOf = (s: string, idx: number) => state(s).group.members.find((m: any) => m.idx === idx);

// --- 1. A server lists itself a device -------------------------------------------------------

// Server B's own member key, as a breached B would use it.
const bSk: string = JSON.parse(readFileSync(`${serverDir}test-hard/b/state.json`, 'utf8')).self.sk;
const fakeSk = hex(32), fakePk = pubOf(fakeSk);
const fakeIdx = Math.max(...state('a').group.members.flatMap((m: any) => (m.shares ?? [{ idx: m.idx }]).map((x: any) => x.idx))) + 1;
const fake = { idx: fakeIdx, name: 'Another phone', role: 'device', pk: fakePk, sharePub: '02' + 'ab'.repeat(32) };
send(bSk, servers[0].pk, { type: 'members', members: [...state('b').group.members.map((m: any) => ({ idx: m.idx, name: m.name, role: m.role, pk: m.pk, sharePub: m.sharePub, ...(m.shares ? { shares: m.shares } : {}) })), fake] });
check('a server can still tell the others about a member (that is how a device added elsewhere is learned)',
  await waitFor(() => !!memberOf('a', fakeIdx), 20_000));
check('but it is marked as that server’s word and nothing more', !!memberOf('a', fakeIdx)?.viaServer);

send(fakeSk, servers[0].pk, { type: 'remove_member', id: hex(6), idx: phoneIdx, lock: true });
await sleep(6000);
check('so it cannot report the real phone lost', !memberOf('a', phoneIdx)?.removed,
  memberOf('a', phoneIdx)?.removed ? 'the phone was removed' : '');
send(fakeSk, servers[0].pk, { type: 'take_out', id: hex(6), lock: true });
send(fakeSk, servers[0].pk, { type: 'add_device', id: hex(6), pk: pubOf(hex(32)), name: 'Theirs', lock: true });
await sleep(6000);
check('nor take the account out, nor add a device of its own',
  !state('a').guards.some((g: any) => g.kind === 'take_out') && state('a').group.members.length === ph.group.members.length + 1);

// That the real phone can still do those things is what part 2 shows: everything it sends
// there — the add, and the cancel — goes through the same gate.

// --- 2. A paper backup waits ------------------------------------------------------------------

asPhone(phonePk, { type: 'test_backup' });
check('a paper backup is held, not made', await waitFor(() => state('a').guards.some((g: any) => g.kind === 'add' && !g.done && !g.cancelled), 20_000));
check('no paper member yet', !state('a').group.members.some((m: any) => m.role === 'backup'));
const g = state('a').guards.find((x: any) => x.kind === 'add');
asPhone(servers[0].pk, { type: 'guard_cancel', id: g.id, lock: true });
check('a device stops it', await waitFor(() => !!state('a').guards.find((x: any) => x.id === g.id)?.cancelled, 15_000));
await sleep(8000);
check('and its pieces were never made', !state('a').group.members.some((m: any) => m.role === 'backup') && !phone.out().includes('PAPER made'));

asPhone(phonePk, { type: 'test_backup' });
check('asked again and left alone, it is made after the wait', await waitFor(() => phone.out().includes('PAPER made'), 40_000));
check('the paper holds 2, and nobody online holds its piece', (() => {
  const b = state('a').group.members.find((m: any) => m.role === 'backup');
  return !!b && (b.shares ?? []).length === 2;
})());

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
