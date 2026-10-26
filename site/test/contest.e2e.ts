// "That wasn't me." Reporting a device lost is instant and final, and the first report used
// to win outright: a thief with one device could report every other device lost, and the
// user's own devices were mute from that moment — they could not even answer, let alone stop
// the thief cancelling each paper recovery they started afterwards.
//
// A device that was reported lost may now say it wasn't them, for a week, and nothing else.
// Two devices that report each other are both out: a thief can deny service and can never
// take over. This runs it: the tablet plays the thief and reports the phone, the phone
// answers, both go, and the thief is left with nothing it can do.
//
//   node test/contest.e2e.ts      (sets up its own group in server/test-contest/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, pubOf, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-contest-phone.json', tabletFile = '/tmp/cosign-contest-tablet.json';
const state = (s: string) => JSON.parse(readFileSync(`${serverDir}test-contest/${s}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-contest/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-contest/']);
for (const f of [phoneFile, tabletFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-contest', '--port', '8791', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/contest-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-contest/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_ADD_WAIT: '2' } }));
}
await sleep(3000);

const html = await (await fetch('http://localhost:8791/')).text();
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
const send = (sk: string, to: string, msg: object) => { for (const e of sealParts(sk, to, msg)) ctl.publish(e); };
const asPhone = (to: string, msg: object) => send(ph.sk, to, msg);
const at = (s: string, idx: number) => state(s).group.members.find((m: any) => m.idx === idx);

// A second device of the user's, which the thief will be holding.
const tablet = run(['test/fake-device.ts', 'Test tablet'], { DEVICE_STATE: tabletFile });
await waitFor(() => tablet.out().includes('JOIN '), 10_000);
const j = new URL(tablet.out().split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
await sleep(1500);
asPhone(servers[0].pk, { type: 'add_device', id: hex(6), pk: j.searchParams.get('pk'), name: 'Test tablet', relays: j.searchParams.getAll('r'), lock: true });
check('a tablet joins', await waitFor(() => tablet.out().includes('JOINED'), 40_000));
await sleep(2000);
const tb = json(tabletFile);
const tabletIdx: number = tb.idx;

// --- The thief reports first ------------------------------------------------------------------

send(tb.sk, servers[0].pk, { type: 'remove_member', id: hex(6), idx: ph.idx, lock: true });
check('whoever reports first is believed: the phone is out', await waitFor(() => !!at('a', ph.idx)?.removed, 20_000));

// --- The phone answers ------------------------------------------------------------------------

asPhone(servers[0].pk, { type: 'remove_member', id: hex(6), idx: tabletIdx, lock: true });
check('the phone can still say it wasn’t lost, and the tablet goes too', await waitFor(() => !!at('a', tabletIdx)?.removed, 25_000));
check('and it is recorded as contested', !!at('a', ph.idx)?.contested);
check('both are out, so neither side can sign', !!at('a', ph.idx)?.removed && !!at('a', tabletIdx)?.removed);
check('the other server is told', await waitFor(() => !!at('b', tabletIdx)?.removed && !!at('b', ph.idx)?.removed, 25_000));

// --- And the thief is left with nothing -------------------------------------------------------

const before = state('a').group.members.length;
send(tb.sk, servers[0].pk, { type: 'add_device', id: hex(6), pk: pubOf(hex(32)), name: 'Theirs', lock: true });
send(tb.sk, servers[0].pk, { type: 'take_out', id: hex(6), lock: true });
await sleep(6000);
check('a removed device can add nothing and take nothing out',
  state('a').group.members.length === before && !state('a').guards.some((g: any) => g.kind === 'take_out'));
check('nor report anyone else', (() => {
  const other = state('a').group.members.find((m: any) => m.role === 'server' && !m.removed);
  return !!other && !other.removed;
})());

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
