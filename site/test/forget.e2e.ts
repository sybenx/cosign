// What one server tells another about the archive, and what that is worth.
//
// Two things are checked here, both of them about the archive as it was before this branch.
//
// 1. **Nothing enters it that this account didn't sign.** The archive used to take whatever
//    a peer handed over — kind, an id and a sig being *present* was the whole test — and
//    everything built on it acts as if that had been checked: a change is judged against
//    the version it replaces, "dated in the future" is shown to devices and removed by its
//    id with one tap, and Undo signs the content of a saved copy again. A member that could
//    put its own events in there could have the account sign a deletion, or a post it wrote.
// 2. **Removing something dated ahead reaches the servers that weren't asked.** The message
//    for it was called 'forget', which is also what a device calls "remove my servers'
//    pieces", so the clause could never run and a server that was offline when the device
//    asked kept the entry for ever. It is `archive_forget` now.
//
// A legacy group, because the test needs a list dated 2099 that the account really signed:
// through the signer a list dated ahead is refused outright (COSIGN.md §5.3), so the key
// itself has to sign it, the way one that leaked before Cosign held it would have.
//
//   node test/forget.e2e.ts      (sets up its own group in server/test-forget/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { finalizeEvent } from 'nostr-tools/pure';
import { nsecEncode } from 'nostr-tools/nip19';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-forget-phone.json';
const raw = (s: string) => readFileSync(`${serverDir}test-forget/${s}/state.json`, 'utf8');
/** The archive is its own file for the Node host, not part of the state. */
const arch = (s: string) => { try { return readFileSync(`${serverDir}test-forget/${s}/archive.json`, 'utf8'); } catch { return ''; } };
const state = (s: string) => JSON.parse(raw(s));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-forget']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

// A throwaway key, split by the servers as the earlier 2-of-3 did, so this test holds it.
const groupSk = randomBytes(32);
spawnSync('pkill', ['-f', 'server.ts.*test-forget']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('node', ['setup.ts', '--legacy', '--nsec', nsecEncode(groupSk), '--dir', 'test-forget', '--port', '8778', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/forget-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-forget/${s}`], { cwd: serverDir, stdio: ['ignore', l, l] }));
}
await sleep(3000);

// Both servers, not just the one with the page: a server that could not bind its port used to
// leave this suite running against a dead B, which showed up as "the archive didn't sync"
// rather than as "B never started".
for (const [s, port] of [['a', 8778], ['b', 8779]] as const) {
  const up = await fetch(`http://localhost:${port}/status`).then(r => r.ok).catch(() => false);
  if (!up) { check(`server ${s} is listening on ${port}`, false, 'something else has the port, or it crashed — see logs/forget-' + s + '.log'); done(1); }
}
const html = await (await fetch('http://localhost:8778/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile });
check('the phone pairs with the key the servers hold', await waitFor(() => /paired|npub/.test(phone.out()), 60_000), phone.out().split('\n').slice(-2).join(' | ').slice(0, 100));
await sleep(5000);
const ph = json(phoneFile);
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const send = (sk: string, to: string, msg: object) => { for (const e of sealParts(sk, to, msg)) ctl.publish(e); };
const selfOf = (s: string) => state(s).self as { idx: number; sk: string };
const pkOf = (s: string) => servers.find((m: any) => m.idx === selfOf(s).idx).pk as string;
const y2099 = Math.floor(Date.UTC(2099, 0, 1) / 1000);

// --- 1. An event this account never signed -----------------------------------------------------

const forged = { id: hex(32), pubkey: ph.group.groupX, kind: 3, tags: [['p', hex(32)]], content: '', created_at: y2099, sig: hex(64) };
send(selfOf('a').sk, pkOf('b'), { type: 'sync', archive: [forged] });
await sleep(6000);
check('a server’s word doesn’t put an event in another’s archive', !arch('b').includes(forged.id),
  arch('b').includes(forged.id) ? 'it was kept' : '');

// --- 2. One that the key really signed, dated 2099 ---------------------------------------------

const leaked = finalizeEvent({ kind: 3, content: '', tags: [['p', hex(32)]], created_at: y2099 }, groupSk);
send(selfOf('a').sk, pkOf('b'), { type: 'sync', archive: [leaked] });
send(selfOf('b').sk, pkOf('a'), { type: 'sync', archive: [leaked] });
check('one the account signed is kept by both', await waitFor(() => arch('a').includes(leaked.id) && arch('b').includes(leaked.id), 25_000),
  `a:${arch('a').includes(leaked.id)} b:${arch('b').includes(leaked.id)}`);

// Asked of one server only — the app asks them all, which is why nothing caught this.
send(ph.sk, pkOf('a'), { type: 'remove_future', id: leaked.id });
check('the server that was asked removes it', await waitFor(() => !arch('a').includes(leaked.id), 40_000),
  phone.out().split('\n').slice(-2).join(' | ').slice(0, 100));
check('and tells the other, which never heard from the phone', await waitFor(() => !arch('b').includes(leaked.id), 30_000),
  arch('b').includes(leaked.id) ? 'the other server still has it' : '');

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
