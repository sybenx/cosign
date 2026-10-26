// Guarded actions (COSIGN.md §7.2), on a weighted key with two servers: a phone, a tablet
// and a paper backup. Taking the account out through the server (after a wait every
// device hears of), stopping it, taking it out with the paper (announced first, the
// server's answer bound to the request), reporting a device lost (final), and removing the
// server's pieces: stopped at once, cancelled, then deleted for real after the wait. And
// what a paper or a removed device can get from a server: nothing beyond its role (no
// piece of a decryption, no signature).
//
//   node test/guards.e2e.ts      (sets up its own group in server/test-guards/; the wait is 6 s here)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createRequire } from 'node:module';
import { getPublicKey } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const W = createRequire(import.meta.url)('../../server/frost-wasm/cosign_frost.js');
const phoneFile = '/tmp/cosign-guards-phone.json', tabletFile = '/tmp/cosign-guards-tablet.json', paperFile = '/tmp/cosign-guards-paper.json';
const groupDir = `${serverDir}test-guards/a`;
const state = () => JSON.parse(readFileSync(`${groupDir}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-guards/']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts test-guards/']);
for (const f of [phoneFile, tabletFile, paperFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-guards', '--port', '8758', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) { const l = openSync(`${serverDir}logs/guards-${s}.log`, 'w'); kids.push(spawn('node', ['server.ts', `test-guards/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_RECOVERY_WAIT: '6' } })); }
await sleep(3000);

// --- The key: a phone, a tablet, a paper ------------------------------------------------

const html = await (await fetch('http://localhost:8758/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile, PAPER_FILE: paperFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);
const ph = json(phoneFile);
const server = ph.group.members.find((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;

// Everything the server says to the phone, the tablet and the paper, heard here too.
const heard: { to: string; m: any }[] = [];
const keys = new Map<string, string>([[phonePk, ph.sk]]);
const parts = new Parts();
const ctl = new Pool(ph.group.relays, e => {
  const to = e.tags.find(t => t[0] === 'p')?.[1];
  const sk = to && keys.get(to);
  if (!sk || e.pubkey !== server.pk) return;
  const m = parts.take(e.pubkey, openFrom(sk, e));
  if (m) heard.push({ to: to!, m });
});
const listen = () => ctl.start([{ kinds: [KIND_MEMBER], '#p': [...keys.keys()] }]);
listen();
await sleep(2000);
const as = (sk: string, msg: object) => { for (const e of sealParts(sk, server.pk, msg)) ctl.publish(e); };
const asPhone = (to: string, msg: object) => { for (const e of sealParts(ph.sk, to, msg)) ctl.publish(e); };
const got = (to: string, pred: (m: any) => boolean) => heard.some(h => h.to === to && pred(h.m));

asPhone(phonePk, { type: 'test_backup' });
check('a paper backup', await waitFor(() => phone.out().includes('PAPER made'), 40_000));
const tablet = run(['test/fake-device.ts', 'Test tablet'], { DEVICE_STATE: tabletFile });
await waitFor(() => tablet.out().includes('JOIN '), 10_000);
const j = new URL(tablet.out().split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
await sleep(2500);
asPhone(phonePk, { type: 'test_vouch', pk: j.searchParams.get('pk') });
await sleep(1500);
asPhone(server.pk, { type: 'add_device', id: hex(6), pk: j.searchParams.get('pk'), name: 'Test tablet', relays: j.searchParams.getAll('r'), lock: true });
check('a tablet joins', await waitFor(() => tablet.out().includes('JOINED'), 40_000));
await sleep(2000);
const tb = json(tabletFile);
const tabletPk = pubOf(tb.sk);
const paper = json(paperFile);
keys.set(tabletPk, tb.sk); keys.set(pubOf(paper.sk), paper.sk);
listen();
await sleep(2000);
const paperPk = pubOf(paper.sk);
const paperKs: number[] = state().group.members.find((m: any) => m.role === 'backup').shares.map((x: any) => x.idx);
check('the paper holds 2', paperKs.length === 2);
const peerX = getPublicKey(randomBytes(32));

// --- What the paper can get: its pieces, nothing else -------------------------------------

const e1 = hex();
as(paper.sk, { type: 'ecdh_req', id: e1, participants: [...paperKs, server.idx], peerX });
await waitFor(() => got(paperPk, m => m.type === 'ecdh_res' && m.id === e1), 8000);
check('the paper gets no piece of a decryption', !got(paperPk, m => m.type === 'ecdh_res' && m.id === e1 && m.ok));
const s1 = hex();
as(paper.sk, { type: 'sign_req', id: s1, msg: hex(32), participants: [...paperKs, server.idx], commits: [], frost: 2, event: { pubkey: ph.group.groupX, kind: 1, content: '', tags: [], created_at: 0 } });
await waitFor(() => got(paperPk, m => m.type === 'sign_res' && m.id === s1), 8000);
check('nor a signature', !got(paperPk, m => m.type === 'sign_res' && m.id === s1 && m.ok));
const b1 = hex();
as(paper.sk, { type: 'backup_get', id: b1 });
check('but it can fetch its own pieces', await waitFor(() => got(paperPk, m => m.type === 'backup'), 10_000));
const e2 = hex();
as(tb.sk, { type: 'ecdh_req', id: e2, participants: [server.idx], peerX });
await waitFor(() => got(tabletPk, m => m.type === 'ecdh_res' && m.id === e2), 8000);
check('a device asking with fewer shares than it takes to sign gets nothing', !got(tabletPk, m => m.type === 'ecdh_res' && m.id === e2 && m.ok));

const group = () => ({ groupX: ph.group.groupX, threshold: 4, members: state().group.members.flatMap((m: any) => m.shares ?? [{ idx: m.idx, sharePub: m.sharePub }]) });

// --- Taking the account out through the server ------------------------------------------

const t1 = hex();
as(ph.sk, { type: 'take_out', id: t1 });
await sleep(1500);
check('without the lock, nothing starts', !state().guards?.some((g: any) => g.id === t1));
as(ph.sk, { type: 'take_out', id: t1, lock: true });
check('the tablet is told at once', await waitFor(() => got(tabletPk, m => m.type === 'guard' && m.id === t1 && m.kind === 'take_out' && m.state === 'waiting'), 15_000));
check('nothing is released before the wait', !got(phonePk, m => m.type === 'released'));
check('after the wait the server seals its share to the phone', await waitFor(() => got(phonePk, m => m.type === 'released' && m.id === t1), 30_000));
const rel = heard.find(h => h.to === phonePk && h.m.type === 'released')!.m;
const nsec = W.reconstruct(JSON.stringify(group()), JSON.stringify([...ph.shares.map((s: any) => [s.idx, s.secret]), ...rel.shares.map((s: any) => [s.idx, s.secret])]));
check('the phone’s 3 and the server’s 1 make the account’s key', getPublicKey(nsec) === ph.group.groupX);
check('the tablet hears it’s done', await waitFor(() => got(tabletPk, m => m.type === 'guard' && m.id === t1 && m.state === 'done'), 10_000));

// --- Stopped by another device -----------------------------------------------------------

const t2 = hex();
as(tb.sk, { type: 'take_out', id: t2, lock: true });
await waitFor(() => got(phonePk, m => m.type === 'guard' && m.id === t2), 15_000);
as(ph.sk, { type: 'guard_cancel', id: t2, lock: true });
check('the phone stops the tablet’s', await waitFor(() => got(tabletPk, m => m.type === 'guard' && m.id === t2 && m.state === 'cancelled'), 15_000));
await sleep(8000);
check('and nothing is released', !got(tabletPk, m => m.type === 'released' && m.id === t2));

// --- Removing the server's pieces: stops at once, can be cancelled ------------------------

const f1 = hex();
as(tb.sk, { type: 'forget', id: f1, lock: true });
await waitFor(() => got(phonePk, m => m.type === 'guard' && m.id === f1), 15_000);
const c1 = hex();
as(tb.sk, { type: 'cosign_req', id: c1, event: { kind: 1, content: 'x', tags: [], created_at: Math.floor(Date.now() / 1000) } });
check('while it waits the server signs nothing', await waitFor(() => got(tabletPk, m => m.type === 'cosign_res' && m.id === c1 && /removing its pieces/.test(m.reason ?? '')), 15_000));
as(ph.sk, { type: 'guard_cancel', id: f1, lock: true });
await waitFor(() => got(tabletPk, m => m.type === 'guard' && m.id === f1 && m.state === 'cancelled'), 15_000);
await sleep(8000);
check('cancelled: the pieces are still there', existsSync(`${groupDir}/state.json`));

// --- Taking it out with the paper: announced first ---------------------------------------

const t3 = hex();
as(ph.sk, { type: 'take_out', id: t3, lock: true, paper: true });
check('the server answers this request, signed by its member key', await waitFor(() => got(phonePk, m => m.type === 'noted' && m.id === t3), 15_000));
check('and every device hears it was taken out', await waitFor(() => got(tabletPk, m => m.type === 'guard' && m.id === t3 && m.paper && m.state === 'done'), 15_000));

// --- An app that was renamed keeps its grant ------------------------------------------------
//
// The app this signer is part of was renamed (Cosign became Marble) and says so with the
// grant it already has. Only one of your devices is ever heard on that.

const grantPk = 'a'.repeat(63) + '1';
as(tb.sk, { type: 'app_grant', pk: grantPk, origin: 'Cosign', via: 'App on this phone' });
check('an app connects', await waitFor(() => state().sites?.some((x: any) => x.pk === grantPk && x.origin === 'Cosign'), 15_000));
as(tb.sk, { type: 'app_grant', pk: grantPk, origin: 'Marble', via: 'App on this phone' });
check('renamed, it keeps the same grant under the new name',
  await waitFor(() => state().sites?.some((x: any) => x.pk === grantPk && x.origin === 'Marble'), 15_000),
  (state().sites ?? []).filter((x: any) => x.pk === grantPk).map((x: any) => x.origin).join(', '));
check('and it is still one grant, as it was added', state().sites.filter((x: any) => x.pk === grantPk).length === 1);

// --- Reported lost: at once, and for good -------------------------------------------------

as(tb.sk, { type: 'remove_member', id: hex(), idx: ph.idx });
await sleep(2000);
check('without the lock, a device isn’t removed', !state().group.members.find((m: any) => m.pk === phonePk)?.removed);
const r1 = hex();
as(tb.sk, { type: 'remove_member', id: r1, idx: ph.idx, lock: true });
check('the tablet reports the phone lost: removed at once', await waitFor(() => !!state().group.members.find((m: any) => m.pk === phonePk)?.removed, 15_000));
check('every device is told', await waitFor(() => got(tabletPk, m => m.type === 'guard' && m.id === r1 && m.kind === 'remove' && m.state === 'done'), 15_000));
const t5 = hex();
as(ph.sk, { type: 'take_out', id: t5, lock: true });
as(ph.sk, { type: 'guard_cancel', id: r1, lock: true });
await sleep(3000);
check('a removed device can’t start or cancel anything', !state().guards?.some((g: any) => g.id === t5) && !state().guards?.find((g: any) => g.id === r1)?.cancelled);

// --- A device taken out gets nothing at all -------------------------------------------------

const [x1, x2, x3] = [hex(), hex(), hex()];
as(ph.sk, { type: 'ecdh_req', id: x1, participants: [...ph.shares.map((x: any) => x.idx), server.idx], peerX });
as(ph.sk, { type: 'cosign_req', id: x2, event: { kind: 1, content: 'x', tags: [], created_at: Math.floor(Date.now() / 1000) } });
const backups = heard.filter(h => h.to === phonePk && h.m.type === 'backup').length;
as(ph.sk, { type: 'backup_get', id: x3 });
await sleep(6000);
check('the phone, taken out, gets no answer to anything', !got(phonePk, m => [x1, x2].includes(m.id)) && heard.filter(h => h.to === phonePk && h.m.type === 'backup').length === backups);

// --- Removing the server's pieces, for real -----------------------------------------------

const f2 = hex();
as(tb.sk, { type: 'forget', id: f2, lock: true });
check('after the wait, every piece here is deleted', await waitFor(() => !existsSync(groupDir), 30_000));

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
