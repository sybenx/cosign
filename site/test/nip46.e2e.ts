// Ordinary NIP-46 clients against a Cosign account — the author's bar: "Cosign should be
// working with nak, grimoire, whatever, commandline tools on nostr."
//
// The client here is written to the spec rather than with Cosign's own helper: a fresh key,
// kind 24133, nip44 (and one request in nip04, which older clients still send). Every method
// a standard client calls is asked for, including the ones Cosign refuses on purpose, so a
// change of mind about any of them shows up here. When `nak` is on the PATH it is run too,
// as the real thing: `nak event --sec bunker://…`.
//
// The bunker URL is built from a relay the server reports **up**. That is not a detail: with
// an unreachable relay among the `relay=` parameters, nak publishes nothing at all and waits
// for ever (seen with nos.lol down, 2026-10-26), so a client's experience depends on Cosign
// handing out relays that answer.
//
//   node test/nip46.e2e.ts      (sets up its own group in server/test-nip46/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, execFileSync, type ChildProcess } from 'node:child_process';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, KIND_MEMBER, KIND_NIP46 } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-nip46-phone.json';
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
const hex = (n = 8) => bytesToHex(randomBytes(n));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-nip46']); process.exit(code); };

spawnSync('pkill', ['-f', 'server.ts.*test-nip46']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('node', ['setup.ts', '--dir', 'test-nip46', '--port', '8795', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) {
  const l = openSync(`${serverDir}logs/nip46-${s}.log`, 'w');
  kids.push(spawn('node', ['server.ts', `test-nip46/${s}`], { cwd: serverDir, stdio: ['ignore', l, l] }));
}
await sleep(3000);
const html = await (await fetch('http://localhost:8795/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phoneLog = openSync(`${serverDir}logs/nip46-phone.log`, 'w');
kids.push(spawn('node', ['test/fake-phone.ts', uri], { cwd: serverDir, stdio: ['ignore', phoneLog, phoneLog], env: { ...process.env, PHONE_STATE: phoneFile } }));
check('the phone and two servers make a key', await waitFor(() => existsSync(phoneFile) && !!json(phoneFile).signer, 60_000));
if (failures) done(1);
await sleep(5000);
const ph = json(phoneFile);
const signer: string = ph.signer;

// A relay this server says is up, which is what a client should be handed.
const status = await (await fetch('http://localhost:8795/status')).json() as any;
const live: string = (status.relays ?? []).find((r: any) => r.up)?.url ?? ph.group.relays[0];
check('the server knows which of its relays are up', !!live, live);

const sk = randomBytes(32), pk = getPublicKey(sk);
const key = nip44.v2.utils.getConversationKey(sk, signer);
const answers = new Map<string, any>();
const pool = new Pool([live], (e: any) => {
  if (e.kind !== KIND_NIP46) return;
  for (const dec of [() => nip44.v2.decrypt(e.content, key), () => nip04.decrypt(sk, signer, e.content)]) {
    try { const r = JSON.parse(dec()); if (r?.id) answers.set(r.id, r); return; } catch { /* the other scheme */ }
  }
});
pool.start([{ kinds: [KIND_NIP46], '#p': [pk] }]);
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2500);
/** The phone mints a ticket, as scanning a site's code does. */
const ticket = (origin: string) => {
  const t = hex(16);
  for (const s of ph.group.members.filter((m: any) => m.role === 'server')) for (const e of sealParts(ph.sk, s.pk, { type: 'ticket', t, origin, expires: Math.floor(Date.now() / 1000) + 900 })) ctl.publish(e);
  return t;
};
const t = ticket('spec.test');
await sleep(2500);

async function call(method: string, params: string[], scheme: 'nip44' | 'nip04' = 'nip44', ms = 15_000) {
  const id = hex(6);
  const body = JSON.stringify({ id, method, params });
  const content = scheme === 'nip44' ? nip44.v2.encrypt(body, key) : nip04.encrypt(sk, signer, body);
  pool.publish(finalizeEvent({ kind: KIND_NIP46, created_at: Math.floor(Date.now() / 1000), tags: [['p', signer]], content }, sk));
  const until = Date.now() + ms;
  while (Date.now() < until) { const a = answers.get(id); if (a) return a; await sleep(200); }
  return { timeout: true } as any;
}
const errs = (a: any, code: string) => typeof a.error === 'string' && a.error.startsWith(code);

// --- Before connecting ------------------------------------------------------------------------

check('connect with no secret is refused', errs(await call('connect', [signer]), 'bad-ticket:'));
check('connect with a wrong secret is refused', errs(await call('connect', [signer, 'deadbeef']), 'bad-ticket:'));
check('anything before connecting is refused', errs(await call('get_public_key', []), 'not-connected:'));

// --- Connected --------------------------------------------------------------------------------

check('connect with a ticket is acked', (await call('connect', [signer, t])).result === 'ack');
check('get_public_key is the account', (await call('get_public_key', [])).result === ph.group.groupX);
check('ping answers pong', (await call('ping', [])).result === 'pong');
const rel = await call('get_relays', []);
check('get_relays answers the account’s relays', typeof rel.result === 'string' && rel.result.includes(live));

for (const [label, ev, ms] of [
  ['a note', { kind: 1, content: 'from a spec client', tags: [] }, 15_000],
  ['a profile', { kind: 0, content: '{"name":"spec client"}', tags: [] }, 15_000],
  ['a long-form post', { kind: 30023, content: 'long', tags: [['d', 'spec']] }, 15_000],
  // A deletion is answered after its ten-second undo window (§5.4), so a client waits
  // longer for this one than for anything else. Worth knowing before blaming the signer.
  ['a deletion', { kind: 5, content: '', tags: [['e', hex(32)]] }, 40_000],
] as [string, any, number][]) {
  const a = await call('sign_event', [JSON.stringify({ ...ev, created_at: Math.floor(Date.now() / 1000) })], 'nip44', ms);
  let signed: any = null;
  try { signed = JSON.parse(a.result); } catch { /* an error, below */ }
  check(`sign_event: ${label}`, !!signed && verifyEvent(signed) && signed.pubkey === ph.group.groupX, a.error ?? '');
}
const old = await call('sign_event', [JSON.stringify({ kind: 1, content: 'an nip04 request', tags: [], created_at: Math.floor(Date.now() / 1000) })], 'nip04');
check('a request in nip04 is answered in nip04', (() => { try { const s = JSON.parse(old.result); return verifyEvent(s); } catch { return false; } })(), old.error ?? '');

// --- Refused on purpose (COSIGN.md §6.1, §9.2) -------------------------------------------------

for (const m of ['nip44_encrypt', 'nip44_decrypt', 'nip04_encrypt', 'nip04_decrypt']) {
  check(`${m} is refused while sites share one signer key`, errs(await call(m, [ph.group.groupX, 'x']), 'unsupported:'));
}
check('an unknown method says so', /^unsupported method/.test((await call('wave_hands', [])).error ?? ''));

// --- Signing out ------------------------------------------------------------------------------

check('logout is acked', (await call('logout', [])).result === 'ack');
check('and then everything is refused', errs(await call('sign_event', [JSON.stringify({ kind: 1, content: 'after logout', tags: [], created_at: Math.floor(Date.now() / 1000) })]), 'revoked:'));

// --- nak, when it is here ---------------------------------------------------------------------

let nak = '';
try { nak = execFileSync('which', ['nak'], { encoding: 'utf8' }).trim(); } catch { /* not installed */ }
if (!nak) console.log('--   nak is not on the PATH: skipped (brew install nak)');
else {
  const bunker = `bunker://${signer}?relay=${encodeURIComponent(live)}&secret=${ticket('nak.test')}`;
  await sleep(2500);
  const out = await new Promise<string>(resolve => {
    // stdin must be closed: `nak event` also takes an event on stdin, so with an open pipe
    // there it waits for one and never gets as far as the signer.
    const k = spawn(nak, ['event', '-k', '1', '-c', 'hello from nak', '--sec', bunker], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let s = ''; k.stdout.on('data', d => { s += d; }); k.stderr.on('data', d => { s += d; });
    const stop = setTimeout(() => { k.kill(); resolve(s); }, 45_000);
    k.on('exit', () => { clearTimeout(stop); resolve(s); });
    const look = setInterval(() => { if (/"sig"|error/.test(s)) { clearInterval(look); clearTimeout(stop); k.kill(); resolve(s); } }, 400);
  });
  let ev: any = null;
  for (const line of out.split('\n')) { try { const p = JSON.parse(line); if (p?.sig) ev = p; } catch { /* nak's own chatter */ } }
  check('nak signs through a bunker URL', !!ev && verifyEvent(ev) && ev.pubkey === ph.group.groupX,
    ev ? '' : `${out.length} chars from nak: ${out.slice(0, 220).replace(/\n/g, ' | ')}`);
  if (!ev) console.log(`--   the URL it was given: bunker://${signer.slice(0, 10)}…?relay=${live}&secret=…`);
}

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
