// "Add a server" to a key that exists: a phone and one Node server make a key, then the
// phone adds a Cloudflare Worker server (../../worker, under wrangler dev) as a second one:
// enrolled on the Worker to wait for its share (how: 'repair'), vouched for by the phone
// with the first server, after which the Worker co-signs, never answers sites (it has no
// signer key), and the first server knows that and keeps answering them.
//
//   (cd worker && npx wrangler dev --port 8800 --var COSIGN_URL:ws://127.0.0.1:8800)
//   node test/addserver.e2e.ts

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { getEventHash, verifyEvent } from 'nostr-tools/pure';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, sealParts, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';
import * as Sig from '../../server/sign.ts';

const worker = 'ws://127.0.0.1:8800';
const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-addserver-phone.json';
const state = () => JSON.parse(readFileSync(`${serverDir}test-addserver/a/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts test-addserver/']); process.exit(code); };

const w0 = await (await fetch(worker.replace(/^ws/, 'http') + '/status')).json() as any;
spawnSync('pkill', ['-f', 'server.ts test-addserver/']);
if (existsSync(phoneFile)) rmSync(phoneFile);
spawnSync('node', ['setup.ts', '--dir', 'test-addserver', '--port', '8763', '--weighted', '--single', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
const l = openSync(`${serverDir}logs/addserver-a.log`, 'w');
// The Worker under wrangler dev is on this machine: let this test's server reach it (egress.ts refuses loopback otherwise).
kids.push(spawn('node', ['server.ts', 'test-addserver/a'], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_RELAY_ALLOW: worker, COSIGN_ADD_WAIT: '2' } }));
await sleep(3000);
const html = await (await fetch('http://localhost:8763/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = spawn('node', ['test/fake-phone.ts', uri], { cwd: serverDir, env: { ...process.env, PHONE_STATE: phoneFile } });
kids.push(phone);
let out = ''; phone.stdout.on('data', d => { out += d; }); phone.stderr.on('data', d => { out += d; });
check('a phone and one server make a key', await waitFor(() => out.includes('made npub'), 60_000));
await sleep(5000);
let ph = json(phoneFile);
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool([...ph.group.relays, worker], () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);

ctl.publish(sealTo(ph.sk, phonePk, { type: 'test_add_server', host: w0.host, relays: [worker], name: 'Worker' }));
const added = await waitFor(() => state().group.members.some((m: any) => m.name === 'Worker' && m.role === 'server' && m.sharePub), 60_000);
check('the phone adds the Worker as a second server', added, out.split('\n').filter(x => /server|FAILED/.test(x)).join(' | '));
if (!added) done(1);
const w1 = await (await fetch(worker.replace(/^ws/, 'http') + '/status')).json() as any;
check('the Worker serves the key now', w1.groups === w0.groups + 1);
check('the first server knows the Worker doesn’t answer sites', await waitFor(() => !!state().group.members.find((m: any) => m.name === 'Worker')?.noSites, 20_000));
check('and listens on the Worker’s relay', state().group.relays.includes(worker));
await sleep(3000);

// The Worker co-signs a round the phone runs (as for an app on the phone).
ph = json(phoneFile);
const wk = state().group.members.find((m: any) => m.name === 'Worker');
const g: Sig.Group = { groupX: ph.group.groupX, threshold: 4, members: state().group.members.filter((m: any) => !m.removed).map((m: any) => ({ idx: m.idx, sharePub: m.sharePub, ...(m.shares ? { shares: m.shares } : {}) })) };
const replies = new Map<string, any>();
const parts = new Parts();
const dev = new Pool([worker], e => { const m = parts.take(e.pubkey, openFrom(ph.sk, e)); if (m?.id) replies.set(m.id, m); });
dev.start([{ kinds: [KIND_MEMBER], '#p': [phonePk] }]);
await sleep(1500);
const sendW = (m: object) => { for (const e of sealParts(ph.sk, wk.pk, m)) dev.publish(e); };
const grant = bytesToHex(randomBytes(32));
sendW({ type: 'app_grant', pk: grant, origin: 'Test app' });
await sleep(1500);
const ev = { pubkey: ph.group.groupX, kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'phone and the Worker' };
const id = getEventHash(ev as any);
const mine = Sig.commitAll(g, ph.shares);
const rid = bytesToHex(randomBytes(6));
for (let i = 0; i < 5 && !replies.has(rid); i++) { sendW({ type: 'cosign_req', id: rid, event: ev, msg: id, participants: [...ph.shares.map((s: any) => s.idx), wk.idx].sort((a, b) => a - b), commits: mine.commits, commit: mine.commits[0], frost: 2, grant, approved: false }); await waitFor(() => replies.has(rid), 3000); }
const res = replies.get(rid);
if (res?.ok) {
  const commits = [...mine.commits, ...res.commits];
  const zs = Sig.partialAll(2, g, ph.shares, mine.nonces, id, commits);
  check('the phone (3) and the Worker (1) sign', schnorr.verify(hexToBytes(Sig.combine(2, g, id, commits, [...zs, ...res.zs])), hexToBytes(id), hexToBytes(ph.group.groupX)));
} else check('the phone (3) and the Worker (1) sign', false, res?.reason ?? 'no answer');

// Sites still sign through the first server, which has the signer key.
const t = bytesToHex(randomBytes(16));
ctl.publish(sealTo(ph.sk, state().group.members.find((m: any) => m.idx === state().self.idx).pk, { type: 'ticket', t, origin: 'addserver.test', expires: Math.floor(Date.now() / 1000) + 900 }));
await sleep(1500);
const site = new SignerClient(newSession(ph.signer, ph.group.relays.filter((r: string) => r.startsWith('wss'))));
await site.connect(t);
const n = await site.signEvent({ kind: 1, content: 'a site, with two servers', tags: [] }).catch(e => e);
check('a site still signs, answered by the first server', verifyEvent(n), String(n?.message ?? ''));
site.close();
console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
