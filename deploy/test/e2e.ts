// A sidecar, end to end, against a relay running here in Docker: the server starts from
// the published image beside the relay, announces itself (kind 30243) on it, takes on a
// key a device enrolls (the phone 3 shares, this server and a second one 1 each, any 4
// sign), and a site signs in with a ticket and signs. Then a restart, and it still signs.
//
//   node deploy/test/e2e.ts strfry                 (or nostr-rs-relay)
//   node deploy/test/e2e.ts strfry other-relay     another folder's compose.yaml, beside that relay
//
// Needs Docker, and npm installs done in server/ and site/: the stand-in phone and site
// come from there. The relay goes by a public-looking name (a server never announces
// itself on relays only reachable locally), which the servers map to the relay inside
// Docker and this test maps to localhost (map-relays.ts). The relay's Docker network is
// internal (test/relays/), so the servers can't reach the internet: nothing is posted to
// a public relay.

import './map-relays.ts'; // before nostr-tools loads, which takes the WebSocket it finds
import { writeFileSync, mkdtempSync, openSync } from 'node:fs';
import { createRequire } from 'node:module';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// url: the relay's "public" address; local: where this machine reaches it; internal: where the servers do.
const RELAYS: Record<string, { url: string; local: string; internal: string }> = {
  'strfry': { url: 'wss://strfry.sidecar-test.example', local: 'ws://localhost:17777', internal: 'ws://strfry:7777' },
  'nostr-rs-relay': { url: 'wss://nostr-rs-relay.sidecar-test.example', local: 'ws://localhost:18080', internal: 'ws://nostr-rs-relay:8080' },
};
const name = process.argv[2];
const folder = process.argv[3] ?? name;
const relay = RELAYS[name];
if (!relay) { console.error(`usage: node deploy/test/e2e.ts ${Object.keys(RELAYS).join('|')} [folder]`); process.exit(1); }
process.env.TEST_RELAY_MAP = `${relay.url}=${relay.local}`;

const src = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const { verifyEvent, generateSecretKey, getPublicKey } = await import(`${src}/server/node_modules/nostr-tools/lib/esm/pure.js`);
const { nip19 } = await import(`${src}/server/node_modules/nostr-tools/lib/esm/index.js`);
const { bytesToHex, randomBytes } = await import(`${src}/server/node_modules/@noble/hashes/utils.js`);
const { Pool, sealTo, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } = await import(`${src}/server/net.ts`);
const { SignerClient, newSession } = await import(`${src}/site/src/client.ts`);
const { parseAnnouncement, relayQuery } = await import(`${src}/site/src/servers.ts`);

const repo = new URL('..', import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), `cosign-sidecar-${name}-`));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const hex = () => bytesToHex(randomBytes(32));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const waitFor = async (pred: () => boolean | Promise<boolean>, ms: number) => { const until = Date.now() + ms; while (!(await pred()) && Date.now() < until) await sleep(500); return pred(); };

// --- The relay, and the sidecar beside it -------------------------------------------

const operator = generateSecretKey();
const env = {
  ...process.env,
  COSIGN_OPERATOR: nip19.npubEncode(getPublicKey(operator)),
  RELAY_URL: relay.url, RELAY_INTERNAL: relay.internal, RELAY_NETWORK: `${name}_default`, EXTRA_RELAYS: '',
};
const relayStack = ['compose', '-f', `${repo}test/relays/${name}.yaml`];
const sidecar = ['compose', '-f', `${repo}${folder}/compose.yaml`, '-f', `${repo}test/sidecar.yaml`];
const docker = (args: string[]) => execFileSync('docker', args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const children: ChildProcess[] = [];
function done(code: number) {
  for (const c of children) c.kill();
  if (!process.env.KEEP) { try { docker([...sidecar, 'down', '-v']); docker([...relayStack, 'down', '-v']); } catch {} }
  console.log(failures ? `${failures} failed` : 'all passed');
  process.exit(code);
}

docker([...sidecar, 'down', '-v']);
docker([...relayStack, 'up', '-d', '--wait']);
docker([...sidecar, 'up', '-d']);
const hostOf = (svc: string) => { try { return JSON.parse(docker([...sidecar, 'exec', '-T', svc, 'cat', '/data/host.json'])); } catch { return null; } };
let host1: any = null, host2: any = null;
await waitFor(() => !!(host1 = hostOf('cosign')) && !!(host2 = hostOf('cosign-b')), 30_000);
check('both servers start, each with a host key', !!host1 && !!host2);
if (!host1 || !host2) done(1);
check('the server uses the relay’s public address, and no other relay', host1.relays.join() === relay.url, host1.relays.join());

// --- It announces itself ---------------------------------------------------------------

let ann: any = null;
await waitFor(async () => {
  const found = await relayQuery(4000)([relay.url], { kinds: [30243], authors: [host1.pk] });
  return !!(ann = found.map(parseAnnouncement).find(Boolean));
}, 30_000);
check('it announces itself on the relay (kind 30243), signed by its host key', !!ann && ann.pk === host1.pk);
check('naming its operator, the relay and open enrollment', !!ann && ann.operator === getPublicKey(operator) && ann.relays.join() === relay.url && ann.enroll === 'open',
  ann && `operator ${ann.operator.slice(0, 8)}…, version ${ann.version}`);
const quiet = await relayQuery(4000)([relay.url], { kinds: [30243], authors: [host2.pk] });
check('a server with no operator doesn’t announce', quiet.length === 0);

// --- A device enrolls a new key on both servers ------------------------------------------

const dealer = hex();
const replies = new Map<string, any>();
const parts = new Parts();
const dev = new Pool([relay.url], (e: any) => { const m = parts.take(e.pubkey, openFrom(dealer, e)); if (m?.id) replies.set(m.id, m); });
dev.start([{ kinds: [KIND_MEMBER], '#p': [pubOf(dealer)] }]);
await sleep(1500);
async function ask(hostPk: string, msg: any) {
  msg.id = bytesToHex(randomBytes(8));
  const until = Date.now() + 25_000;
  while (!replies.has(msg.id) && Date.now() < until) {
    for (const e of sealParts(dealer, hostPk, msg)) dev.publish(e);
    await waitFor(() => replies.has(msg.id), 4000);
  }
  return replies.get(msg.id) ?? { type: 'no answer' };
}

const [key1, key2] = await Promise.all([ask(host1.pk, { type: 'enroll_key' }), ask(host2.pk, { type: 'enroll_key' })]);
check('both servers hand out a member key', key1.type === 'enroll_key' && key2.type === 'enroll_key', `${key1.type}/${key2.type}`);
// Weighted, as accounts are: the phone 3 shares (1–3), each server 1 (4, 5), any 4 sign.
const W = createRequire(import.meta.url)(`${src}/server/frost-wasm/cosign_frost.js`);
const d = JSON.parse(W.dealFromSecret(randomBytes(32), [1, 2, 3, 4, 5], 4));
const sh = (i: number) => d.shares.find((x: any) => x.idx === i);
const signerSk = hex(), phoneSk = hex();
const group = {
  groupX: d.groupX, threshold: 4, relays: [relay.url],
  members: [
    { idx: 4, name: 'Sidecar', role: 'server', pk: key1.pk, sharePub: sh(4).sharePub },
    { idx: 5, name: 'Second server', role: 'server', pk: key2.pk, sharePub: sh(5).sharePub },
    { idx: 1, name: 'Phone', role: 'phone', pk: pubOf(phoneSk), sharePub: sh(1).sharePub, shares: [1, 2, 3].map(i => ({ idx: i, sharePub: sh(i).sharePub })) },
  ],
};
const signer = { sk: signerSk, pk: pubOf(signerSk) };
const enroll = (k: any, share: string) => ({ type: 'enroll', how: 'dealt', key: k.key, group, signer, share });
const [e1, e2] = await Promise.all([ask(host1.pk, enroll(key1, sh(4).secret)), ask(host2.pk, enroll(key2, sh(5).secret))]);
check('both servers take the new key on', e1.type === 'enrolled' && e2.type === 'enrolled', `${e1.type}/${e2.type} ${e1.reason ?? ''}${e2.reason ?? ''}`);
dev.close?.();

// --- The phone, and a site signing in ------------------------------------------------------

const phone = { sk: phoneSk, idx: 1, shares: [1, 2, 3].map(i => ({ idx: i, secret: sh(i).secret })), signer: signer.pk, group };
const phoneFile = join(tmp, 'phone.json');
writeFileSync(phoneFile, JSON.stringify(phone, null, 2));
const log = openSync(join(tmp, 'phone.log'), 'a');
children.push(spawn('node', ['--import', new URL('./map-relays.ts', import.meta.url).href, `${src}/server/test/fake-phone.ts`], { cwd: `${src}/server`, env: { ...process.env, PHONE_STATE: phoneFile }, stdio: ['ignore', log, log] }));
await sleep(12_000); // the servers see the phone's pings

async function signs(origin: string) {
  const ctl = new Pool(group.relays, () => {});
  ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
  await sleep(1500);
  const t = bytesToHex(randomBytes(16));
  for (const s of group.members.filter(m => m.role === 'server')) ctl.publish(sealTo(phone.sk, s.pk, { type: 'ticket', t, origin, expires: Math.floor(Date.now() / 1000) + 900 }));
  await sleep(1500);
  const site = new SignerClient(newSession(phone.signer, group.relays));
  try {
    await site.connect(t);
    const pk = await site.getPublicKey();
    const note = await site.signEvent({ kind: 1, content: `sidecar test, ${origin}`, tags: [] });
    const follows = await site.signEvent({ kind: 3, content: '', tags: [['p', hex()]] });
    return pk === group.groupX && verifyEvent(note) && note.pubkey === pk && verifyEvent(follows);
  } catch (err: any) {
    console.log(`     ${err?.message ?? err}`);
    return false;
  } finally { site.close(); ctl.close?.(); }
}

check('a site signs in with a ticket, and signs a note and a follow list', await signs('one.test'));

// --- A restart -------------------------------------------------------------------------

docker([...sidecar, 'restart', 'cosign']);
await sleep(15_000);
check('after a restart the server still has the key, and it signs', await signs('two.test'));
const again = hostOf('cosign');
check('and the same host key', again?.pk === host1.pk);

if (failures) console.log(`logs: docker ${sidecar.join(' ')} logs; phone: ${tmp}/phone.log`);
done(failures ? 1 : 0);
