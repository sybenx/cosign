// Shared servers: one process serving several people's keys at once, and a device giving
// a running server a share in a brand-new key, with no setup step on the server.
//
// Two hosts (each one process, like two operators' servers) serve server A and server B
// of two keys made by setup.ts; a fake phone for each, and both sign at the same time.
// Then a device deals a third key and enrolls it on both hosts (one takes only invited
// devices, the other anyone), its phone signs with them, and the first host restarts
// and still serves it from its groups/ directory.
//
//   node test/shared.e2e.ts        (starts and stops everything itself, in server/test-shared/)

import { readFileSync, writeFileSync, existsSync, openSync, mkdirSync } from 'node:fs';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, sealParts, openFrom, Parts, pubOf, KIND_MEMBER } from '../../server/net.ts';
import { deal } from '../../server/frost.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const at = (p: string) => serverDir + 'test-shared/' + p;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const json = (p: string) => JSON.parse(readFileSync(p, 'utf8'));
const hex = () => bytesToHex(randomBytes(32));

mkdirSync(serverDir + 'logs', { recursive: true });
const children: ChildProcess[] = [];
const run = (args: string[], log: string, env: Record<string, string> = {}) => {
  const c = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env }, stdio: ['ignore', openSync(serverDir + 'logs/' + log, 'a'), openSync(serverDir + 'logs/' + log, 'a')] });
  children.push(c);
  return c;
};
const done = (code: number) => { for (const c of children) c.kill(); process.exit(code); };
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };

// --- Two keys, server A of each on host 1 and server B of each on host 2 ---------------

execFileSync('rm', ['-rf', at('')]);
execFileSync('node', ['setup.ts', '--dir', 'test-shared/k1', '--port', '8971'], { cwd: serverDir });
execFileSync('node', ['setup.ts', '--dir', 'test-shared/k2', '--port', '8981'], { cwd: serverDir });
const dealer = hex(), stranger = hex(); // the device that will enroll a third key, and one nobody invited
const startH1 = () => run(['server.ts', '--root', 'test-shared/h1', '--port', '8970', 'test-shared/k1/a', 'test-shared/k2/a'], 'shared-h1.log', { COSIGN_INVITES: pubOf(dealer) });
let h1 = startH1();
run(['server.ts', '--root', 'test-shared/h2', '--port', '8990', 'test-shared/k1/b', 'test-shared/k2/b'], 'shared-h2.log', { COSIGN_ENROLL: 'open' });
await sleep(3000);

const phoneFile = (k: string) => `/tmp/cosign-fake-phone-${k}.json`;
for (const k of ['k1', 'k2']) {
  const s = json(at(`${k}/a/state.json`));
  const me = s.group.members.find((m: any) => m.idx === s.self.idx);
  const uri = `cosign:pair?pk=${me.pk}&t=${s.pairing.token}&${s.group.relays.map((r: string) => 'r=' + encodeURIComponent(r)).join('&')}`;
  run(['test/fake-phone.ts', uri], `shared-phone-${k}.log`, { PHONE_STATE: phoneFile(k) });
}
const paired = await waitFor(() => existsSync(phoneFile('k1')) && existsSync(phoneFile('k2')), 30_000);
check('a phone pairs with each key, both on the same host', paired);
if (!paired) done(1);
await sleep(12_000); // the servers see the phones' pings

const hostStatus = async (port: number) => (await fetch(`http://localhost:${port}/status`)).json() as Promise<any>;
const s1 = await hostStatus(8970);
check('host 1 lists both groups', s1.groups.length === 2, s1.groups.map((g: any) => `${g.me} ${g.id}`).join(', '));
const g1 = await (await fetch(`http://localhost:8970/g/${s1.groups[0].id}/status`)).json() as any;
check('each group keeps its own page under /g/<id>/', g1.npub === s1.groups[0].npub && Array.isArray(g1.activity));
check('and on its own port, as before', (await (await fetch('http://localhost:8971/status')).json() as any).npub === json(at('k1/a/state.json')).group.npub);

/** As a key's phone: hand the servers a ticket, connect a site with it. */
async function connectSite(phone: any, origin: string) {
  const ctl = new Pool(phone.group.relays, () => {});
  ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
  await sleep(1500);
  const t = bytesToHex(randomBytes(16));
  for (const s of phone.group.members.filter((m: any) => m.role === 'server')) ctl.publish(sealTo(phone.sk, s.pk, { type: 'ticket', t, origin, expires: Math.floor(Date.now() / 1000) + 900 }));
  await sleep(1500);
  const site = new SignerClient(newSession(phone.signer, phone.group.relays));
  await site.connect(t);
  return site;
}

async function signs(phone: any, origin: string) {
  const site = await connectSite(phone, origin);
  const pk = await site.getPublicKey();
  const note = await site.signEvent({ kind: 1, content: `shared server test, ${origin}`, tags: [] });
  const follows = await site.signEvent({ kind: 3, content: '', tags: [['p', hex()]] });
  site.close();
  return pk === phone.group.groupX && verifyEvent(note) && note.pubkey === pk && verifyEvent(follows);
}

const [ok1, ok2] = await Promise.all([signs(json(phoneFile('k1')), 'one.test'), signs(json(phoneFile('k2')), 'two.test')]);
check('key 1 signs (a note and a follow list) on the shared hosts', ok1);
check('key 2 signs at the same time, on the same two processes', ok2);

// --- Enrolling a third key on both running hosts ------------------------------------

const host1 = json(at('h1/host.json')), host2 = json(at('h2/host.json'));
const replies = new Map<string, any>();
const parts = new Parts();
const dev = new Pool([...new Set([...host1.relays, ...host2.relays])], e => {
  for (const sk of [dealer, stranger]) { const m = parts.take(e.pubkey, openFrom(sk, e)); if (m?.id) replies.set(m.id, m); }
});
dev.start([{ kinds: [KIND_MEMBER], '#p': [pubOf(dealer), pubOf(stranger)] }]);
await sleep(2000);
/** Write to a host key, again every 4 s, until it answers. */
async function ask(from: string, hostPk: string, msg: any) {
  msg.id = bytesToHex(randomBytes(8));
  const until = Date.now() + 25_000;
  while (!replies.has(msg.id) && Date.now() < until) {
    for (const e of sealParts(from, hostPk, msg)) dev.publish(e);
    await waitFor(() => replies.has(msg.id), 4000);
  }
  return replies.get(msg.id) ?? { type: 'no answer' };
}

const refused = await ask(stranger, host1.pk, { type: 'enroll_key' });
check('a host that takes only invited devices turns away anyone else', refused.type === 'enroll_failed' && refused.reason.startsWith('not-invited'), refused.reason);
const [key1, key2] = await Promise.all([ask(dealer, host1.pk, { type: 'enroll_key' }), ask(dealer, host2.pk, { type: 'enroll_key' })]);
check('both hosts hand out a member key for the new group', key1.type === 'enroll_key' && key2.type === 'enroll_key' && key1.pk !== key2.pk);

const dealt = deal(null, 3, 2);
const signerSk = hex(), phoneSk = hex();
const relays = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
const group = {
  groupX: dealt.groupX, threshold: 2, relays,
  members: [
    { idx: 1, name: 'Shared A', role: 'server', pk: key1.pk, sharePub: dealt.shares[0].pub },
    { idx: 2, name: 'Shared B', role: 'server', pk: key2.pk, sharePub: dealt.shares[1].pub },
    { idx: 3, name: 'Phone', role: 'phone', pk: pubOf(phoneSk), sharePub: dealt.shares[2].pub },
  ],
};
const signer = { sk: signerSk, pk: pubOf(signerSk) };
const enroll = (k: any, share: string) => ({ type: 'enroll', how: 'dealt', key: k.key, group, signer, share });

const wrong = await ask(dealer, host1.pk, enroll(key1, dealt.shares[1].secret));
check('a share that isn’t this server’s is refused', wrong.type === 'enroll_failed' && wrong.reason.startsWith('bad-share'), wrong.reason);
const bent = await ask(dealer, host2.pk, { ...enroll(key2, dealt.shares[1].secret), group: { ...group, members: group.members.map(m => m.idx === 3 ? { ...m, sharePub: dealt.shares[0].pub } : m) } });
check('so is a group whose share points don’t belong to its key', bent.type === 'enroll_failed' && bent.reason.startsWith('bad-group'), bent.reason);
const [e1, e2] = await Promise.all([ask(dealer, host1.pk, enroll(key1, dealt.shares[0].secret)), ask(dealer, host2.pk, enroll(key2, dealt.shares[1].secret))]);
check('both hosts take the new group on', e1.type === 'enrolled' && e2.type === 'enrolled', `${e1.type}/${e2.type} ${e1.reason ?? ''}${e2.reason ?? ''}`);
const again = await ask(dealer, host1.pk, enroll(key1, dealt.shares[0].secret));
check('asking again gets the same answer', again.type === 'enrolled' && again.group === e1.group);
check('it has a directory of its own on each', existsSync(at(`h1/groups/${e1.group}/state.json`)) && existsSync(at(`h2/groups/${e2.group}/state.json`)));
check('host 1 now serves three groups', (await hostStatus(8970)).groups.length === 3);

const phone3 = { sk: phoneSk, idx: 3, share: dealt.shares[2].secret, signer: signer.pk, group };
writeFileSync(phoneFile('k3'), JSON.stringify(phone3, null, 2));
run(['test/fake-phone.ts'], 'shared-phone-k3.log', { PHONE_STATE: phoneFile('k3') });
await sleep(12_000);
check('the enrolled key signs with its two servers and its phone', await signs(phone3, 'three.test'));

// --- A restart: the enrolled group is in groups/, and comes back ------------------------

h1.kill();
await sleep(1500);
h1 = startH1();
await sleep(15_000);
const after = await hostStatus(8970);
check('after a restart, host 1 serves all three again', after.groups.length === 3 && after.groups.some((g: any) => g.id === e1.group));
check('and the enrolled key still signs', await signs(phone3, 'three-again.test'));

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
