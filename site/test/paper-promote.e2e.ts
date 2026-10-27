// A paper backup must not be able to promote itself to a device (~/igloo/cosign-live-findings.md
// item 12). `case 'members'` used to accept the list from any member that is not a device, and
// the paper is one of those: it could send a list saying its own entry is a device, and
// `mergeMembers`'s backup-became-a-phone clause would believe it. After the flip the paper was
// `isDevice`, so everything gated on that opened — `app_grant` above all — with none of the
// wait a real recovery runs.
//
//   node test/paper-promote.e2e.ts   (sets up its own group in server/test-promote/)

import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { getPublicKey } from 'nostr-tools/pure';
import { hexToBytes } from '@noble/hashes/utils.js';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const phoneFile = '/tmp/cosign-promote-phone.json', paperFile = '/tmp/cosign-promote-paper.json';
const state = (s = 'a') => JSON.parse(readFileSync(`${serverDir}test-promote/${s}/state.json`, 'utf8'));
const json = (f: string) => JSON.parse(readFileSync(f, 'utf8'));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: () => boolean, ms: number) => { const until = Date.now() + ms; while (!pred() && Date.now() < until) await sleep(250); return pred(); };
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const kids: ChildProcess[] = [];
const done = (code: number) => { for (const k of kids) k.kill(); spawnSync('pkill', ['-f', 'server.ts.*test-promote']); process.exit(code); };
const run = (args: string[], env: Record<string, string> = {}) => {
  const k = spawn('node', args, { cwd: serverDir, env: { ...process.env, ...env } });
  let out = '';
  k.stdout.on('data', d => { out += d; }); k.stderr.on('data', d => { out += d; });
  kids.push(k);
  return { k, out: () => out };
};

spawnSync('pkill', ['-f', 'server.ts.*test-promote']);
for (const f of [phoneFile, paperFile]) if (existsSync(f)) rmSync(f);
spawnSync('node', ['setup.ts', '--dir', 'test-promote', '--port', '8772', '--weighted', '--force'], { cwd: serverDir });
mkdirSync(serverDir + 'logs', { recursive: true });
for (const s of ['a', 'b']) { const l = openSync(`${serverDir}logs/promote-${s}.log`, 'w'); kids.push(spawn('node', ['server.ts', `test-promote/${s}`], { cwd: serverDir, stdio: ['ignore', l, l], env: { ...process.env, COSIGN_RECOVERY_WAIT: '12', COSIGN_ADD_WAIT: '2' } })); }
await sleep(3000);

const html = await (await fetch('http://localhost:8772/')).text();
const uri = html.match(/href="(cosign:pair\?[^"]+)"/)![1].replaceAll('&amp;', '&');
const phone = run(['test/fake-phone.ts', uri], { PHONE_STATE: phoneFile, PAPER_FILE: paperFile });
check('the phone and two servers make a key', await waitFor(() => phone.out().includes('made npub'), 60_000));
await sleep(5000);

const ph = json(phoneFile);
const server = ph.group.members.find((m: any) => m.role === 'server');
const phonePk = ph.group.members.find((m: any) => m.idx === ph.idx).pk;
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);

ctl.publish(sealTo(ph.sk, phonePk, { type: 'test_backup' }));
check('the phone makes a paper backup', await waitFor(() => phone.out().includes('PAPER made'), 40_000));
await sleep(2000);

const paper = json(paperFile);
const paperPk = getPublicKey(hexToBytes(paper.sk));
const paperMember = state().group.members.find((m: any) => m.role === 'backup');
check('the server knows the paper, by its own public key', paperMember?.pk === paperPk, `${paperMember?.role} ${paperMember?.pk?.slice(0, 8)}`);

// The attack. The paper sends a member list in which its own entry is a device.
const forged = state().group.members
  .filter((m: any) => !m.removed)
  .map((m: any) => m.idx === paperMember.idx ? { ...m, role: 'device', name: 'Not a paper' } : m);
for (const s of [server.pk, ph.group.members.find((m: any) => m.role === 'server' && m.pk !== server.pk)?.pk].filter(Boolean)) {
  ctl.publish(sealTo(paper.sk, s as string, { type: 'members', members: forged, epoch: state().epoch ?? 0 }));
}
await sleep(4000);

for (const s of ['a', 'b']) {
  const mine = state(s).group.members.find((m: any) => m.idx === paperMember.idx);
  check(`server ${s} still calls it a paper`, mine?.role === 'backup', `role ${mine?.role}`);
}
check('the paper is still the backup the server holds', !!state().backup);

// And the thing the flip was worth: granting a site. A paper may not.
const sitePk = bytesToHex(randomBytes(32));
ctl.publish(sealTo(paper.sk, server.pk, { type: 'app_grant', pk: sitePk, origin: 'paper.invalid', sign: true, dm: true }));
await sleep(3000);
check('a grant asked for by the paper is refused', !JSON.stringify(state().sites ?? []).includes(sitePk));

// The phone is unaffected: it still grants.
const goodPk = bytesToHex(randomBytes(32));
ctl.publish(sealTo(ph.sk, server.pk, { type: 'app_grant', pk: goodPk, origin: 'phone.invalid', sign: true, dm: true }));
check('a grant asked for by the phone still works', await waitFor(() => JSON.stringify(state().sites ?? []).includes(goodPk), 10_000));

// A server's list is still merged: the real backup-became-a-phone path is untouched.
check('the two servers still agree on the members', state('a').group.members.length === state('b').group.members.length,
  `${state('a').group.members.length} vs ${state('b').group.members.length}`);

console.log(failures ? `${failures} failed` : 'all passed');
done(failures ? 1 : 0);
