// A live Cosign account on local servers, with a bunker:// URL printed, so standard NIP-46
// clients can be pointed at it by hand. Stays up until killed.
import { readFileSync, openSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { Pool, sealParts, KIND_MEMBER } from '../../server/net.ts';

const serverDir = '/Users/aaronherbst/cosign/server/';
const phoneFile = '/tmp/cosign-nip46-phone.json';
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const hex = (n = 8) => bytesToHex(randomBytes(n));
const kids: ChildProcess[] = [];
process.on('SIGINT', () => { for (const k of kids) k.kill(); process.exit(0); });
process.on('SIGTERM', () => { for (const k of kids) k.kill(); process.exit(0); });

spawnSync('pkill', ['-f', 'server.ts test-nip46/']);
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
for (let i = 0; i < 120 && !existsSync(phoneFile); i++) await sleep(1000);
await sleep(6000);
const ph = JSON.parse(readFileSync(phoneFile, 'utf8'));
const servers = ph.group.members.filter((m: any) => m.role === 'server');
const ctl = new Pool(ph.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
await sleep(2000);
const t = hex(16);
for (const s of servers) for (const e of sealParts(ph.sk, s.pk, { type: 'ticket', t, origin: process.env.ORIGIN ?? 'nak.test', expires: Math.floor(Date.now() / 1000) + 3600 })) ctl.publish(e);
await sleep(2500);
const relays = (ph.group.relays as string[]).map(r => `relay=${encodeURIComponent(r)}`).join('&');
console.log(`NPUB ${ph.group.npub}`);
console.log(`GROUPX ${ph.group.groupX}`);
console.log(`SIGNER ${ph.signer}`);
console.log(`TICKET ${t}`);
console.log(`BUNKER bunker://${ph.signer}?${relays}&secret=${t}`);
console.log('READY');
await new Promise(() => {});
