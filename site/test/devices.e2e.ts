// Adding a device: a new one shows a code, your phone vouches (with its lock), the phone
// and a server make its share by repair, and from then on it signs like any member.
//
//   (test servers running, fake phone paired)   node test/devices.e2e.ts

import { readFileSync, openSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const serverDir = new URL('../../server/', import.meta.url).pathname;
const stateA = () => JSON.parse(readFileSync(serverDir + 'test-data/a/state.json', 'utf8'));
const ctl = new Pool(phone.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
const toA = (msg: object) => ctl.publish(sealTo(phone.sk, servers[0].pk, msg));
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const lastSigned = async () => ((await (await fetch(`http://localhost:${stateA().port}/status`)).json()).activity as any[]).map(a => a.text).find(t => t.startsWith('signed')) ?? '';

// The new device shows its code.
const dev = spawn('node', ['test/fake-device.ts', 'Test tablet'], { cwd: serverDir });
let out = '';
dev.stdout.on('data', d => { out += d; });
while (!out.includes('JOIN ')) await sleep(200);
const uri = new URL(out.split('JOIN ')[1].split('\n')[0].replace('cosign:', 'cosign://'));
await sleep(2500);

const before = stateA().group.members.length;
const noLock = `${Date.now()}a`;
toA({ type: 'add_device', id: noLock, pk: uri.searchParams.get('pk'), name: 'Test tablet', relays: uri.searchParams.getAll('r'), lock: false });
await sleep(4000);
check('without the phone’s lock, nothing is added', stateA().group.members.length === before);

const t0 = Date.now();
toA({ type: 'add_device', id: `${Date.now()}b`, pk: uri.searchParams.get('pk'), name: 'Test tablet', relays: uri.searchParams.getAll('r'), lock: true });
while (!out.includes('JOINED') && Date.now() - t0 < 30000) await sleep(250);
check('with it, the tablet gets its share and joins', out.includes('JOINED'), `${Date.now() - t0} ms`);
await sleep(2000);
const added = stateA().group.members.find((m: any) => m.pk === uri.searchParams.get('pk'));
check('the server lists it as a member', !!added && added.idx === before + 1 && added.role === 'device');
const shareFile = JSON.parse(readFileSync('/tmp/cosign-fake-device.json', 'utf8'));
check('no server or phone ever had its share', !readFileSync(serverDir + 'test-data/a/state.json', 'utf8').includes(shareFile.share) && !readFileSync(serverDir + 'test-data/b/state.json', 'utf8').includes(shareFile.share) && !readFileSync('/tmp/cosign-fake-phone.json', 'utf8').includes(shareFile.share));

// It signs: with the phone gone, the server asks the tablet.
const t = bytesToHex(randomBytes(16));
asPhone({ type: 'ticket', t, origin: 'devices.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);
const site = new SignerClient(newSession(phone.signer, phone.group.relays));
await site.connect(t);
spawn('pkill', ['-f', 'test/fake-phone.ts']);
spawn('pkill', ['-f', 'server.ts test-data/b']);
await sleep(12000);
const ev = await site.signEvent({ kind: 3, content: '', tags: [['p', bytesToHex(randomBytes(32))]] }).catch(e => e);
check('the tablet co-signs when the phone is gone', verifyEvent(ev) && (await lastSigned()).includes('with Test tablet'), `${await lastSigned()}`);

spawn('node', ['server.ts', 'test-data/b'], { cwd: serverDir, stdio: 'ignore', detached: true }).unref();
spawn('node', ['test/fake-phone.ts'], { cwd: serverDir, stdio: ['ignore', openSync(serverDir + 'logs/test-phone.log', 'a'), openSync(serverDir + 'logs/test-phone.log', 'a')], detached: true }).unref();
dev.kill(); site.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
