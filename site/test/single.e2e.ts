// Single-server mode: your phone co-signs everyday things, the backup server steps in
// when the phone doesn't answer, and with neither the site gets a clear error. Also a
// follow list too big for one NIP-44 message.
//
//   (test servers running, fake phone paired)   node test/single.e2e.ts
//
// It stops and starts the fake phone and server B itself (test-data/ only).

import { readFileSync } from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const serverDir = new URL('../../server/', import.meta.url).pathname;
const portA = JSON.parse(readFileSync(serverDir + 'test-data/a/state.json', 'utf8')).port;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

const ctl = new Pool(phone.group.relays, () => {});
ctl.start([{ kinds: [KIND_MEMBER], '#p': ['0'.repeat(64)] }]);
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };

let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const time = async <T>(f: () => Promise<T>) => { const t = Date.now(); const v = await f(); return [v, Date.now() - t] as const; };
const lastSigned = async () => ((await (await fetch(`http://localhost:${portA}/status`)).json()).activity as any[]).map(a => a.text).find(t => t.startsWith('signed') || t.startsWith('did not sign')) ?? '';
const run = (args: string[]): ChildProcess => spawn('node', args, { cwd: serverDir, stdio: 'ignore' });
const kill = (pattern: string) => spawn('pkill', ['-f', pattern]);

await sleep(2000);
const t = bytesToHex(randomBytes(16));
asPhone({ type: 'ticket', t, origin: 'single.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);
const site = new SignerClient(newSession(phone.signer, phone.group.relays));
await site.connect(t);
const note = (text: string) => site.signEvent({ kind: 1, content: text, tags: [] });

const [n1, ms1] = await time(() => note('phone co-signs'));
check('a note signs, with the phone', verifyEvent(n1) && (await lastSigned()).includes('with Phone'), `${ms1} ms, ${await lastSigned()}`);

const big = Array.from({ length: 1500 }, () => ['p', bytesToHex(randomBytes(32))]);
const [f, ms2] = await time(() => site.signEvent({ kind: 3, content: '', tags: big }));
check('a 1500-follow list signs (in parts)', verifyEvent(f) && f.tags.length === 1500, `${ms2} ms, ${JSON.stringify(f).length} bytes`);

// The phone goes quiet: the backup steps in after 3 s, then straight away once the phone counts as gone.
kill('test/fake-phone.ts');
await sleep(1000);
const [n2, ms3] = await time(() => note('phone asleep'));
check('phone silent: the backup server signs after ~3 s', verifyEvent(n2) && (await lastSigned()).includes('with Server B') && ms3 >= 2500 && ms3 < 8000, `${ms3} ms`);

// Neither: a clear error after ~15 s.
kill('server.ts test-data/b');
await sleep(1000);
const [err, ms4] = await time(() => note('nobody there').then(() => null, e => e as Error));
check('phone and backup both gone: the site gets an error', !!err && /phone/i.test(err.message) && ms4 < 25_000, `${ms4} ms: ${err?.message}`);

// Back to normal.
run(['server.ts', 'test-data/b']);
run(['test/fake-phone.ts']);
await sleep(14_000);
const [n3, ms5] = await time(() => note('phone back'));
check('phone back: it co-signs again', verifyEvent(n3) && (await lastSigned()).includes('with Phone'), `${ms5} ms`);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
