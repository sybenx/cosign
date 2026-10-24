// Deletions, which Nostr can't take back: a copy is kept first, each one waits 10 s
// with Undo on the phone, and a burst from one site gets one approval for all of it.
//
//   (test servers running, fake phone paired and approving)   node test/deletion.e2e.ts

import { readFileSync } from 'node:fs';
import { verifyEvent } from 'nostr-tools/pure';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const savedFile = new URL('../../server/test-data/a/saved.jsonl', import.meta.url);
let cancelNext = false;
const parts = new Parts(); // big state messages come in parts
const ctl = new Pool(phone.group.relays, (e) => {
  const m = parts.take(e.pubkey, openFrom(phone.sk, e));
  if (m?.type === 'deleting' && cancelNext) { cancelNext = false; for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, { type: 'cancel_batch', batch: m.batch })); }
});
ctl.start([{ kinds: [KIND_MEMBER], '#p': [phone.group.members.find((m: any) => m.idx === phone.idx).pk] }]);
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const saved = () => { try { return readFileSync(savedFile, 'utf8'); } catch { return ''; } };

await sleep(2000);
const t = bytesToHex(randomBytes(16));
asPhone({ type: 'ticket', t, origin: 'delete.test', expires: Math.floor(Date.now() / 1000) + 900 });
await sleep(1500);
const site = new SignerClient(newSession(phone.signer, phone.group.relays));
await site.connect(t);
const notes = [];
for (let i = 0; i < 8; i++) notes.push(await site.signEvent({ kind: 1, content: `note ${i} to delete`, tags: [] }));
const del = (ids: string[]) => site.signEvent({ kind: 5, content: '', tags: ids.map(id => ['e', id]).concat([['k', '1']]) });

let t0 = Date.now();
const one = await del([notes[0].id]).catch(e => e);
check('one deletion waits about 10 s, then signs', verifyEvent(one) && Date.now() - t0 >= 9500, `${Date.now() - t0} ms`);
check('…and a copy of the note was kept first', saved().includes(notes[0].id));

t0 = Date.now();
const burst = await Promise.all(notes.slice(1, 7).map(n => del([n.id]).catch(e => e)));
check('six deletions in a burst: one approval, all signed', burst.every(e => verifyEvent(e)), `${Date.now() - t0} ms`);
check('…all six kept', notes.slice(1, 7).every(n => saved().includes(n.id)));
const approvals = readFileSync(new URL('../../server/logs/test-phone.log', import.meta.url), 'utf8').split('\n').filter(l => l.includes('APPROVED batch: Delete 6 events for delete.test'));
check('…and the phone was asked once', approvals.length === 1, approvals[0]);

cancelNext = true;
t0 = Date.now();
const stopped = await del([notes[7].id]).catch(e => e);
check('Undo on the phone stops a deletion', String(stopped).includes('stopped this deletion'), `${Date.now() - t0} ms: ${stopped}`);

site.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
