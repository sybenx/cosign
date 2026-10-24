// "Undo everything this site did": its access goes, every list it changed goes back to
// how it was before it touched it, and everything else it signed is deleted (copies kept).
//
//   (test servers running, fake phone paired)   node test/undo-site.e2e.ts

import { readFileSync } from 'node:fs';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { SignerClient, newSession } from '../src/client.ts';
import { Pool, sealTo, openFrom, Parts, KIND_MEMBER } from '../../server/net.ts';

const phone = JSON.parse(readFileSync('/tmp/cosign-fake-phone.json', 'utf8'));
const servers = phone.group.members.filter((m: any) => m.role === 'server');
const msgs: any[] = [];
const parts = new Parts(); // big state messages come in parts
const ctl = new Pool(phone.group.relays, e => { const m = parts.take(e.pubkey, openFrom(phone.sk, e)); if (m) msgs.push(m); });
ctl.start([{ kinds: [KIND_MEMBER], '#p': [phone.group.members.find((m: any) => m.idx === phone.idx).pk] }]);
const asPhone = (msg: object) => { for (const s of servers) ctl.publish(sealTo(phone.sk, s.pk, msg)); };
const toA = (msg: object) => ctl.publish(sealTo(phone.sk, servers[0].pk, msg));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const waitFor = async (pred: (m: any) => boolean, ms = 30000) => { const until = Date.now() + ms; while (Date.now() < until) { const m = msgs.find(pred); if (m) return m; await sleep(250); } };
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const archive = () => JSON.parse(readFileSync(new URL('../../server/test-data/a/archive.json', import.meta.url), 'utf8'));
const p = () => ['p', bytesToHex(randomBytes(32))];

async function connect(origin: string) {
  const t = bytesToHex(randomBytes(16));
  asPhone({ type: 'ticket', t, origin, expires: Math.floor(Date.now() / 1000) + 900 });
  await sleep(1500);
  const c = new SignerClient(newSession(phone.signer, phone.group.relays));
  await c.connect(t);
  return c;
}

await sleep(2000);
const good = await connect('good.test');
const baseline = [p(), p(), p()];
await good.signEvent({ kind: 3, content: '', tags: baseline });
await good.signEvent({ kind: 0, content: JSON.stringify({ name: 'me', about: 'the real one' }), tags: [] });

const bad = await connect('bad.test');
const badPk = latestSitePk('bad.test');
await bad.signEvent({ kind: 3, content: '', tags: [...baseline, p(), p()] });
await bad.signEvent({ kind: 3, content: '', tags: [...baseline, p(), p(), p()] });
await bad.signEvent({ kind: 0, content: JSON.stringify({ name: 'me', about: 'buy my coin' }), tags: [] });
for (let i = 0; i < 12; i++) await bad.signEvent({ kind: 1, content: `spam ${i}`, tags: [] });
for (let i = 0; i < 5; i++) await bad.signEvent({ kind: 7, content: '+', tags: [['e', bytesToHex(randomBytes(32))]] });

function latestSitePk(origin: string): string {
  const st = JSON.parse(readFileSync(new URL('../../server/test-data/a/state.json', import.meta.url), 'utf8'));
  return st.sites.filter((s: any) => s.origin === origin).at(-1).pk;
}

toA({ type: 'site_summary', pk: badPk });
const sum = await waitFor(m => m.type === 'site_summary' && m.pk === badPk);
check('the phone gets a summary first', sum?.total === 20 && sum?.deletable === 17 && sum?.lists?.length === 2, JSON.stringify(sum?.counts) + ' lists: ' + sum?.lists?.join(', '));

toA({ type: 'undo_site', pk: badPk });
const done = await waitFor(m => m.type === 'undone_site' && m.pk === badPk, 60000);
check('undo finishes', done?.restored === 2 && done?.deleted === 17, JSON.stringify(done));
const a = archive();
const follows = a['3'][0];
check('the follow list is back to before bad.test', JSON.stringify(follows.tags) === JSON.stringify(baseline), `${follows.tags.length} follows`);
check('the profile is back too', JSON.parse(a['0'][0].content).about === 'the real one');
const after = await bad.signEvent({ kind: 1, content: 'still here?', tags: [] }).catch(e => e);
check('bad.test has no access any more', String(after).includes('revoked'), String(after));
const good2 = await good.signEvent({ kind: 1, content: 'good.test is fine', tags: [] }).catch(e => e);
check('good.test is untouched', !!good2?.sig);

good.close(); bad.close();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
