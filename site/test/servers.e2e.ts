// Finding servers (site/src/servers.ts, COSIGN.md §9.5): announcements and operator lists
// checked against each other, picking one fast server per operator; then a live shared
// server announcing itself and answering a ping.
//
//   node test/servers.e2e.ts      (starts and stops a host itself, in server/test-servers/)
//
// The live part publishes one announcement from a throwaway host key, with no operator
// list naming it (so no client would ever pick it), and deletes it at the end.

import { readFileSync, openSync, mkdirSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { finalizeEvent, generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure';
import { SimplePool } from 'nostr-tools/pool';
import { hexToBytes } from '@noble/hashes/utils.js';
import { announcement, operatorServers, parseAnnouncement, verify, findServers, pickServers, sharedOperators, relayQuery, pingHost, type Server } from '../src/servers.ts';

const serverDir = new URL('../../server/', import.meta.url).pathname;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (label: string, ok: boolean, extra = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${extra ? ' — ' + extra : ''}`); if (!ok) failures++; };
const key = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk) }; };

// --- Offline: who counts, and who gets picked ---------------------------------------------

const opA = key(), opB = key(), opC = key(), opD = key();
const [a1, a2, b1, c1, d1, x1] = Array.from({ length: 6 }, key);
const ann = (h: ReturnType<typeof key>, op: string, enroll: 'open' | 'invite' = 'open') =>
  finalizeEvent(announcement({ relays: ['wss://relay.example'], https: null, enroll, version: 'test', operator: op }), h.sk);
const anns = [ann(a1, opA.pk), ann(a2, opA.pk), ann(b1, opB.pk), ann(c1, opC.pk, 'invite'), ann(d1, opD.pk), ann(x1, opB.pk)];
const lists = [
  finalizeEvent(operatorServers([a1.pk, a2.pk]), opA.sk),
  finalizeEvent(operatorServers([b1.pk]), opB.sk), // not x1: it only claims opB
  finalizeEvent(operatorServers([c1.pk]), opC.sk),
  // opD lists nothing
];
const all = verify(anns.map(e => parseAnnouncement(e)!), lists);
const v = (h: { pk: string }) => all.find(s => s.pk === h.pk)!.verified;
check('a server counts as its operator’s when both name each other', v(a1) && v(a2) && v(b1) && v(c1));
check('a server claiming an operator that doesn’t list it doesn’t', !v(x1) && !v(d1));
// From JSON, as a relay hands it over (a copy of the object would carry nostr-tools' cached check).
const forged = { ...JSON.parse(JSON.stringify(anns[0])), content: anns[0].content.replace('relay.example', 'evil.example') } as Event;
check('a tampered announcement is refused', parseAnnouncement(forged) === null);

const speed = new Map([[a1.pk, 80], [a2.pk, 20], [b1.pk, 50], [c1.pk, 5], [d1.pk, 1], [x1.pk, 2]]);
const picked = await pickServers(all, { ping: async s => speed.get(s.pk) ?? null });
check('one per operator first (fastest), only verified and open; then fills from the same operators', picked.map(s => s.pk).join() === [a2.pk, b1.pk, a1.pk].join(), picked.map(s => `${s.operator.slice(0, 6)}:${s.ms}`).join(' '));
check('and says which operator runs more than one', JSON.stringify(sharedOperators(picked)) === JSON.stringify([opA.pk]));
const distinct = await pickServers(all, { ping: async s => speed.get(s.pk) ?? null, distinct: true });
check('with distinct, never two from one operator', distinct.map(s => s.pk).join() === [a2.pk, b1.pk].join());
const without = await pickServers(all, { ping: async s => s.pk === a2.pk ? null : speed.get(s.pk) ?? null, distinct: true });
check('a server that doesn’t answer is skipped for its operator’s next', without.map(s => s.pk).join() === [b1.pk, a1.pk].join());
const own = await pickServers(all, { ping: async s => speed.get(s.pk) ?? null, exclude: [opA.pk] });
check('an operator left out isn’t picked at all', own.map(s => s.pk).join() === b1.pk);

const seeded = await findServers({ query: async () => [], seeds: [{ pubkey: b1.pk, relays: ['wss://relay.example'], operator: opB.pk }] });
check('with nothing found, the seed list still gives servers', seeded.length === 1 && seeded[0].verified && seeded[0].pk === b1.pk);
const merged = await findServers({ query: async (_r, f: any) => f.kinds[0] === 30243 ? anns : lists, seeds: [] });
check('found on relays: announcements and lists together', merged.length === 6 && merged.filter(s => s.verified).length === 4);

// --- Live: a shared server announces itself and answers a ping ----------------------------

execFileSync('rm', ['-rf', serverDir + 'test-servers']);
mkdirSync(serverDir + 'logs', { recursive: true });
const log = openSync(serverDir + 'logs/servers-host.log', 'w');
const op = key();
const host = spawn('node', ['server.ts', '--root', 'test-servers/h', '--port', '8996'], {
  cwd: serverDir, stdio: ['ignore', log, log],
  env: { ...process.env, COSIGN_ENROLL: 'open', COSIGN_OPERATOR: op.pk, COSIGN_HTTPS: 'https://cosign.test' },
});
await sleep(3000);
const hostCfg = JSON.parse(readFileSync(serverDir + 'test-servers/h/host.json', 'utf8'));
let mine: Server | null = null;
for (let i = 0; i < 8 && !mine; i++) {
  await sleep(2500);
  const found = await relayQuery(4000)(hostCfg.relays, { kinds: [30243], authors: [hostCfg.pk] });
  mine = found.map(parseAnnouncement).find(Boolean) ?? null;
}
check('the server announces itself, signed by its host key', !!mine && mine.operator === op.pk && mine.enroll === 'open' && mine.https === 'https://cosign.test' && /^\d+\.\d+/.test(mine.version), JSON.stringify(mine && { relays: mine.relays, version: mine.version }));
if (mine) {
  check('its operator’s list makes it count', verify([mine], [finalizeEvent(operatorServers([mine.pk]), op.sk)])[0].verified);
  const ms = await pingHost(mine);
  check('it answers a ping', ms !== null, `${ms} ms`);
  const relays = [...new Set([...hostCfg.relays, 'wss://syb.lol', 'wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.damus.io'])];
  const p = new SimplePool();
  // Clean up after ourselves: no test server left announced. An empty announcement first,
  // for relays that keep a replaceable event but ignore deletions, then the deletion.
  const empty = finalizeEvent({ kind: 30243, created_at: Math.floor(Date.now() / 1000), tags: [['d', 'cosign-server']], content: JSON.stringify({ relays: [] }) }, hexToBytes(hostCfg.sk));
  await Promise.allSettled(p.publish(relays, empty));
  const del = finalizeEvent({ kind: 5, created_at: Math.floor(Date.now() / 1000) + 1, tags: [['a', `30243:${mine.pk}:cosign-server`], ['k', '30243']], content: 'test server' }, hexToBytes(hostCfg.sk));
  await Promise.allSettled(p.publish(relays, del));
  p.close(relays);
}

host.kill();
console.log(failures ? `${failures} failed` : 'all passed');
process.exit(failures ? 1 : 0);
