// Grant-store vectors (Doors §1–§2), for every port: a device's snapshot (B), the grant events another device
// (A) published (one grant made and signed out, two live, one large enough to need parts... kept small here),
// and what B lists after reading them. Also the account's base data key and current data key, test material
// only, so a port can check that what it publishes reads back in the TS reference (vectors/check-grants.ts).
// Run: node vectors/gen-grants.ts > vectors/grants.json
import { create, invite } from '../sim/account.ts';
import { bytesToHex } from '../src/bytes.ts';

const acc = await create();
const A = acc.A;
const B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
await B.fetch();
const before = B.snapshot();
const site = (n: string, scopes: any[]) => ({ site: `https://${n}.example`, says: n, door: 'nip07' as const, connection: 'chrome', scopes });
A.grants.make(site('coracle', ['sign-in', 'post']));
const gone = A.grants.make(site('gone', ['sign-in']));
A.grants.make(site('lists-app', ['sign-in', 'post', 'lists']));
A.grants.end(A.kp.pub, gone.id);
const events = await A.grants.publish();
await B.grants.fetch();
const dk = A.dataKeys.current();
console.log(JSON.stringify({
  note: 'B (before) reads A\'s grant events: it lists `listed` (says, scopes), never the ended one.',
  maker: A.kp.pub, device: B.kp.pub, before, events,
  listed: B.grants.all().map((e) => ({ says: e.says, scopes: e.scopes, by: e.by })).sort((a, b) => (a.says < b.says ? -1 : 1)),
  ended: [gone.id], base_dk: B.baseDk, data_key: { state: dk.state, key: bytesToHex(dk.key) },
}, null, 1));
