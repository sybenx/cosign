// The Keykin server process. Configuration is the environment only, with no defaults that reach a
// live host: it refuses to start without KEYKIN_RELAYS, publishes nowhere else, and pushes only to
// KEYKIN_PUSH_HOSTS.
//
//   KEYKIN_RELAYS      comma-separated relay URLs (required)
//   KEYKIN_DATA        sealed records (default /data); may be snapshotted
//   KEYKIN_KEYS        the key ring (default /keys); never backed up (core §7.3)
//   KEYKIN_HTTPS       this server's public HTTPS URL, written into enrol replies
//   KEYKIN_OPERATOR    the operator's npub hex (default: the host key)
//   KEYKIN_NAME        a label for logs
//   KEYKIN_PORT        HTTP port (default 8711); KEYKIN_BIND (default 127.0.0.1)
//   KEYKIN_PUSH_HOSTS  comma-separated push gateway hosts
//   KEYKIN_TRUST_PROXY 1 to take the client IP from X-Forwarded-For
//   KEYKIN_PUSH_HTTP   1 to accept plain-http push addresses: a local test gateway only, never in a deployment

import { RelayNet } from '../runtime/relay.ts';
import { FileStore, KeyRing } from '../runtime/store.ts';
import { Host } from './host.ts';
import { PushSender } from './push.ts';
import { serveHttp } from './http.ts';

const env = process.env;
const list = (v?: string) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const relays = list(env.KEYKIN_RELAYS);
// Tests only: a short recovery and hold wait, for a local test stack whose members all use the same.
if (env.KEYKIN_TEST_W) { (await import('../src/approval.ts')).setTestW(Number(env.KEYKIN_TEST_W)); console.error(JSON.stringify({ test_w: Number(env.KEYKIN_TEST_W) })); }
if (!relays.length) { console.error('KEYKIN_RELAYS is required: the server has no relays of its own.'); process.exit(2); }
for (const r of relays) if (!/^wss?:\/\//.test(r)) { console.error(`not a relay URL: ${r}`); process.exit(2); }

const store = new FileStore(env.KEYKIN_DATA ?? '/data', new KeyRing(env.KEYKIN_KEYS ?? '/keys'));
const net = new RelayNet({ relays, log: (s) => console.log(JSON.stringify({ relay: s })) });
await net.connect();
let host: Host;
// A gone address is dropped and the seat saved, so it doesn't come back after a restart (review 10 L2).
net.pushes = new PushSender({ allow: list(env.KEYKIN_PUSH_HOSTS), onGone: (url) => { for (const n of host.nodes.values()) for (const [m, a] of n.pushReg.dump()) if (a.addrs.some((x) => x.url === url)) { n.pushReg.dead(m, url); host.save(n); } } });
host = new Host({ net, hosting: net, store, profile: { https: env.KEYKIN_HTTPS ?? '', relays, operator: env.KEYKIN_OPERATOR ?? '', name: env.KEYKIN_NAME ?? 'keykin', allowHttpPush: env.KEYKIN_PUSH_HTTP === '1' } });
host.log = (s) => console.log(JSON.stringify({ host: s }));
host.start();
const http = serveHttp({ net, limits: host.limits, port: Number(env.KEYKIN_PORT ?? 8711), bind: env.KEYKIN_BIND ?? '127.0.0.1', trustProxy: env.KEYKIN_TRUST_PROXY === '1',
  status: () => ({ host: host.key.pub, relays: net.status() }) });
console.log(JSON.stringify({ started: true, host: host.key.pub, seats: host.nodes.size, relays, port: Number(env.KEYKIN_PORT ?? 8711) }));

const stop = () => { http.close(); net.close(); process.exit(0); };
process.on('SIGTERM', stop); process.on('SIGINT', stop);
