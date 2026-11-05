// The Keykin dry-run stack's one front door on a tailnet: TLS with the machine's Tailscale certificate, bound to its
// tailnet address only. /r1 and /r2 are the two relays (WebSocket), /s1../s3 the servers' HTTPS front doors; the
// relays, servers and push stub themselves listen on 127.0.0.1 only. Test use only (Keykin dry run, 2026-11).
//   node proxy.mjs <bind address> <port> <cert.crt> <cert.key>
import { createServer, request } from 'node:https';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { readFileSync } from 'node:fs';

const [bind, port, crt, key] = process.argv.slice(2);
if (!/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+$/.test(bind ?? '')) { console.error('bind: a tailnet (100.64.0.0/10) address only'); process.exit(2); }
const routes = { '/r1': 7781, '/r2': 7782, '/s1': 8711, '/s2': 8712, '/s3': 8713 };
const route = (url) => { const p = Object.keys(routes).find((r) => url === r || url.startsWith(r + '/') || url.startsWith(r + '?')); return p ? { port: routes[p], path: url.slice(p.length) || '/' } : null; };
const srv = createServer({ cert: readFileSync(crt), key: readFileSync(key) }, (q, s) => {
  const r = route(q.url ?? '');
  if (!r) { s.writeHead(404); s.end('not here\n'); return; }
  const up = httpRequest({ host: '127.0.0.1', port: r.port, path: r.path, method: q.method, headers: { ...q.headers, host: `127.0.0.1:${r.port}`, 'x-forwarded-for': q.socket.remoteAddress } }, (u) => { s.writeHead(u.statusCode ?? 502, u.headers); u.pipe(s); });
  up.on('error', () => { s.writeHead(502); s.end(); });
  q.pipe(up);
});
// WebSocket upgrades: the request line and headers re-sent to the relay, then bytes both ways.
srv.on('upgrade', (q, sock, head) => {
  const r = route(q.url ?? '');
  if (!r || !String(q.url).startsWith('/r')) { sock.destroy(); return; }
  const up = connect(r.port, '127.0.0.1', () => {
    const hs = [`${q.method} ${r.path} HTTP/1.1`, ...Object.entries({ ...q.headers, host: `127.0.0.1:${r.port}` }).map(([k, v]) => `${k}: ${v}`), '', ''].join('\r\n');
    up.write(hs); if (head?.length) up.write(head);
    sock.pipe(up).pipe(sock);
  });
  up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
});
srv.listen(Number(port), bind, () => console.log(JSON.stringify({ proxy: `https://${bind}:${port}`, routes })));
void request;
