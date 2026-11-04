// HTTPS for a Keykin server (core §9.2 SHOULD, Server profile §3): the same sealed wraps as over relays,
// POSTed one or more at a time, answered with the wraps of the reply. TLS is the reverse proxy's. Junk
// (unparseable, not addressed to a hosted key, not decryptable) counts against the source IP.

import { createServer, type IncomingMessage, type Server } from 'node:http';
import { strictJson } from '../src/bytes.ts';
import type { RelayNet } from '../runtime/relay.ts';
import type { Limits } from './limits.ts';
import type { NostrEvent } from '../src/event.ts';

const MAX_BODY = 640 * 1024;
const read = (req: IncomingMessage) => new Promise<string>((res, rej) => {
  let n = 0; const chunks: Buffer[] = [];
  req.on('data', (c: Buffer) => { n += c.length; if (n > MAX_BODY) { rej(new Error('too_large')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => res(Buffer.concat(chunks).toString('utf8'))); req.on('error', rej);
});

export function serveHttp(o: { net: RelayNet; limits: Limits; port: number; bind: string; trustProxy?: boolean; status?: () => unknown }): Server {
  const server = createServer(async (req, res) => {
    const ip = (o.trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() : '') || req.socket.remoteAddress || '?';
    const send = (code: number, body: unknown) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
    try {
      if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true, ...(o.status?.() as object ?? {}) });
      if (req.method !== 'POST' || req.url !== '/v1/wrap') return send(404, { error: 'not_found' });
      let wraps: NostrEvent[];
      try { const x = strictJson(await read(req)); wraps = Array.isArray(x) ? x : [x]; } catch { o.limits.junk(ip, o.net.now); return send(400, { error: 'malformed' }); }
      if (wraps.length > 32) return send(400, { error: 'too_many' });
      const out: NostrEvent[] = [];
      for (const w of wraps) {
        const to = Array.isArray(w?.tags) ? w.tags.find((t) => t[0] === 'p')?.[1] : undefined;
        if (typeof to !== 'string' || !o.net.hosted.has(to)) { if (!o.limits.junk(ip, o.net.now)) return send(429, { error: 'rate_limited' }); continue; }
        const r = await o.net.take(to, w, { ip });
        if (r) out.push(...o.net.wrapsFor(r.from, r.to, r.answer));
      }
      return send(200, out);
    } catch { return send(500, { error: 'internal' }); }
  });
  server.listen(o.port, o.bind);
  return server;
}
