// Serves dist/ on 127.0.0.1 for the browser self-test (wasm with its MIME type).   node browser/serve.mjs [port]
import { createServer } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { join, extname, normalize } from 'node:path';
const dir = join(import.meta.dirname, '../dist'), port = Number(process.argv[2] ?? 8765);
const types = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.map': 'application/json' };
createServer((q, s) => {
  const path = decodeURIComponent((q.url ?? '/').split('?')[0]);
  const p = normalize(join(dir, path === '/' ? 'selftest.html' : path));
  let file = false; try { file = statSync(p).isFile(); } catch {}
  if (!p.startsWith(dir) || !file) { s.writeHead(404); s.end(); return; }
  s.writeHead(200, { 'content-type': types[extname(p)] ?? 'application/octet-stream' }); s.end(readFileSync(p));
}).listen(port, '127.0.0.1', () => console.log(`http://127.0.0.1:${port}/selftest.html`));
