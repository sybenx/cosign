// Serves public/ on http://localhost:8790. Nothing else.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
const root = join(import.meta.dirname, 'public');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.map': 'application/json' };
createServer(async (req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  try {
    const file = join(root, path === '/' ? 'index.html' : path.replace(/^\/+/, ''));
    if (!file.startsWith(root)) throw 0;
    res.setHeader('content-type', types[extname(file)] ?? 'application/octet-stream');
    res.end(await readFile(file));
  } catch { res.statusCode = 404; res.end(); }
}).listen(Number(process.env.PORT ?? 8790), '127.0.0.1', () => console.log('http://localhost:' + (process.env.PORT ?? 8790)));
