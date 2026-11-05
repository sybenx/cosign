// Guard: the server runtime and its local stack name no live host and no public relay. Anything under
// deploy/, the Dockerfile, and the server and runtime code may reach only local names.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const files = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? files(p) : [p]; });
const LIVE = /syb\.lol|aaro\.cc|racknerd|cosign-cf|damus\.io|primal\.net|nos\.lol|nostr\.band|ntfy\.sh/i;
const LOCAL = new Set(['relay1', 'relay2', 'pushstub', '127.0.0.1', 'localhost', '[::1]']);

test('deploy/, the Dockerfile, server/ and runtime/ name no live host and dial only local names', () => {
  const scanned = [...files(join(root, 'deploy')), join(root, 'Dockerfile'), ...files(join(root, 'server')), ...files(join(root, 'runtime'))];
  assert.ok(scanned.length > 5);
  for (const f of scanned) {
    const text = readFileSync(f, 'utf8');
    assert.doesNotMatch(text, LIVE, `${f} names a live host`);
    for (const m of text.matchAll(/\b(wss?|https?):\/\/([A-Za-z0-9.\-\[\]:]+)/g)) {
      const host = m[2].replace(/:\d+$/, '').toLowerCase();
      assert.ok(LOCAL.has(host) || host.endsWith('.test') || host.endsWith('.invalid') || host === '' , `${f}: ${m[0]} is not a local name`);
    }
  }
});
