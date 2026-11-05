// keykin/device for the browser (the extension's member): the bundle builds with no Node module anywhere on its path
// (browser/build.mjs refuses one). The bundle itself is run in a real browser by dist/selftest.html (browser/serve.mjs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
test('keykin/device bundles for the browser with no Node modules', { skip: !existsSync(join(root, 'frost-wasm-web/keykin_frost_bg.wasm')) && 'build frost for the web first (browser/README)' }, () => {
  const r = spawnSync(process.execPath, [join(root, 'browser/build.mjs')], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  for (const f of ['keykin-device.js', 'selftest.js', 'selftest.html', 'keykin_frost_bg.wasm']) assert.ok(existsSync(join(root, 'dist', f)), f);
});
