// Builds keykin/device for the browser: dist/keykin-device.js (ESM, the extension's import) and the self-test page
// (dist/selftest.html). Fails if anything on the device's path imports a Node module.
//   node browser/build.mjs
import { build } from 'esbuild';
import { cpSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const here = import.meta.dirname, out = join(here, '../dist');
mkdirSync(out, { recursive: true });
const noNode = { name: 'no-node', setup(b) { b.onResolve({ filter: /^node:/ }, (a) => ({ errors: [{ text: `${a.path} imported by ${a.importer}: the browser build has no Node modules` }] })); } };
const common = { bundle: true, format: 'esm', platform: 'browser', target: 'es2022', plugins: [noNode], logLevel: 'warning', sourcemap: true };
await build({ ...common, entryPoints: [join(here, 'index.ts')], outfile: join(out, 'keykin-device.js') });
await build({ ...common, entryPoints: [join(here, 'selftest.ts')], outfile: join(out, 'selftest.js') });
cpSync(join(here, '../frost-wasm-web/keykin_frost_bg.wasm'), join(out, 'keykin_frost_bg.wasm'));
writeFileSync(join(out, 'selftest.html'), '<!doctype html><meta charset="utf-8"><title>keykin selftest</title><body>running…</body><script type="module" src="selftest.js"></script>\n');
console.log('built', out);
