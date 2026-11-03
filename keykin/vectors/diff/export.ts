// Writes ../negative.json from probes.json: every probe both implementations decide alike, as
// { area, name, input, expect }, for the spec's shared negative vectors (core §9.5, §14).
// Run after compare.ts reports 0 disagreements: node export.ts
import { readFileSync, writeFileSync } from 'node:fs';
const here = new URL('.', import.meta.url).pathname;
const probes = JSON.parse(readFileSync(here + 'probes.json', 'utf8'));
const kt = JSON.parse(readFileSync(here + 'kt-results.json', 'utf8'));
// Key order is not a difference (as compare.ts).
const canon = (v: any): any => Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v;
const same = (a: unknown, b: unknown) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));
const out = probes.map((p: any, k: number) => {
  if (!same(p.ts, kt[k])) throw new Error(`probe ${k} (${p.area} ${p.name}) differs; fix it before exporting`);
  return { area: p.area, name: p.name, input: p.input, expect: canon(p.ts) };
});
writeFileSync(here + '../negative.json', JSON.stringify({
  note: 'Keykin Core negative and edge vectors (TS and Kotlin agree on every one). expect is a value, "ok", or "refuse:<code>". Areas: event_id (text -> §9.5 reader, rumor shape, NIP-01 id), jcs (text -> reader -> JCS), utf8 (hex bytes -> fatal UTF-8 -> reader -> JCS), b64u, b64 (string -> hex bytes), schnorr, lock (§6.1), destructive (§5.8), lifetime (§5.6), record (§3.4), membership (§3, §6.7), slip39 (Backup §3).',
  vectors: out }, null, 1) + '\n');
console.log(`${out.length} vectors written`);
