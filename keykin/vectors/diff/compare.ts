// Prints every probe where the Kotlin result differs from the TypeScript one.
// Run: node compare.ts [--all]
import { readFileSync } from 'node:fs';
const probes = JSON.parse(readFileSync(new URL('./probes.json', import.meta.url), 'utf8'));
const kt = JSON.parse(readFileSync(new URL('./kt-results.json', import.meta.url), 'utf8'));
const canon = (v: any): any => Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v;
const all = process.argv.includes('--all');
let n = 0;
probes.forEach((p: any, k: number) => {
  const a = canon(p.ts), b = canon(kt[k]);
  const same = JSON.stringify(a) === JSON.stringify(b);
  if (same && !all) return;
  if (!same) n++;
  if (a && typeof a === 'object' && b && typeof b === 'object') {
    const diff = Object.keys({ ...a, ...b }).filter((f) => JSON.stringify(a[f]) !== JSON.stringify(b[f]));
    console.log(`${same ? 'same' : 'DIFF'} [${p.area}] ${p.name}`); for (const f of diff) console.log(`    ${f}: ts=${JSON.stringify(a[f])}\n    ${' '.repeat(f.length)}  kt=${JSON.stringify(b[f])}`);
  } else console.log(`${same ? 'same' : 'DIFF'} [${p.area}] ${p.name}\n    ts=${JSON.stringify(a)}\n    kt=${JSON.stringify(b)}`);
});
console.log(`${n} of ${probes.length} probes differ`);
