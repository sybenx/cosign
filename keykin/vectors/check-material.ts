// The TS reference reads a paper's material another port made: `node vectors/check-material.ts <in.json>` with
// {K_sk, base_seed, paper_seed, base, seeds, inner, records}. Prints {ok, base, seeds, inner} or exits 1.
import { readFileSync } from 'node:fs';
import { openItem, itemHash } from '../src/redeal.ts';
import { materialInner, unpackSeeds } from '../src/upkeep.ts';
import { hexToBytes, sha } from '../src/bytes.ts';
import { schnorrVerify, pubOf } from '../src/event.ts';

const x = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const Ksk = hexToBytes(x.K_sk), K = pubOf(Ksk);
const signed = (it: any) => it.to === K && schnorrVerify(it.sig, sha(itemHash(it)), K);
const base = openItem(x.base, x.base_seed, { backupSk: Ksk });
const seeds = x.seeds.flatMap((it: any) => unpackSeeds(openItem(it, x.paper_seed, { backupSk: Ksk })));
const ok = signed(x.base) && x.seeds.every(signed) && materialInner(x.base, x.seeds) === x.inner
  && JSON.stringify(seeds) === JSON.stringify([...x.records].sort((a: any, b: any) => (a[0] < b[0] ? -1 : 1)));
console.log(JSON.stringify({ ok, base, seeds: seeds.length, inner: materialInner(x.base, x.seeds) }));
process.exit(ok ? 0 : 1);
