// A paper's material (core §4.3, §7.2, core 14.21 §4.5), made by the TS reference: a base item and seed items for a
// fixed backup key K, release seeds and seeds; every port opens them with K, keeps each seed whose sha matches its
// redeal's `dk`, and computes the same pin `inner`.
// Run: node vectors/gen-material.ts > vectors/material.json
import { baseItem, seedItems, materialInner } from '../src/upkeep.ts';
import { bytesToHex, hexToBytes, shaHex } from '../src/bytes.ts';
import { pubOf } from '../src/event.ts';

const Ksk = hexToBytes('3c'.repeat(32)), K = { sk: Ksk, pub: pubOf(Ksk) };
const baseSeed = '5a'.repeat(32), paperSeed = '6b'.repeat(32), baseDk = '7c'.repeat(32);
const shares = new Map<number, bigint>([[5, 0x1234n], [6, 0xabcdefn]]);
const records: [string, string][] = Array.from({ length: 3 }, (_, k) => [String(k + 1).padStart(32, '0'), String(k + 1).repeat(64).slice(0, 64)]);
const base = baseItem(K, baseSeed, shares, baseDk, ['00'.repeat(16)]);
const seeds = seedItems(K, paperSeed, records);
console.log(JSON.stringify({
  note: 'base and seeds sealed to K (K_sk); open seeds with paper_seed; keep a seed only if sha256(seed) is dk_of[id]; inner = sha256(JCS([hash(base), ...hash(seeds)]))',
  K_sk: bytesToHex(Ksk), K: K.pub, base_seed: baseSeed, paper_seed: paperSeed, base_dk: baseDk,
  shares: [...shares].map(([i, s]) => [i, s.toString(16).padStart(64, '0')]), records,
  dk_of: Object.fromEntries(records.slice(0, 2).map(([id, seed]) => [id, shaHex(hexToBytes(seed))])),
  base, seeds, inner: materialInner(base, seeds),
}, null, 1));
