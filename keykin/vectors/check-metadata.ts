// A port's metadata events read by the TS reference: `node vectors/check-metadata.ts <in.json>` with {g, maker,
// base_dk, data_key: {state, key}, events}; prints {owners, kinds}: the records it took, by count.
import { readFileSync } from 'node:fs';
import { MetaStore } from '../device/metadata.ts';
import { hexToBytes } from '../src/bytes.ts';
const x = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const store = new MetaStore({ g: x.g, kp: { pub: '00'.repeat(32), sk: new Uint8Array(32) }, baseDk: x.base_dk, now: Math.floor(Date.now() / 1000),
  currentDevices: () => new Set([x.maker]), dataKey: () => ({ state: x.data_key.state, key: hexToBytes(x.data_key.key) }),
  keyFor: (s: string) => (s === x.data_key.state ? hexToBytes(x.data_key.key) : null),
  sign: async () => { throw new Error('read only'); }, publish: async () => {}, query: async () => ({ events: x.events, answered: 1, asked: 1 }) });
await store.fetch();
const ev = store.evidence();
console.log(JSON.stringify({ owners: [...ev.owners.values()].reduce((n, s) => n + s.size, 0), kinds: [...ev.kinds.values()].reduce((n, s) => n + s.size, 0) }));
