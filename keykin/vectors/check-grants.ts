// A port's grant event read by the TS reference: `node vectors/check-grants.ts <in.json>` with {g, maker,
// base_dk, data_key: {state, key}, events}; prints {set: <the set read, or null>}.
import { readFileSync } from 'node:fs';
import { readMaker, entryOk } from '../device/grants.ts';
import { hexToBytes } from '../src/bytes.ts';

const x = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const got = readMaker(x.g, x.maker, x.base_dk, (s) => (s === x.data_key.state ? hexToBytes(x.data_key.key) : null), x.events);
console.log(JSON.stringify({ set: got?.set ?? null, signed: got ? got.set.entries.every((e) => entryOk(x.g, e)) : false }));
