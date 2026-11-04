// A port's re-issued paper item (core §6.7.6) checked by the TS reference, as a server and the paper's
// holder check it: `node vectors/check-reissue.ts <in.json>` with {g, redeal, item, K, devices, backup_seat,
// release, paper_sk}; prints {check: null | <refusal>, opens: <the values match the clear ones>}.
import { readFileSync } from 'node:fs';
import { checkReissue, openItem } from '../src/redeal.ts';
import { hexToBytes } from '../src/bytes.ts';
import { mul, scalarFrom, compHex } from '../src/curve.ts';

const x = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const check = checkReissue(x.g, x.redeal, x.item, x.K, (k: string) => x.devices.includes(k), x.backup_seat);
let opens = false;
try {
  const v = openItem(x.item, x.release, { backupSk: hexToBytes(x.paper_sk) });
  opens = v.redeal === x.redeal.id && JSON.stringify(v.b) === JSON.stringify(x.backup_seat) && v.d.every((d: string, k: number) => compHex(mul(scalarFrom(d))) === x.item.clear[k]);
} catch { /* opens stays false */ }
console.log(JSON.stringify({ check, opens }));
