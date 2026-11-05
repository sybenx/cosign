// The `recovery` approval's backup signature (core §6.5, §4.4): what the backup key signs for a list, by the TS
// reference: detached("recovery", g, {list: approvalHash(placeholder list)}). Every port signs the same digest.
// Run: node vectors/gen-recovery-approval.ts > vectors/recovery-approval.json
import { approvalHash, placeholderList } from '../src/approval.ts';
import { detachedDigest } from '../src/codes.ts';
import { bytesToHex } from '../src/bytes.ts';

const g = '9a'.repeat(32), device = '8b'.repeat(32), lost = '7c'.repeat(32);
const list = [{ add: { key: device, kind: 'device', lock: null, salt: 0 } }] as any;
const removal = [{ remove: lost }, { redeal: { dealer: device } }] as any;
const one = (l: any) => ({ list: l, placeholder: placeholderList(l), hash: approvalHash(placeholderList(l)), digest: bytesToHex(detachedDigest('recovery', g, { list: approvalHash(placeholderList(l)) })) });
console.log(JSON.stringify({ note: 'digest = detached("recovery", g, {list: hash(placeholder(list))})', g, cases: [one(list), one(removal)] }, null, 1));
