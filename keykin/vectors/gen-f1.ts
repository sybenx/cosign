// F1's shutdown notices (Server profile §4.1), signed by the TS reference: a pushed notice and the live answer to a
// `notice_get`, for a fixed host and seat. Every port checks them as F1Watch does.
// Run: node vectors/gen-f1.ts > vectors/f1.json
import { signNotice, signAnswer } from '../src/f1.ts';
import { hexToBytes } from '../src/bytes.ts';
import { pubOf } from '../src/event.ts';

const g = 'ab'.repeat(32), hostSk = hexToBytes('51'.repeat(32)), host = { sk: hostSk, pub: pubOf(hostSk) };
const member = pubOf(hexToBytes('62'.repeat(32)));
console.log(JSON.stringify({
  note: 'pushed: a notice with no re; answer: the live answer to notice_get re; both host-signed (detached shutdown / shutdown-answer)',
  g, host: host.pub, member,
  pushed: signNotice(g, host, { shutdown: 1_900_000_000, seq: 5, member }),
  answer: signAnswer(g, host, { shutdown: 1_900_000_000, seq: 6, member }, 'cd'.repeat(16)),
  cancel: signAnswer(g, host, { shutdown: null, seq: 7, member }, 'cd'.repeat(16)),
}, null, 1));
