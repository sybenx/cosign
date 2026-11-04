// Device policy §1 metadata vectors, for every port: device B's snapshot (before); device A's metadata events,
// published after A encrypted a list to the account and signed it; the list's ciphertext and plaintext, and
// what B decides for it after reading A's metadata (lists) and before (private-data). Also the data key, test
// material only, so a port's own snapshot can be read back by the TS reference (vectors/check-metadata.ts).
// Run: node vectors/gen-metadata.ts > vectors/metadata.json
import { create, invite } from '../sim/account.ts';
import { scopeForDecrypt } from '../device/grants.ts';
import { bytesToHex } from '../src/bytes.ts';

const acc = await create();
const A = acc.A;
const B = await invite(acc, A, (l) => A.approveLock(l));
await B.fetch(); await A.fetch();
const before = B.snapshot();
const plaintext = JSON.stringify([['p', 'ab'.repeat(32)], ['t', 'nostr']]);
const ciphertext = await A.nip44(A.g, plaintext, true);
await A.sign({ kind: 10000, content: ciphertext, tags: [] });
const events = await A.meta.publish();
const without = scopeForDecrypt(B.g, B.g, plaintext, { payload: ciphertext, evidence: B.evidence, owner: 'x:y' });
await B.meta.fetch();
const withMeta = scopeForDecrypt(B.g, B.g, plaintext, { payload: ciphertext, evidence: B.evidence, owner: 'x:y' });
const dk = B.dataKeys.current();
console.log(JSON.stringify({ note: 'B reads A\'s metadata events, then judges the decrypt of `ciphertext` to self.',
  maker: A.kp.pub, device: B.kp.pub, before, events, plaintext, ciphertext, without, with: withMeta,
  base_dk: B.baseDk, data_key: { state: dk.state, key: bytesToHex(dk.key) } }, null, 1));
