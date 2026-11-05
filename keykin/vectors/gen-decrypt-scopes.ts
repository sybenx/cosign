// Doors §1's decrypt-to-self decisions for every port: an evidence store (kinds and encrypt records by the
// SHA-256 of each ciphertext's bytes) and cases (payload, plaintext, owner) with the scope TS decides.
// Run: node vectors/gen-decrypt-scopes.ts > vectors/decrypt-scopes.json
import * as nip44 from 'nostr-tools/nip44';
import { Evidence, scopeForDecrypt } from '../device/grants.ts';
import { newKey } from '../src/event.ts';
const g = 'ab'.repeat(32);
const ct = () => nip44.v2.encrypt('x', nip44.v2.utils.getConversationKey(newKey().sk, newKey().pub));
const ev = new Evidence();
const c = { list: ct(), wallet: ct(), both: ct(), planted: ct(), bare: ct(), dm: ct(), none: ct(), copy: ct() };
ev.event(10000, c.list); ev.encrypted(c.list, 'member');
ev.event(17375, c.wallet); ev.encrypted(c.wallet, 'member');
ev.event(30078, c.both); ev.event(10000, c.both); ev.encrypted(c.both, 'member');
ev.event(10000, c.planted, 'by:B'); ev.encrypted(c.planted, 'by:B');
ev.event(10003, c.bare);
ev.event(14, c.dm, 'by:A'); ev.encrypted(c.dm, 'by:A');
ev.event(10000, c.copy, 'by:S'); ev.encrypted(c.copy, 'member'); ev.event(30078, c.copy, 'member');
const list = JSON.stringify([['p', 'x'], ['t', 'y']]), wal = JSON.stringify({ mint: 'https://m', proofs: [] }), note = 'a private note';
const rumor = JSON.stringify({ kind: 14, pubkey: g, content: 'hi', tags: [], created_at: 1 });
const cases = [
  [c.list, list, 'by:A'], [c.list, JSON.stringify([['privkey', 'k']]), 'by:A'], [c.wallet, list, 'by:A'], [c.both, list, 'by:A'],
  [c.planted, list, 'by:A'], [c.planted, list, 'by:B'], [c.bare, list, 'by:A'], [c.bare, note, 'by:A'], [c.dm, note, 'by:A'],
  [c.none, list, 'by:A'], [c.none, wal, 'by:A'], [c.copy, list, 'by:S'], [c.none, rumor, 'by:A'], [c.none, note, 'by:A'], [c.list + ' ', list, 'by:A'],
].map(([payload, plaintext, owner]) => ({ payload, plaintext, owner, scope: scopeForDecrypt(g, g, plaintext, { payload, evidence: ev, owner }) }));
console.log(JSON.stringify({ note: 'scopeForDecrypt(g, g, plaintext, {payload, evidence, owner}) as the TS reference decides it', g, evidence: ev.dump(), cases }, null, 1));
