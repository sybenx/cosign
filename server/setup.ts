// One-time setup: make a key, split it 2-of-3, write a state file for each server.
//
//   node setup.ts                 fresh throwaway key
//   node setup.ts --nsec nsec1... split a key you already have
//   node setup.ts --force         overwrite existing data/
//   node setup.ts --dir test-data --port 8721   a second group beside it, for tests
//   node setup.ts --dir /data --relays wss://syb.lol,wss://nos.lol   (in a container)
//   node setup.ts --weighted      no key yet: your phone and the servers make one together
//
// Share 1 goes to server A, share 2 to server B, and share 3 waits on server A
// until your phone scans A's pairing code. Once the phone has it, A deletes it.
// This script sees all three shares at once: that is what a trusted dealer is.
//
// --weighted: nobody sees the key, ever. Your phone holds 3 shares and each server 1,
// and it takes 4 to sign, so your phone and either server can, and the two servers
// can't. The key is made (dkg.ts) when your phone scans A's code.

import { existsSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { nip19 } from 'nostr-tools';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { deal } from './frost.ts';
import { pubOf } from './net.ts';

const args = process.argv.slice(2);
const force = args.includes('--force');
const nsecArg = args[args.indexOf('--nsec') + 1];
const opt = (name: string) => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
const name = opt('--dir') ?? 'data';
const root = resolve(import.meta.dirname, name);
const port = Number(opt('--port') ?? 8711);

if (existsSync(join(root, 'a', 'state.json')) && !force) {
  console.error(`${name}/ already has a group. Pass --force to replace it (the old key is gone for good).`);
  process.exit(1);
}
if (force) rmSync(root, { recursive: true, force: true });

let secretHex: string | null = null;
if (args.includes('--nsec')) {
  const d = nip19.decode(nsecArg);
  if (d.type !== 'nsec') throw new Error('expected an nsec');
  secretHex = bytesToHex(d.data as Uint8Array);
}

const weighted = args.includes('--weighted');
if (weighted && secretHex) { console.error('--weighted makes a new key; it can\'t split one you have.'); process.exit(1); }
const key = () => bytesToHex(randomBytes(32));
const skA = key(), skB = key(), signerSk = key();
const relays = opt('--relays')?.split(',').map(r => r.trim()).filter(Boolean) ?? ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
const write = (dir: string, state: object) => {
  mkdirSync(join(root, dir), { recursive: true });
  writeFileSync(join(root, dir, 'state.json'), JSON.stringify(state, null, 2), { mode: 0o600 });
};
const signer = { sk: signerSk, pk: pubOf(signerSk) };

if (weighted) {
  const group = {
    groupX: null, npub: null, threshold: 4, relays,
    members: [
      { idx: 1, name: 'Server A', role: 'server', pk: pubOf(skA), sharePub: '' },
      { idx: 2, name: 'Server B', role: 'server', pk: pubOf(skB), sharePub: '' },
      { idx: 3, name: 'Phone', role: 'phone', pk: null, sharePub: '', push: null, shares: [3, 4, 5].map(idx => ({ idx, sharePub: '' })) },
    ],
  };
  const common = { group, signer, sites: [], tickets: [], changes: [] };
  write('a', { port, self: { idx: 1, sk: skA, shares: [] }, ...common, pairing: { token: bytesToHex(randomBytes(16)), weighted: true } });
  write('b', { port: port + 1, self: { idx: 2, sk: skB, shares: [] }, ...common, pairing: null });
  console.log(`
No key yet. It's made when your phone scans Server A's code: your phone 3 shares,
each server 1, any 4 sign.

Start the servers:
  node server.ts ${name}/a      http://localhost:${port}   (shows the code to add your phone)
  node server.ts ${name}/b      http://localhost:${port + 1}
`);
  process.exit(0);
}

const dealt = deal(secretHex, 3, 2);

const group = {
  groupX: dealt.groupX,
  npub: nip19.npubEncode(dealt.groupX),
  threshold: 2,
  relays,
  members: [
    { idx: 1, name: 'Server A', role: 'server', pk: pubOf(skA), sharePub: dealt.shares[0].pub },
    { idx: 2, name: 'Server B', role: 'server', pk: pubOf(skB), sharePub: dealt.shares[1].pub },
    { idx: 3, name: 'Phone', role: 'phone', pk: null as string | null, sharePub: dealt.shares[2].pub, push: null as string | null },
  ],
};
const common = { group, signer, sites: [], tickets: [], changes: [] };

write('a', { port, self: { idx: 1, sk: skA, share: dealt.shares[0].secret }, ...common,
  pairing: { token: bytesToHex(randomBytes(16)), idx: 3, share: dealt.shares[2].secret } });
write('b', { port: port + 1, self: { idx: 2, sk: skB, share: dealt.shares[1].secret }, ...common, pairing: null });

console.log(`
Your key: ${group.npub}
  split 2 of 3: Server A, Server B, your phone (not added yet)

Start the servers:
  node server.ts ${name}/a      http://localhost:${port}   (shows the code to add your phone)
  node server.ts ${name}/b      http://localhost:${port + 1}
`);
