// One-time setup: make a key, split it 2-of-3, write a state file for each server.
//
//   node setup.ts                 fresh throwaway key
//   node setup.ts --nsec nsec1... split a key you already have
//   node setup.ts --force         overwrite existing data/
//
// Share 1 goes to server A, share 2 to server B, and share 3 waits on server A
// until a phone scans A's pairing code. Once the phone has it, A deletes it.
// This script sees all three shares at once: that is what a trusted dealer is.

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { nip19 } from 'nostr-tools';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { deal } from './frost.ts';
import { pubOf } from './net.ts';
import { DEFAULT_AUTO_KINDS } from './policy.ts';

const args = process.argv.slice(2);
const force = args.includes('--force');
const nsecArg = args[args.indexOf('--nsec') + 1];
const root = join(import.meta.dirname, 'data');

if (existsSync(join(root, 'a', 'state.json')) && !force) {
  console.error('data/ already has a group. Pass --force to replace it (the old key is gone for good).');
  process.exit(1);
}

let secretHex: string | null = null;
if (args.includes('--nsec')) {
  const d = nip19.decode(nsecArg);
  if (d.type !== 'nsec') throw new Error('expected an nsec');
  secretHex = bytesToHex(d.data as Uint8Array);
}

const dealt = deal(secretHex, 3, 2);
const key = () => bytesToHex(randomBytes(32));
const skA = key(), skB = key(), bunkerSk = key();
const relays = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];

const group = {
  groupX: dealt.groupX,
  npub: nip19.npubEncode(dealt.groupX),
  threshold: 2,
  relays,
  autoKinds: DEFAULT_AUTO_KINDS,
  members: [
    { idx: 1, name: 'Server A', role: 'server', pk: pubOf(skA), sharePub: dealt.shares[0].pub },
    { idx: 2, name: 'Server B', role: 'server', pk: pubOf(skB), sharePub: dealt.shares[1].pub },
    { idx: 3, name: 'Phone', role: 'phone', pk: null as string | null, sharePub: dealt.shares[2].pub },
  ],
};
const bunker = { sk: bunkerSk, pk: pubOf(bunkerSk), secret: bytesToHex(randomBytes(16)), clients: [] as string[] };

const write = (dir: string, state: object) => {
  mkdirSync(join(root, dir), { recursive: true });
  writeFileSync(join(root, dir, 'state.json'), JSON.stringify(state, null, 2), { mode: 0o600 });
};

write('a', {
  port: 8711,
  self: { idx: 1, sk: skA, share: dealt.shares[0].secret },
  group, bunker,
  pairing: { token: bytesToHex(randomBytes(16)), idx: 3, share: dealt.shares[2].secret },
});
write('b', {
  port: 8712,
  self: { idx: 2, sk: skB, share: dealt.shares[1].secret },
  group, bunker,
  pairing: null,
});

const bunkerUri = `bunker://${bunker.pk}?${relays.map(r => 'relay=' + encodeURIComponent(r)).join('&')}&secret=${bunker.secret}`;
console.log(`
Group ${group.npub}
  2 of 3: Server A, Server B, Phone (not paired yet)

Start the servers:
  node server.ts data/a      http://localhost:8711   (shows the phone pairing code)
  node server.ts data/b      http://localhost:8712

Log in to a Nostr app with:
  ${bunkerUri}
`);
