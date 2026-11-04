// The paper's 24 words (Backup module §2) for every port: secrets and their words, and words a port must refuse
// (a bad checksum; a BIP-39 wallet seed, told apart). Run: node vectors/gen-backup-words.ts > vectors/backup-words.json
import { backupWords } from '../src/backup.ts';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { bytesToHex, hexToBytes } from '../src/bytes.ts';
const secrets = ['01'.repeat(32), '7f'.repeat(31) + '00', 'c0ffee'.repeat(10) + 'ab01'].map(hexToBytes);
const ok = secrets.map((sk) => ({ secret: bytesToHex(sk), words: backupWords(sk) }));
const bad = [...ok[0].words]; bad[23] = bad[23] === 'abandon' ? 'ability' : 'abandon';
console.log(JSON.stringify({ note: '24 words: the secret as BIP-39 English, the last 8 bits the first 8 of SHA-256("keykin-backup/1" ‖ secret).',
  valid: ok, refused: [{ words: bad, why: 'checksum' }], wallet_seed: generateMnemonic(wordlist, 256).split(' ') }, null, 1));
