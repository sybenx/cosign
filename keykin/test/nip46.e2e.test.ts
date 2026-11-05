// Doors §3.3 against real clients over a real relay: `nak` (the interop plan's must-pass tool) and
// nostr-tools' BunkerSigner (what most web clients use) sign and encrypt as the account through a
// bunker:// link the device minted. A local `nak serve` relay only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as nip44 from 'nostr-tools/nip44';
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46';
import { SimplePool } from 'nostr-tools/pool';
import { RelayNet } from '../runtime/relay.ts';
import { create } from '../sim/account.ts';
import { newKey, verifyEvent } from '../src/event.ts';

const haveNak = spawnSync('nak', ['--version']).status === 0;
const port = 17251, url = `ws://127.0.0.1:${port}`, other = 'ws://127.0.0.1:17252';
let relay: ChildProcess | undefined, relay2: ChildProcess | undefined, net: RelayNet | undefined;
before(async () => {
  if (!haveNak) return;
  relay = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  relay2 = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', '17252'], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 1200));
  net = new RelayNet({ relays: [url], timeoutMs: 7000, resendMs: 1200 }); await net.connect();
});
after(() => { net?.close(); relay?.kill(); relay2?.kill(); });
const run = (args: string[]) => new Promise<{ code: number; out: string; err: string }>((res) => {
  const p = spawn('nak', args, { stdio: ['ignore', 'pipe', 'pipe'] }); let out = '', err = '';
  p.stdout.on('data', (c) => (out += c)); p.stderr.on('data', (c) => (err += c));
  const t = setTimeout(() => p.kill(), 30_000);
  p.on('exit', (code) => { clearTimeout(t); res({ code: code ?? -1, out, err }); });
});

test('nak and BunkerSigner sign and encrypt as the account through the device\'s bunker link', { skip: !haveNak && 'nak not installed', timeout: 180_000 }, async () => {
  const acc = await create({ net: net as any, relays: [url] });
  // nak makes a new client key each run, so each run gets a fresh link (Doors §3.3).
  const n1 = await run(['event', '--sec', acc.A.nip46.mintBunker([url], 'nak'), '-k', '1', '-c', 'hello from nak', url]);
  const ev = JSON.parse(n1.out.trim().split('\n').find((l) => l.startsWith('{'))!);
  assert.equal(ev.pubkey, acc.g, n1.err);
  assert.equal(ev.content, 'hello from nak');
  assert.ok(verifyEvent(ev));
  const peer = newKey();
  const n2 = await run(['encrypt', '--sec', acc.A.nip46.mintBunker([url], 'nak', ['sign-in', 'post', 'dms']), '-p', peer.pub, 'a note for the peer']);
  assert.equal(nip44.v2.decrypt(n2.out.trim(), nip44.v2.utils.getConversationKey(peer.sk, acc.g)), 'a note for the peer', n2.err);

  // nostr-tools' BunkerSigner: connect, get_public_key, sign_event, nip44.
  const pool = new SimplePool();
  try {
    const bp = await parseBunkerInput(acc.A.nip46.mintBunker([url], 'web', ['sign-in', 'post', 'dms']));
    const s = BunkerSigner.fromBunker(newKey().sk, bp!, { pool });
    await s.connect();
    assert.equal(await s.getPublicKey(), acc.g);
    const signed = await s.signEvent({ kind: 1, content: 'hello from BunkerSigner', tags: [], created_at: Math.floor(Date.now() / 1000) });
    assert.ok(verifyEvent(signed as any) && signed.pubkey === acc.g);
    const ct = await s.nip44Encrypt(peer.pub, 'from the web');
    assert.equal(await s.nip44Decrypt(peer.pub, ct), 'from the web');
    await s.close();
  } finally { pool.destroy(); }
});

test('a grant on a relay the device doesn\'t otherwise use: the reply goes there and requests there are answered (review 11 H3)', { skip: !haveNak && 'nak not installed', timeout: 120_000 }, async () => {
  const acc = await create({ net: net as any, relays: [url] });
  const pool = new SimplePool();
  try {
    const clientSk = newKey().sk;
    const { createNostrConnectURI } = await import('nostr-tools/nip46');
    const { getPublicKey } = await import('nostr-tools/pure');
    const secret = 'r11h3';
    const uri = createNostrConnectURI({ clientPubkey: getPublicKey(clientSk), relays: [other], secret, name: 'site' });
    const signerP = BunkerSigner.fromURI(clientSk, uri, { pool }, 20_000);
    await new Promise((r) => setTimeout(r, 500));
    await acc.A.nip46.acceptNostrconnect(uri);
    const s = await signerP;
    assert.equal(await s.getPublicKey(), acc.g, 'answered on the grant\'s own relay');
    await s.close();
  } finally { pool.destroy(); }
});
