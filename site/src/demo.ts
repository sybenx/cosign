// A demo site that signs in with your phone. Everything a real site would do is in
// pair.ts and client.ts; this page only draws buttons around them.

import encodeQR from 'qr';
import { nip19 } from 'nostr-tools';
import type { Event } from 'nostr-tools/pure';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { BunkerSigner, createNostrConnectURI, type BunkerPointer } from 'nostr-tools/nip46';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { pair, restore, forget, DEFAULT_RELAYS, type Signer } from './pair.ts';


const $ = (id: string) => document.getElementById(id)!;
const storage = window.localStorage;

function qrSvg(text: string): string {
  const m = encodeQR(text, 'raw', { ecc: 'medium', border: 4 });
  let d = '';
  for (let y = 0; y < m.length; y++) for (let x = 0; x < m.length; x++) {
    if (!m[y][x]) continue;
    let run = 1; while (x + run < m.length && m[y][x + run]) run++;
    d += `M${x} ${y}h${run}v1h-${run}z`; x += run - 1;
  }
  return `<svg viewBox="0 0 ${m.length} ${m.length}" shape-rendering="crispEdges"><rect width="${m.length}" height="${m.length}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

// --- Signed out ----------------------------------------------------------------

let cancelPairing: (() => void) | undefined;
let useNostrConnect = false;

function signIn() {
  cancelPairing?.();
  if (useNostrConnect) return signInNostrConnect();
  $('mode').textContent = 'Show a nostrconnect code instead';
  $('modeText').textContent = 'Most sites only know NIP-46.';
  show('out');
  $('qr').innerHTML = '';
  $('status').textContent = '';
  $('confirm').hidden = true;
  let last = '';
  const p = pair({
    origin: location.origin,
    baseUrl: 'https://cosign.aaro.cc/',
    storage,
    // One code for everyone: Cosign uses the ticket, any other signer app the nostrconnect half.
    nostrconnect: { name: 'Cosign demo' },
    ui: {
      code: uri => { $('qr').innerHTML = qrSvg(uri); $('qr').dataset.uri = uri; },
      confirm: (rendering, yes, no) => {
        $('confirm').hidden = false;
        $('rendering').textContent = rendering;
        $('yes').onclick = () => { $('confirm').hidden = true; yes(); };
        $('no').onclick = () => { $('confirm').hidden = true; no(); };
      },
      status: s => { if (s !== last) $('status').textContent = last = s; },
    },
  });
  cancelPairing = p.cancel;
  p.done.then(signedIn, err => { $('status').textContent = err.message; $('again').hidden = false; });
}

// The way an ordinary NIP-46 site does it, with nostr-tools and nothing of Cosign's: a
// nostrconnect:// code, which the phone scans too.
function signInNostrConnect() {
  $('mode').textContent = 'Show the QRST code';
  $('modeText').textContent = 'This is the code an ordinary NIP-46 site shows.';
  show('out');
  $('status').textContent = 'Scan this with Cosign on your phone.';
  $('confirm').hidden = true;
  const sk = generateSecretKey();
  const uri = createNostrConnectURI({ clientPubkey: getPublicKey(sk), relays: DEFAULT_RELAYS, secret: bytesToHex(randomBytes(8)), name: 'Cosign demo', url: location.origin });
  $('qr').innerHTML = qrSvg(uri); $('qr').dataset.uri = uri;
  const abort = new AbortController();
  cancelPairing = () => abort.abort();
  BunkerSigner.fromURI(sk, uri, {}, abort.signal).then(signer => {
    storage.setItem('demo.nc', JSON.stringify({ sk: bytesToHex(sk), bp: signer.bp }));
    void signedIn(signer);
  }, err => { if (!abort.signal.aborted) { $('status').textContent = err.message; $('again').hidden = false; } });
}

function restoreNostrConnect(): Signer | undefined {
  try {
    const saved = JSON.parse(storage.getItem('demo.nc') ?? 'null') as { sk: string; bp: BunkerPointer } | null;
    return saved ? BunkerSigner.fromBunker(hexToBytes(saved.sk), saved.bp) : undefined;
  } catch { return undefined; }
}

// --- Signed in -----------------------------------------------------------------

let client: Signer;
let follows: string[][] = JSON.parse(storage.getItem('demo.follows') ?? '[]');
const saveFollows = () => storage.setItem('demo.follows', JSON.stringify(follows));

async function signedIn(c: Signer) {
  client = c;
  show('in');
  $('who').textContent = 'checking…';
  try {
    const pk = await client.getPublicKey();
    const npub = nip19.npubEncode(pk);
    $('who').textContent = `${npub.slice(0, 14)}…${npub.slice(-6)}`;
  } catch (e: any) {
    $('who').textContent = e.message;
  }
  $('follows').textContent = String(follows.length);
}

const randomPk = () => bytesToHex(randomBytes(32));
// Notes this page posted, newest last, so the delete buttons delete real ones.
const posted: string[] = JSON.parse(storage.getItem('demo.posted') ?? '[]');
const deleteNotes = (n: number) => {
  const ids = posted.splice(-n, n);
  while (ids.length < n) ids.push(randomPk());
  storage.setItem('demo.posted', JSON.stringify(posted));
  return { kind: 5, content: '', tags: [...ids.map(id => ['e', id]), ['k', '1']] };
};

const actions: Record<string, () => { kind: number; content: string; tags: string[][] }> = {
  note: () => ({ kind: 1, content: ($('text') as HTMLTextAreaElement).value || 'gm from the cosign demo', tags: [] }),
  react: () => ({ kind: 7, content: '🤙', tags: [['e', randomPk()], ['p', randomPk()]] }),
  follow30: () => ({ kind: 3, content: '', tags: [...follows, ...Array.from({ length: 30 }, () => ['p', randomPk()])] }),
  follow1: () => ({ kind: 3, content: '', tags: [...follows, ['p', randomPk()]] }),
  unfollow: () => ({ kind: 3, content: '', tags: [] }),
  name: () => ({ kind: 0, content: JSON.stringify({ name: `demo-${Math.floor(Math.random() * 1000)}`, about: 'trying cosign', picture: 'https://robohash.org/cosign' }), tags: [] }),
  wipe: () => ({ kind: 0, content: '{}', tags: [] }),
  delete1: () => deleteNotes(1),
  delete6: () => deleteNotes(6),
};

async function act(name: string, button: HTMLButtonElement) {
  const template = actions[name]();
  const line = document.createElement('li');
  line.textContent = `${button.textContent}: signing…`;
  $('log').prepend(line);
  const started = Date.now();
  const slow = setTimeout(() => { line.textContent = `${button.textContent}: waiting for your phone…`; line.className = 'wait'; }, 2500);
  try {
    const ev: Event = await client.signEvent(template);
    if (ev.kind === 3) { follows = ev.tags.filter(t => t[0] === 'p'); saveFollows(); $('follows').textContent = String(follows.length); }
    if (ev.kind === 1) { posted.push(ev.id); storage.setItem('demo.posted', JSON.stringify(posted)); }
    line.textContent = `${button.textContent}: signed in ${((Date.now() - started) / 1000).toFixed(1)} s`;
    line.className = 'ok';
  } catch (e: any) {
    line.textContent = `${button.textContent}: ${e?.message ?? e}`;
    line.className = 'no';
  } finally {
    clearTimeout(slow);
  }
}

// --- Page ----------------------------------------------------------------------

function show(which: 'in' | 'out') { $('signedin').hidden = which !== 'in'; $('signedout').hidden = which !== 'out'; }

for (const b of document.querySelectorAll<HTMLButtonElement>('button[data-act]')) b.onclick = () => act(b.dataset.act!, b);
$('again').onclick = () => { $('again').hidden = true; signIn(); };
$('signout').onclick = () => { void client?.logout().catch(() => {}); forget(storage); for (const k of ['demo.follows', 'demo.nc', 'demo.posted']) storage.removeItem(k); follows = []; signIn(); };
$('mode').onclick = () => { useNostrConnect = !useNostrConnect; $('again').hidden = true; signIn(); };

const previous = restore(storage) ?? restoreNostrConnect();
if (previous) void signedIn(previous); else signIn();
