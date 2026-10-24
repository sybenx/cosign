// Moving a key you already have out of a web app and into Cosign, in one scan: the page
// holding the nsec deals it (your phone 3 shares, each server 1, any 4 sign), gives each
// server its share (enroll, `how: 'dealt'`), and hands your phone its three by QRST
// (profile `cosign-member`, checked by typing the five digits the phone shows). The
// same move signs the page in: it gave the servers a ticket of its own.
//
// After this the page holds no key, only a session like any signed-in site's. Forget the
// nsec yourself (the caller's copy): this can't reach into your variables.
//
//   const { done } = importToPhone({ secretKey, origin, baseUrl, storage, ui });
//   const signer = await done;

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { SimplePool } from 'nostr-tools/pool';
import * as nip44 from 'nostr-tools/nip44';
import { nip19 } from 'nostr-tools';
import { Transfer, Store, browserEnv, type KeyValue } from '../vendor/qrst-web/index.ts';
import { SignerClient, newSession } from './client.ts';
import { cosignMember, type MemberMove } from './member.ts';
import { findServers, pickServers, relayQuery, pingHost, type Server } from './servers.ts';
import { DEFAULT_RELAYS, type Signer } from './pair.ts';

export interface ImportUi {
  status(text: string): void;
  /** Draw this as a QR code (and offer it as a link). */
  code(uri: string): void;
  /** Your phone shows five digits: ask for them and pass them on. `left`: tries remaining. */
  enterCode(left: number, submit: (digits: string) => void): void;
}

export interface ImportOptions {
  /** The key to move: hex or nsec. */
  secretKey: string | Uint8Array;
  /** This page's origin: the ticket it signs in with is for it. */
  origin: string;
  /** Where the code points if a phone's camera app opens it (QRST §11.2a). */
  baseUrl: string;
  storage?: KeyValue;
  /** Servers to use instead of finding them (site/src/servers.ts). */
  servers?: Server[];
  /** Relays for the QRST session. */
  relays?: string[];
  ui: ImportUi;
}

const N = secp256k1.Point.Fn.ORDER;
const mod = (a: bigint) => ((a % N) + N) % N;
const hex32 = (x: bigint) => x.toString(16).padStart(64, '0');
const SESSION_KEY = 'cosign.session';
const KIND_MEMBER = 28001;
const THRESHOLD = 4, PHONE_SHARES = 3;

/** Split `secret` so any `t` of `n` shares sign as it (BIP-340: an odd-y key is negated, same npub). */
function deal(secret: Uint8Array, n: number, t: number) {
  let a0 = mod(BigInt('0x' + bytesToHex(secret)));
  if (a0 === 0n) throw new Error('that key is zero');
  const P = secp256k1.Point.BASE.multiply(a0);
  if (P.toBytes(true)[0] === 3) a0 = N - a0;
  const coeffs = [a0, ...Array.from({ length: t - 1 }, () => mod(BigInt('0x' + bytesToHex(randomBytes(32)))))];
  const f = (x: bigint) => coeffs.reduceRight((acc, c) => mod(acc * x + c), 0n);
  const shares = Array.from({ length: n }, (_, i) => {
    const s = f(BigInt(i + 1));
    return { idx: i + 1, secret: hex32(s), sharePub: bytesToHex(secp256k1.Point.BASE.multiply(s).toBytes(true)) };
  });
  return { groupX: bytesToHex(P.toBytes(true).slice(1)), shares };
}

/** One question to a server's host key, asked again every 4 s until it answers. */
async function ask(pool: SimplePool, sk: Uint8Array, s: Server, msg: Record<string, unknown>, ms = 30_000): Promise<any> {
  const me = getPublicKey(sk), ck = nip44.v2.utils.getConversationKey(sk, s.pk);
  const id = bytesToHex(randomBytes(8));
  const body = JSON.stringify({ ...msg, id });
  return new Promise((resolve, reject) => {
    let again: ReturnType<typeof setInterval>;
    const timer = setTimeout(() => { clearInterval(again); sub.close(); reject(new Error(`${s.nip05 ?? 'a server'} didn't answer`)); }, ms);
    const sub = pool.subscribeMany(s.relays, { kinds: [KIND_MEMBER], '#p': [me], authors: [s.pk], since: Math.floor(Date.now() / 1000) - 5 } as any, {
      onevent: e => {
        let r: any;
        try { r = JSON.parse(nip44.v2.decrypt(e.content, ck)); } catch { return; }
        if (r?.id !== id) return;
        clearTimeout(timer); clearInterval(again); sub.close();
        if (r.type === 'enroll_failed') reject(new Error(r.reason)); else resolve(r);
      },
    });
    const send = () => void Promise.allSettled(pool.publish(s.relays, finalizeEvent({ kind: KIND_MEMBER, created_at: Math.floor(Date.now() / 1000), tags: [['p', s.pk]], content: nip44.v2.encrypt(body, ck) }, sk)));
    send(); again = setInterval(send, 4000);
  });
}

export function importToPhone(o: ImportOptions): { done: Promise<Signer>; cancel(): void } {
  let transfer: Transfer<MemberMove> | null = null, cancelled = false;
  const pool = new SimplePool();
  const done = (async (): Promise<Signer> => {
    const secret = typeof o.secretKey === 'string'
      ? (o.secretKey.startsWith('nsec1') ? nip19.decode(o.secretKey as `nsec1${string}`).data as Uint8Array : hexToBytes(o.secretKey))
      : o.secretKey;

    o.ui.status('Finding servers…');
    const servers = o.servers ?? await pickServers(await findServers({ query: relayQuery() }), { ping: s => pingHost(s) });
    if (!servers.length) throw new Error('No Cosign server answered. Try again in a minute.');
    if (cancelled) throw new Error('cancelled');

    // This page talks to the servers as a device of its own, for these few messages.
    const deviceSk = generateSecretKey();
    o.ui.status(`Asking ${servers.length === 1 ? 'your server' : `${servers.length} servers`}…`);
    const keys = await Promise.all(servers.map(s => ask(pool, deviceSk, s, { type: 'enroll_key' })));

    const dealt = deal(secret, PHONE_SHARES + servers.length, THRESHOLD);
    const relays = [...new Set(servers.flatMap(s => s.relays))].slice(0, 4);
    const phoneShares = dealt.shares.slice(0, PHONE_SHARES);
    const group = {
      groupX: dealt.groupX, npub: nip19.npubEncode(dealt.groupX), threshold: THRESHOLD, relays,
      members: [
        { idx: 1, name: 'Phone', role: 'phone', pk: null, sharePub: phoneShares[0].sharePub, shares: phoneShares.map(s => ({ idx: s.idx, sharePub: s.sharePub })) },
        ...servers.map((s, i) => ({ idx: PHONE_SHARES + 1 + i, name: s.nip05 ?? (s.https ? new URL(s.https).host : `Server ${i + 1}`), role: 'server', pk: keys[i].pk as string, sharePub: dealt.shares[PHONE_SHARES + i].sharePub })),
      ],
    };
    const signerSk = generateSecretKey();
    const signer = { sk: bytesToHex(signerSk), pk: getPublicKey(signerSk) };
    const claim = bytesToHex(randomBytes(16));
    const ticket = { t: bytesToHex(randomBytes(16)), origin: o.origin, expires: Math.floor(Date.now() / 1000) + 900 };

    o.ui.status('Giving each server its share…');
    await Promise.all(servers.map((s, i) => ask(pool, deviceSk, s, {
      type: 'enroll', how: 'dealt', key: keys[i].key, group, share: dealt.shares[PHONE_SHARES + i].secret,
      signer, claim: { token: claim, idx: 1 }, tickets: [ticket],
    })));
    if (cancelled) throw new Error('cancelled');

    // The phone's three, by QRST: it shows five digits, you type them here.
    const move: MemberMove = { v: 1, group, idx: 1, shares: phoneShares.map(s => ({ idx: s.idx, secret: s.secret })), signer: signer.pk, claim };
    const store = new Store(o.storage, () => Math.floor(Date.now() / 1000), [], o.relays ?? DEFAULT_RELAYS);
    const t = transfer = Transfer.show({ profile: cosignMember, store, env: browserEnv(), baseUrl: o.baseUrl, origin: o.origin, check: 'type' }, 'sender', move);
    await new Promise<void>((resolve, reject) => {
      let shown = '', asked = -1;
      t.onChange = () => {
        const v = t.view();
        if (v.uri && v.uri !== shown) { shown = v.uri; o.ui.code(v.uri); o.ui.status('Scan this with Cosign on your phone.'); }
        if (v.session.phase === 'release' && v.session.attemptsLeft !== asked) {
          asked = v.session.attemptsLeft;
          o.ui.enterCode(v.session.attemptsLeft, d => t.enterCode(d));
        }
        if (v.session.phase === 'sent') o.ui.status('Sent. Waiting for your phone to keep it…');
        if (v.stage === 'ended') {
          if (v.session.outcome === 'delivered' || v.session.outcome === 'sent-unconfirmed') resolve();
          else reject(new Error(`Not moved (${v.session.outcome ?? 'ended'}).`));
        }
      };
    });

    o.ui.status('Signing in through your servers…');
    const session = newSession(signer.pk, relays);
    const client = new SignerClient(session);
    try {
      await client.connect(ticket.t);
      session.pubkey = await client.getPublicKey();
    } catch (e) { client.close(); throw e; }
    o.storage?.setItem(SESSION_KEY, JSON.stringify(session));
    return client;
  })().finally(() => pool.destroy());
  return { done, cancel: () => { cancelled = true; transfer?.cancel(); } };
}
