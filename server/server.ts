// A cosign server: holds one share, signs with whichever member agrees, and
// runs the NIP-46 bunker that Nostr apps talk to.
//
//   node server.ts data/a
//
// Server A (idx 1) answers the bunker. Server B (idx 2) answers it only while A
// has been silent for 30 s, so one bunker URI keeps working when either is down.

import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes as nodeRandom } from 'node:crypto';
import { getEventHash, finalizeEvent, type Event } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import QRCode from 'qrcode';
import * as F from './frost.ts';
import { Pool, sealTo, openFrom, KIND_MEMBER, KIND_NIP46 } from './net.ts';
import { allows, kindName, type Member } from './policy.ts';

// --- State -------------------------------------------------------------------

const dir = process.argv[2];
if (!dir) { console.error('usage: node server.ts data/a'); process.exit(1); }
const file = join(dir, 'state.json');
const S = JSON.parse(readFileSync(file, 'utf8'));
const save = () => { writeFileSync(file + '.tmp', JSON.stringify(S, null, 2), { mode: 0o600 }); renameSync(file + '.tmp', file); };

const members: Member[] = S.group.members;
const me = members.find(m => m.idx === S.self.idx)!;
const other = () => members.find(m => m.role === 'server' && m.idx !== me.idx)!;
const phone = () => members.find(m => m.role === 'phone')!;
const byPk = (pk: string) => members.find(m => m.pk === pk);
const groupX: string = S.group.groupX;

const startedAt = Date.now();
const lastSeen = new Map<number, number>();
const seen = (idx: number) => lastSeen.get(idx) ?? 0;
// Pings go out every 10 s; three missed means gone. One threshold for everything.
const online = (m: Member) => m.idx === me.idx || Date.now() - seen(m.idx) < 30_000;

const activity: { ts: number; text: string }[] = [];
const note = (text: string) => {
  activity.unshift({ ts: Date.now(), text });
  activity.length = Math.min(activity.length, 40);
  console.log(`[${me.name}] ${text}`);
};

// --- Relays ------------------------------------------------------------------

const pool = new Pool(S.group.relays, onEvent, t => console.log(`[${me.name}] ${t}`));
const send = (toPk: string, msg: object) => pool.publish(sealTo(S.self.sk, toPk, msg));

const pending = new Map<string, { resolve: (v: any) => void; timer: NodeJS.Timeout }>();
const rid = () => F.bytesToHex(F.randomBytes(8));
function ask(toPk: string, msg: any, ms: number): Promise<any> {
  return new Promise(resolve => {
    const timer = setTimeout(() => { pending.delete(msg.id); resolve({ ok: false, reason: 'no answer' }); }, ms);
    pending.set(msg.id, { resolve, timer });
    send(toPk, msg);
  });
}

function onEvent(e: Event) {
  if (e.created_at < Math.floor(Date.now() / 1000) - 120) return; // stale
  if (e.kind === KIND_MEMBER) {
    const msg = openFrom(S.self.sk, e);
    // Relays replay recent "ephemeral" events to a fresh subscription whatever
    // `since` says. A request that old has been given up on by whoever sent it.
    const age = Math.floor(Date.now() / 1000) - e.created_at;
    if (msg && (msg.type === 'sign_req' || msg.type === 'ecdh_req') && age > 30) return;
    if (msg) onMember(msg, e.pubkey).catch(err => console.error(err));
  } else if (e.kind === KIND_NIP46) {
    onBunker(e).catch(err => console.error(err));
  }
}

// --- Member messages ---------------------------------------------------------

async function onMember(msg: any, fromPk: string) {
  const from = byPk(fromPk);
  if (from) lastSeen.set(from.idx, Date.now());

  // Replies to something we asked.
  if ((msg.type === 'sign_res' || msg.type === 'ecdh_res') && pending.has(msg.id)) {
    const p = pending.get(msg.id)!; clearTimeout(p.timer); pending.delete(msg.id);
    p.resolve({ ...msg, from });
    return;
  }

  // Pairing comes from a phone we don't know yet.
  if (msg.type === 'pair_hello') return onPairHello(msg, fromPk);
  if (msg.type === 'pair_ack') return onPairAck(msg, fromPk);

  if (!from) return; // everything else is members only

  switch (msg.type) {
    case 'ping': return;
    case 'member': {
      // The pairing server tells us who the phone is.
      if (from.role !== 'server') return;
      const m = members.find(x => x.idx === msg.idx);
      if (m && m.role === 'phone') { m.pk = msg.pk; save(); note('learned the phone from ' + from.name); }
      return;
    }
    case 'clients': {
      if (from.role !== 'server') return;
      const before = S.bunker.clients.length;
      S.bunker.clients = [...new Set([...S.bunker.clients, ...msg.clients])];
      if (S.bunker.clients.length !== before) save();
      return;
    }
    case 'sign_req': return onSignReq(msg, from);
    case 'ecdh_req': return onEcdhReq(msg, from);
  }
}

// As the co-signer: check the event is what it claims to be, check policy, sign.
async function onSignReq(msg: any, from: Member) {
  const reply = (r: object) => send(from.pk!, { type: 'sign_res', id: msg.id, ...r });
  const ev = msg.event;
  const participants: number[] = msg.participants;
  if (from.role !== 'server') return reply({ ok: false, reason: 'only servers coordinate' });
  if (participants.length !== 2 || !participants.includes(me.idx) || !participants.includes(from.idx)) return reply({ ok: false, reason: 'bad participants' });
  if (ev.pubkey !== groupX || getEventHash(ev) !== msg.msg) return reply({ ok: false, reason: 'event does not match the message' });
  const p = allows(ev.kind, participants, members, S.group.autoKinds);
  if (!p.ok) { note(`refused ${kindName(ev.kind)} from ${from.name}: ${p.why}`); return reply({ ok: false, reason: p.why }); }
  const mine = F.commit(me.idx);
  const commits = [msg.commit, mine.commit];
  const z = F.partialSign({ groupX, msg: msg.msg, commits, idx: me.idx, secret: S.self.share, nonces: mine.nonces });
  note(`co-signed ${kindName(ev.kind)} for ${from.name}`);
  reply({ ok: true, commit: mine.commit, z });
}

async function onEcdhReq(msg: any, from: Member) {
  const reply = (r: object) => send(from.pk!, { type: 'ecdh_res', id: msg.id, ...r });
  if (from.role !== 'server' || !msg.participants.includes(me.idx)) return reply({ ok: false, reason: 'bad request' });
  const point = F.ecdhPartial({ idx: me.idx, secret: S.self.share, participants: msg.participants, peerX: msg.peerX });
  reply({ ok: true, point });
}

// --- Coordinating ------------------------------------------------------------

/** Who to ask, in order. Auto kinds try the other server first; the rest need the phone. */
function cosigners(kind: number): Member[] {
  const p = phone(), o = other();
  const list = S.group.autoKinds.includes(kind) ? [o, p] : [p];
  return list.filter(m => m.pk).sort((a, b) => Number(online(b)) - Number(online(a)));
}

async function frostSign(unsigned: any, app: string): Promise<Event> {
  const ev = {
    pubkey: groupX, kind: unsigned.kind, created_at: unsigned.created_at ?? Math.floor(Date.now() / 1000),
    tags: unsigned.tags ?? [], content: unsigned.content ?? '',
  };
  const id = getEventHash(ev);
  const tried: string[] = [];
  for (const m of cosigners(ev.kind)) {
    const participants = [me.idx, m.idx].sort((a, b) => a - b);
    if (!allows(ev.kind, participants, members, S.group.autoKinds).ok) continue;
    // Fresh nonces every attempt; ours are only used once we have a valid partner.
    const mine = F.commit(me.idx);
    const isPhone = m.role === 'phone';
    if (isPhone && !online(m)) tried.push('phone not seen lately');
    const res = await ask(m.pk!, { type: 'sign_req', id: rid(), event: ev, msg: id, participants, commit: mine.commit, app }, isPhone ? (online(m) ? 60_000 : 15_000) : 8_000);
    if (!res.ok) { tried.push(`${m.name}: ${res.reason}`); continue; }
    const commits = [mine.commit, res.commit];
    if (res.commit?.idx !== m.idx || !F.verifyPartial({ groupX, msg: id, commits, idx: m.idx, sharePub: m.sharePub, z: res.z })) {
      tried.push(`${m.name}: bad partial`); continue;
    }
    const z = F.partialSign({ groupX, msg: id, commits, idx: me.idx, secret: S.self.share, nonces: mine.nonces });
    const sig = F.aggregate({ groupX, msg: id, commits, partials: [z, res.z] });
    note(`signed ${kindName(ev.kind)} for ${app} with ${m.name}${isPhone && !S.group.autoKinds.includes(ev.kind) ? ' (you approved)' : ''}`);
    return { ...ev, id, sig } as Event;
  }
  note(`could not sign ${kindName(ev.kind)} for ${app}: ${tried.join('; ') || 'nobody to ask'}`);
  throw new Error(tried.join('; ') || 'no co-signer available');
}

// Shared secrets for encrypting on the group's behalf. Kept in memory only, and
// only for ten minutes: a cached shared secret is as sensitive as the share.
const ecdhCache = new Map<string, { x: Uint8Array; at: number }>();
async function frostEcdh(peerX: string): Promise<Uint8Array> {
  const hit = ecdhCache.get(peerX);
  if (hit && Date.now() - hit.at < 600_000) return hit.x;
  const tried: string[] = [];
  for (const m of [other(), phone()].filter(m => m.pk).sort((a, b) => Number(online(b)) - Number(online(a)))) {
    const participants = [me.idx, m.idx].sort((a, b) => a - b);
    const res = await ask(m.pk!, { type: 'ecdh_req', id: rid(), peerX, participants }, m.role === 'phone' ? 20_000 : 6_000);
    if (!res.ok) { tried.push(`${m.name}: ${res.reason}`); continue; }
    const mine = F.ecdhPartial({ idx: me.idx, secret: S.self.share, participants, peerX });
    const x = F.ecdhCombine([mine, res.point]);
    ecdhCache.set(peerX, { x, at: Date.now() });
    return x;
  }
  throw new Error('no member answered: ' + tried.join('; '));
}

const groupNip44Key = async (peerX: string) => extract(sha256, await frostEcdh(peerX), utf8ToBytes('nip44-v2'));
async function groupNip04(peerX: string, text: string, decrypt: boolean) {
  const key = await frostEcdh(peerX);
  if (decrypt) {
    const [ct, iv] = text.split('?iv=');
    const d = createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'base64'));
    return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
  }
  const iv = nodeRandom(16);
  const c = createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([c.update(text, 'utf8'), c.final()]).toString('base64') + '?iv=' + iv.toString('base64');
}

// --- NIP-46 bunker -----------------------------------------------------------

const coordinating = () => me.idx === 1 || (Date.now() - startedAt > 30_000 && !online(members.find(m => m.idx === 1)!));
const appName = (pk: string) => 'app ' + pk.slice(0, 6);

async function onBunker(e: Event) {
  if (!coordinating()) return;
  const sk = F.hexToBytes(S.bunker.sk);
  let scheme: 'nip44' | 'nip04' = 'nip44', req: any;
  try { req = JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(sk, e.pubkey))); }
  catch { try { scheme = 'nip04'; req = JSON.parse(nip04.decrypt(sk, e.pubkey, e.content)); } catch { return; } }

  const respond = (body: object) => {
    const text = JSON.stringify({ id: req.id, ...body });
    const content = scheme === 'nip44' ? nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(sk, e.pubkey)) : nip04.encrypt(sk, e.pubkey, text);
    pool.publish(sealRaw(content, e.pubkey));
  };
  const authorized = S.bunker.clients.includes(e.pubkey);

  try {
    switch (req.method) {
      case 'connect': {
        if (!authorized && req.params?.[1] !== S.bunker.secret) return respond({ error: 'wrong or missing secret' });
        if (!authorized) {
          S.bunker.clients.push(e.pubkey); save();
          send(other().pk!, { type: 'clients', clients: S.bunker.clients });
          note(`${appName(e.pubkey)} connected`);
        }
        return respond({ result: 'ack' });
      }
      case 'ping': return respond({ result: 'pong' });
    }
    if (!authorized) return respond({ error: 'not connected: use the bunker link with its secret' });
    switch (req.method) {
      case 'get_public_key': return respond({ result: groupX });
      case 'get_relays': return respond({ result: JSON.stringify(Object.fromEntries(S.group.relays.map((r: string) => [r, { read: true, write: true }]))) });
      case 'sign_event': {
        const signed = await frostSign(JSON.parse(req.params[0]), appName(e.pubkey));
        return respond({ result: JSON.stringify(signed) });
      }
      case 'nip44_encrypt': return respond({ result: nip44.v2.encrypt(req.params[1], await groupNip44Key(req.params[0])) });
      case 'nip44_decrypt': return respond({ result: nip44.v2.decrypt(req.params[1], await groupNip44Key(req.params[0])) });
      case 'nip04_encrypt': return respond({ result: await groupNip04(req.params[0], req.params[1], false) });
      case 'nip04_decrypt': return respond({ result: await groupNip04(req.params[0], req.params[1], true) });
      default: return respond({ error: `unsupported method ${req.method}` });
    }
  } catch (err: any) {
    respond({ error: err?.message ?? String(err) });
  }
}

const sealRaw = (content: string, toPk: string) =>
  finalizeEvent({ kind: KIND_NIP46, created_at: Math.floor(Date.now() / 1000), tags: [['p', toPk]], content }, F.hexToBytes(S.bunker.sk));

// --- Pairing a phone ---------------------------------------------------------
//
// The QR carries this server's public key, a one-time token and the relays. A
// phone that echoes the token gets the phone share, sealed to the key it just
// generated. It keeps the share only if its user says yes, and tells us so;
// then we forget the share. Like QRST at its lowest level: scan, confirm, done.

let offeredTo: string | null = null;

function pairingUri() {
  if (!S.pairing) return null;
  return `cosign:pair?pk=${me.pk}&t=${S.pairing.token}&${S.group.relays.map((r: string) => 'r=' + encodeURIComponent(r)).join('&')}`;
}

function onPairHello(msg: any, fromPk: string) {
  if (!S.pairing || msg.token !== S.pairing.token) return;
  offeredTo = fromPk;
  send(fromPk, {
    type: 'pair_offer',
    token: S.pairing.token,
    idx: S.pairing.idx,
    share: S.pairing.share,
    group: { groupX, npub: S.group.npub, threshold: S.group.threshold, relays: S.group.relays, autoKinds: S.group.autoKinds,
      members: members.map(m => ({ idx: m.idx, name: m.name, role: m.role, pk: m.role === 'phone' ? null : m.pk, sharePub: m.sharePub })) },
  });
  note('a phone scanned the pairing code');
}

function onPairAck(msg: any, fromPk: string) {
  if (!S.pairing || fromPk !== offeredTo || msg.token !== S.pairing.token) return;
  const p = phone();
  p.pk = fromPk;
  S.pairing = null; // the phone has its share; this server no longer does
  save();
  lastSeen.set(p.idx, Date.now());
  send(other().pk!, { type: 'member', idx: p.idx, pk: fromPk });
  note('phone paired');
}

// --- Liveness ----------------------------------------------------------------

setInterval(() => {
  for (const m of members) if (m.pk && m.idx !== me.idx) send(m.pk, { type: 'ping', idx: me.idx, ts: Date.now() });
}, 10_000);
setTimeout(() => { for (const m of members) if (m.pk && m.idx !== me.idx) send(m.pk, { type: 'ping', idx: me.idx, ts: Date.now() }); }, 2000);

// --- Status page -------------------------------------------------------------

const bunkerUri = () => `bunker://${S.bunker.pk}?${S.group.relays.map((r: string) => 'relay=' + encodeURIComponent(r)).join('&')}&secret=${S.bunker.secret}`;

function status() {
  return {
    me: me.name, npub: S.group.npub, coordinating: coordinating(),
    members: members.map(m => ({ name: m.name, role: m.role, paired: !!m.pk, online: !!m.pk && online(m), self: m.idx === me.idx })),
    relays: pool.status(), pairing: !!S.pairing, apps: S.bunker.clients.length,
    autoKinds: S.group.autoKinds.map(kindName), activity,
  };
}

const page = async () => {
  const pu = pairingUri();
  const pairQr = pu ? await QRCode.toString(pu, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' }) : '';
  const bunkerQr = await QRCode.toString(bunkerUri(), { type: 'svg', margin: 1 });
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${me.name} · cosign</title>
<style>
 body{font:15px/1.45 system-ui,sans-serif;background:#111;color:#eee;max-width:760px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px} .muted{color:#999} .card{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:12px;padding:16px;margin:16px 0}
 .row{display:flex;gap:10px;align-items:center;margin:6px 0} .dot{width:10px;height:10px;border-radius:50%;background:#555}
 .on{background:#3c3} .qr{background:#fff;padding:10px;border-radius:10px;width:220px} code{word-break:break-all;font-size:12px;color:#ccc}
 .grid{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start} ul{padding-left:18px;margin:6px 0} li{margin:3px 0}
</style>
<h1>${me.name}</h1><div class=muted><span id=npub>${S.group.npub}</span> · any 2 of 3 sign</div>
<div class=card><div id=members></div><div class=muted id=coord style="margin-top:8px"></div></div>
${pu ? `<div class=card id=pair><b>Add your phone</b><div class=grid style="margin-top:10px"><div class=qr>${pairQr}</div>
<div style="flex:1;min-width:220px">Open <b>Cosign</b> on your phone and scan this. It joins as the third member.<br><br>
<span class=muted>Whoever scans it first gets the phone's share, so only show it to the phone you mean.</span></div></div></div>` : ''}
<div class=card><b>Log in to a Nostr app</b><div class=grid style="margin-top:10px"><div class=qr>${bunkerQr}</div>
<div style="flex:1;min-width:220px">Use “remote signer” or “bunker” login and scan or paste:<br><code>${bunkerUri()}</code><br><br>
<span class=muted>Anyone with this link can ask to sign. What they get is decided below.</span></div></div></div>
<div class=card><b>What needs the phone</b><div style="margin-top:6px">Signed by the two servers without asking: <span id=auto></span>.</div>
<div style="margin-top:4px">Everything else — profile, follow list, deletions, DMs, relay list… — waits for you to tap Approve on the phone.</div></div>
<div class=card><b>Activity</b><ul id=act></ul></div>
<script>
async function tick(){const s=await (await fetch('/status')).json();
 document.getElementById('members').innerHTML=s.members.map(m=>'<div class=row><span class="dot '+(m.online?'on':'')+'"></span>'+m.name+(m.self?' <span class=muted>(this one)</span>':'')+(m.paired?'':' <span class=muted>— not paired</span>')+'</div>').join('');
 document.getElementById('coord').textContent=(s.coordinating?'Answering the bunker. ':'Standing by for the bunker. ')+s.relays.filter(r=>r.up).length+'/'+s.relays.length+' relays · '+s.apps+' app(s) connected';
 document.getElementById('auto').textContent=s.autoKinds.join(', ');
 document.getElementById('act').innerHTML=s.activity.map(a=>'<li><span class=muted>'+new Date(a.ts).toLocaleTimeString()+'</span> '+a.text+'</li>').join('')||'<li class=muted>nothing yet</li>';
 if(!s.pairing){const p=document.getElementById('pair'); if(p) location.reload();}}
tick(); setInterval(tick,2000);
</script>`;
};

createServer(async (req, res) => {
  if (req.url === '/status') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify(status())); }
  if (req.url === '/') { res.setHeader('content-type', 'text/html'); return res.end(await page()); }
  res.statusCode = 404; res.end();
}).listen(S.port, process.env.HOST ?? '127.0.0.1', () => console.log(`[${me.name}] http://localhost:${S.port}`));

const filters = [{ kinds: [KIND_MEMBER], '#p': [me.pk!] }, { kinds: [KIND_NIP46], '#p': [S.bunker.pk] }];
pool.start(filters);
note('started');
