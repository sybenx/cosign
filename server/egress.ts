// What this server will connect to, when the address came from someone else: a relay a
// device, a site or an enrolling stranger named, or a phone's push endpoint. An open server
// must not be steerable into its own host or the operator's private network, so:
//
// - relays are wss:// only, and every address their name resolves to must be public (not
//   loopback, private, CGNAT/tailnet, link-local, ULA, or a cloud metadata address),
//   checked again at every connect, since a name can change what it points to;
// - the operator's own relay beside it (COSIGN_RELAY_MAP) and COSIGN_RELAY_ALLOW are
//   trusted as they are;
// - push endpoints are https:// on an allowed host (ntfy.sh, plus COSIGN_PUSH_HOSTS), with
//   the same address check, and never followed through a redirect.

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { normRelay } from './core/seal.ts';

const list = (v?: string) => (v ?? '').split(',').map(s => s.trim()).filter(Boolean);
const mapped = new Set(list(process.env.COSIGN_RELAY_MAP).filter(x => x.includes('=')).map(x => normRelay(x.split('=', 2)[0])));
const allowRelays = new Set(list(process.env.COSIGN_RELAY_ALLOW).map(normRelay));
const pushHosts = new Set(['ntfy.sh', ...list(process.env.COSIGN_PUSH_HOSTS)].map(h => h.toLowerCase()));

/** True for an address that isn't on the public internet. */
export function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  const v = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (v === '::' || v === '::1') return true;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (m) return isPrivateAddress(m[1]);
  return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(v) || v.startsWith('64:ff9b:');
}

/** A relay others could reach, by its name alone (no lookup): wss://, not loopback, private or tailnet. */
export function looksPublic(url: string): boolean {
  let p: URL;
  try { p = new URL(url); } catch { return false; }
  const h = p.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (p.protocol !== 'wss:' || h === 'localhost' || /\.(localhost|local|internal|lan|home|ts\.net)$/.test(h) || (!h.includes('.') && !h.includes(':'))) return false;
  return !isIP(h) || !isPrivateAddress(h);
}

/** Every address this name stands for is public. An IP literal is checked as it is. */
async function publicHost(host: string): Promise<boolean> {
  const h = host.replace(/^\[|\]$/g, '');
  if (isIP(h)) return !isPrivateAddress(h);
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.ts.net')) return false;
  try {
    const all = await lookup(h, { all: true, verbatim: true });
    return all.length > 0 && all.every(a => !isPrivateAddress(a.address));
  } catch { return false; }
}

/** May this server open a connection to this relay? Asked at every connect. */
export async function relayAllowed(url: string): Promise<boolean> {
  const u = normRelay(url);
  if (mapped.has(u) || allowRelays.has(u)) return true;
  let p: URL;
  try { p = new URL(u); } catch { return false; }
  if (p.protocol !== 'wss:' || p.username || p.password || u.length > 200) return false;
  return publicHost(p.hostname);
}

/** Only the relays in `urls` this server may use. */
export async function allowedRelays(urls: string[]): Promise<string[]> {
  const ok = await Promise.all(urls.map(relayAllowed));
  return urls.filter((_, i) => ok[i]);
}

/** May this server POST to this push endpoint? */
export async function pushAllowed(url: string): Promise<boolean> {
  let p: URL;
  try { p = new URL(url); } catch { return false; }
  if (p.protocol !== 'https:' || p.username || p.password || !pushHosts.has(p.hostname.toLowerCase())) return false;
  return publicHost(p.hostname);
}
