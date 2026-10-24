// cosign.aaro.cc/servers: the public Cosign servers there are right now, found the way
// the app and the extension find them (servers.ts), each asked whether it's answering.
// Built into link/public/servers.js (see link/README or release.sh).

import { nip19 } from 'nostr-tools';
import { findServers, relayQuery, pingHost, type Server } from './servers.ts';

const $ = (id: string) => document.getElementById(id)!;
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const short = (npub: string) => npub.slice(0, 12) + '…' + npub.slice(-6);
const host = (s: Server) => s.nip05 ?? (s.https ? new URL(s.https).host : s.relays[0]?.replace('wss://', '') ?? 'a server');

async function main() {
  const all = (await findServers({ query: relayQuery(5000) })).filter(s => s.verified);
  const open = all.filter(s => s.enroll === 'open');
  const operators = new Set(open.map(s => s.operator));
  $('count').textContent = (open.length === 1 ? 'One public server so far.' : `${open.length} public servers`)
    + (open.length > 1 && operators.size === 1 ? ', all run by one operator.' : open.length > 1 ? `, run by ${operators.size} operator${operators.size === 1 ? '' : 's'}.` : '');
  $('list').innerHTML = all.map(s => `<div class="server" id="s-${s.pk}">
    <div class="name">${esc(host(s))} <span class="muted small" data-ms>checking…</span></div>
    <div class="muted small">Run by <a href="https://njump.me/${nip19.npubEncode(s.operator)}">${short(nip19.npubEncode(s.operator))}</a>
      · ${s.enroll === 'open' ? 'takes new accounts' : 'invite only'}${s.version ? ` · Cosign ${esc(s.version)}` : ''}</div>
    <div class="muted small">Relays: ${s.relays.map(r => esc(r.replace('wss://', ''))).join(', ')}</div>
  </div>`).join('') || '<p class="muted">None found right now.</p>';
  for (const s of all) void pingHost(s).then(ms => {
    const el = document.querySelector(`#s-${s.pk} [data-ms]`)!;
    el.textContent = ms === null ? 'not answering' : `answering · ${ms} ms`;
    el.className = ms === null ? 'warn small' : 'ok small';
  });
}
main().catch(e => { $('count').textContent = `Couldn't look: ${e?.message ?? e}`; });
