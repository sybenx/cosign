// The status pages, as HTML: one per group (what a server has always shown), and a
// shared server's list of the groups it serves. No I/O: the host serves them.

import QRCode from 'qrcode';

export const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

const STYLE = `
 body{font:15px/1.45 system-ui,sans-serif;background:#13110f;color:#ede6da;max-width:760px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:0 0 8px;color:#a69d90;font-weight:600}
 .muted{color:#a69d90} .card{background:#1e1b18;border:1px solid #2a2622;border-radius:12px;padding:16px;margin:14px 0}
 .row{display:flex;gap:10px;align-items:center;margin:6px 0} .dot{width:9px;height:9px;border-radius:50%;background:#4a443c;flex:none} .on{background:#7fc8c0}
 .qr{background:#fff;padding:10px;border-radius:10px;width:220px} .grid{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start}
 button{background:none;border:1px solid #5a4520;color:#e9cf97;border-radius:8px;padding:5px 12px;font:inherit;cursor:pointer}
 .site{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-top:1px solid #2a2622} .site:first-child{border-top:0}
 .open{display:inline-block;background:#7fc8c0;color:#13110f;border-radius:8px;padding:8px 14px;text-decoration:none;font-weight:600;margin-top:6px}
 .held{color:#f2b33d} ul{padding-left:18px;margin:4px 0} li{margin:3px 0}
`;

// Its script asks for "status" and "revoke" beside the page, so it works at / (one group
// on its own port) and at /g/<id>/ (one of a shared server's).
/** One group's page: its members, the code to add your phone while it waits, sites, changes. */
export const groupPage = async (g: { name: string; npub: string; pairingUri: string | null }) => {
  const pu = g.pairingUri;
  const pairQr = pu ? await QRCode.toString(pu, { type: 'svg', margin: 1 }) : '';
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(g.name)} · cosign</title>
<style>${STYLE}</style>
<h1>${esc(g.name)}</h1><div class=muted>${esc(g.npub)} · 2 of 3</div>
<div class=card><div id=members></div><div class=muted id=coord style="margin-top:6px"></div></div>
${pu ? `<div class=card id=pair><h2>Add your phone</h2><div class=grid><div class=qr>${pairQr}</div>
<div style="flex:1;min-width:220px">Open <b>Cosign</b> on your phone and scan this. It becomes the third member and your remote control.<br><br>
Already on your phone? <a class=open href="${esc(pu)}">Open in Cosign</a><br><br>
<span class=muted>Whoever scans it (or opens it) first becomes that member, so only show it to your phone.</span></div></div></div>` : ''}
<div class=card><h2>Sites that can sign as you</h2><div id=sites></div></div>
<div class=card><h2>Recent changes to your lists</h2><ul id=changes></ul></div>
<div class=card><h2>Activity</h2><ul id=act></ul></div>
<script>
const $=id=>document.getElementById(id);
async function revoke(pk){ await fetch('revoke',{method:'POST',body:pk}); tick(); }
async function tick(){const s=await (await fetch('status')).json();
 $('members').innerHTML=s.members.map(m=>'<div class=row><span class="dot '+(m.online?'on':'')+'"></span>'+m.name+(m.self?' <span class=muted>(this one)</span>':'')+(m.paired?'':' <span class=muted>— not added</span>')+'</div>').join('');
 $('coord').textContent=(s.coordinating?'Answering your sites. ':'Standing by. ')+s.relays.filter(r=>r.up).length+'/'+s.relays.length+' relays · Cosign '+s.version+' · running since '+new Date(s.started).toLocaleTimeString();
 const groups={};for(const x of s.sites)(groups[x.origin]??=[]).push(x);
 $('sites').innerHTML=Object.entries(groups).map(([o,g])=>'<div class=site style="display:block"><div>'+o+'</div>'+g.map(x=>'<div class=row style="justify-content:space-between"><span class=muted style="font-size:13px">'+x.via+' · used '+x.lastUsed+'</span><button data-pk="'+x.pk+'">Remove</button></div>').join('')+'</div>').join('')||'<div class=muted>None yet. Scan a site’s code with your phone.</div>';
 for(const b of document.querySelectorAll('button[data-pk]')) b.onclick=()=>revoke(b.dataset.pk);
 $('changes').innerHTML=s.changes.map(c=>'<li class="'+(c.held?'held':'')+'">'+c.text+' <span class=muted>· '+c.by+' · '+c.when+(c.undone?' · undone':'')+'</span></li>').join('')||'<li class=muted>None yet.</li>';
 $('act').innerHTML=s.activity.map(a=>'<li><span class=muted>'+new Date(a.ts).toLocaleTimeString()+'</span> '+a.text+'</li>').join('')||'<li class=muted>Nothing yet.</li>';
 if(!s.pairing&&$('pair'))location.reload();}
tick(); setInterval(tick,2000);
</script>`;
};

/** A shared server's own page: its host key, who may enroll, and every group it serves. */
export const hostPage = (h: { pk: string | null; enroll: string | null; relays: string[]; version: string }) => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>cosign server</title>
<style>${STYLE}</style>
<h1>Cosign server</h1><div class=muted id=sum></div>
${h.pk ? `<div class=card><h2>Taking on new groups</h2>
<div>${h.enroll === 'open' ? 'Anyone can enroll a new group here.' : 'Only devices on the invite list can enroll a new group here.'}</div>
<div class=muted style="font-size:13px;word-break:break-all;margin-top:6px">Host key ${h.pk}<br>on ${h.relays.map(esc).join(', ')}</div></div>` : ''}
<div class=card><h2>Groups</h2><div id=groups></div></div>
<script>
const $=id=>document.getElementById(id);
async function tick(){const s=await (await fetch('status')).json();
 $('sum').textContent=s.groups.length+' group'+(s.groups.length===1?'':'s')+' · '+s.relays.filter(r=>r.up).length+'/'+s.relays.length+' relays · Cosign '+s.version+' · running since '+new Date(s.started).toLocaleTimeString();
 $('groups').innerHTML=s.groups.map(g=>'<div class=site><div><a style="color:inherit" href="g/'+g.id+'/">'+g.me+'</a> <span class=muted style="font-size:13px">'+(g.npub?g.npub.slice(0,20)+'…':'no key yet')+'</span><div class=muted style="font-size:13px">'+g.online+'/'+g.members+' members online · '+g.sites+' site'+(g.sites===1?'':'s')+(g.coordinating?' · answering sites':'')+'</div></div></div>').join('')||'<div class=muted>None yet.</div>';}
tick(); setInterval(tick,2000);
</script>`;
