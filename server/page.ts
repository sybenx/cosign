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
export const groupPage = async (g: { name: string; npub: string | null; threshold: number; pairingUri: string | null }) => {
  const pu = g.pairingUri;
  const pairQr = pu ? await QRCode.toString(pu, { type: 'svg', margin: 1 }) : '';
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(g.name)} · cosign</title>
<style>${STYLE}</style>
<h1>${esc(g.name)}</h1><div class=muted>${esc(g.npub ?? 'No key yet: add your phone to make it')} · ${g.threshold === 4 ? 'your phone + a server' : '2 of 3'}</div>
<div class=card><div id=members></div><div class=muted id=coord style="margin-top:6px"></div></div>
${pu ? `<div class=card id=pair><h2>Add your phone</h2><div class=grid><div class=qr>${pairQr}</div>
<div style="flex:1;min-width:220px">Scan this with your phone. It becomes your remote control: it approves anything destructive, and holds its own part of your account.<br><br>
Already on your phone? <a class=open href="${esc(pu)}">Open your sign-in app</a><br><br>
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

/**
 * A shared server's own page: what the person running it opens (Umbrel, Docker). Plain
 * words only, as a person reads it: no "signer", "Nostr", "key" or "relay" outside
 * Advanced. The host serves it behind whatever login it has (Umbrel's, a tunnel), so the
 * page may change its settings (POST /settings) and stop serving an account
 * (POST /remove-account).
 */
export const hostPage = async (h: { pk: string | null; relays: string[]; version: string; addUri: string | null }) => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Your server</title>
<style>${STYLE}
 details{margin:14px 0} summary{cursor:pointer;color:#a69d90} .small{font-size:13px}
 label{display:flex;gap:9px;align-items:flex-start;padding:7px 0;cursor:pointer}
 label input{margin:3px 0 0} label b{font-weight:600} label .small{display:block;color:#a69d90}
 input[type=text],textarea{background:#13110f;border:1px solid #2a2622;color:#ede6da;border-radius:8px;padding:7px 9px;font:inherit;width:100%;box-sizing:border-box}
 textarea{min-height:80px;font-size:13px}
 .go{background:#7fc8c0;border-color:#7fc8c0;color:#13110f;font-weight:600}
 .danger{border-color:#7a3a30;color:#f0a090}
 .warn{color:#f2b33d;font-size:13px;margin-top:8px}
 .acct{display:flex;gap:10px;align-items:center;padding:10px 0;border-top:1px solid #2a2622} .acct:first-child{border-top:0}
 .acct img{width:30px;height:30px;border-radius:50%;flex:none;background:#2a2622;object-fit:cover}
 .acct .who{flex:1;min-width:0} .acct .who a{color:inherit;text-decoration:none} .acct .who a:hover{text-decoration:underline}
 .nowrap{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .ok{color:#7fc8c0;font-size:13px;margin-top:8px}
</style>
<h1>Your server is running</h1><div class=row><span class="dot on" id=dot></span><span class=muted id=sum>Starting…</span></div>

${h.addUri ? `<div class=card><h2>Add this server to your account</h2><div class=grid><div class=qr>${await QRCode.toString(h.addUri, { type: 'svg', margin: 1 })}</div>
<div style="flex:1;min-width:220px">Open your sign-in app, go to <b>Add a server</b>, and scan this. Your account then uses this server too: it signs with your phone, and never on its own.<br><br>
<span class="muted small">This code works once, and only on this server. It stops working an hour after it appeared; reload for a new one.</span><br>
<a class=open href="${esc(h.addUri)}">Open it on this device</a></div></div></div>` : ''}

<div class=card><h2>Accounts using this server</h2><div id=groups></div>
<div class="muted small" id=helped style="margin-top:8px"></div></div>

<div class=card><h2>Who can join</h2><div id=who></div></div>

<details><summary>Advanced</summary><div class=card>
<div class=row><span class=muted>Version</span><span style="margin-left:auto">Cosign ${esc(h.version)}</span></div>
${h.pk ? `<div class="muted small" style="word-break:break-all;margin-top:8px">Server ID ${esc(h.pk)}<br>Relays: ${h.relays.map(esc).join(', ')}</div>` : ''}
<div class="muted small" style="margin-top:8px" id=adv></div>
</div></details>

<details><summary>What is this?</summary><div class=card>
<p style="margin-top:0">Your account is split between your phone and servers like this one. Your phone and any one server can act for you; the servers alone never can, and no one place ever holds your whole account.</p>
<p>Running this server means your own account doesn't depend on anyone else's, and other people can use it too if you let them.</p>
<a class=open href="https://cosign.aaro.cc">Get Marble</a></div></details>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let confirming=null, shown='', said='', fade=0;
const typing=()=>{const a=document.activeElement;return a&&$('who').contains(a)&&(a.tagName==='TEXTAREA'||(a.tagName==='INPUT'&&a.type==='text'));};

const MODES=[
 ['owner','Only me','Nobody else can make an account here. Show someone the code above and they can.'],
 ['follows','People I follow','Anyone you follow can add this server to an account they already have.'],
 ['invite','People I invite','Only the people you list below, with an account they already have.'],
 ['anyone-placeholder','',''],
];
const ANYONE=['open','Anyone','This server is public, and listed for everyone to pick.'];

async function post(path,body){
 const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 return await r.json().catch(()=>({ok:false,reason:'That did not go through.'}));
}
async function save(body,note){
 const r=await post('settings',body);
 said=r.ok?(note||'Saved.'):('That did not save: '+(r.reason||''));
 shown=''; tick();
 clearTimeout(fade); fade=setTimeout(()=>{said='';shown='';tick();},6000);
}
function joinCard(j){
 const pin=j.pinned, rows=[...MODES.slice(0,3),ANYONE];
 let html=rows.map(([v,t,d])=>'<label><input type=radio name=mode value="'+v+'"'+(j.enroll===v?' checked':'')+(pin.enroll?' disabled':'')+'><span><b>'+t+'</b><span class=small>'+d+'</span></span></label>').join('');
 if(j.enroll==='follows'){
  html+='<div style="margin:10px 0 0"><div class="muted small" style="margin-bottom:5px">Your npub, so this server knows who you follow'+(j.ownerIsOperator?' (from the operator it announces)':'')+'</div>'
   +'<div class=row><input type=text id=owner placeholder="npub1…" value="'+esc(j.owner||'')+'"'+(pin.owner?' disabled':'')+'><button class=go id=saveowner'+(pin.owner?' disabled':'')+'>Save</button></div>';
  if(!j.owner) html+='<div class=warn>Until you put your npub here, only a code from this page works.</div>';
  html+='</div>';
 }
 if(j.enroll==='invite'){
  html+='<div style="margin:10px 0 0"><div class="muted small" style="margin-bottom:5px">The npubs you invite, one per line</div>'
   +'<textarea id=invites placeholder="npub1…"'+(pin.invites?' disabled':'')+'>'+esc((j.invites||[]).join('\\n'))+'</textarea>'
   +'<div class=row style="margin-top:6px"><button class=go id=saveinvites'+(pin.invites?' disabled':'')+'>Save</button>'
   +'<span class="muted small">'+(j.invites||[]).length+' invited</span></div></div>';
 }
 if(j.enroll==='open') html+='<div class=warn>Anyone means strangers keep pieces of their accounts on this machine. That belongs on a server you rent, with its outgoing connections limited — not at home.</div>';
 if(said) html+='<div class='+(said.startsWith('Saved')?'ok':'warn')+'>'+esc(said)+'</div>';
 if(j.enroll!=='open') html+='<div class="muted small" style="margin-top:10px">A brand-new account always needs a code from this page: a key that does not exist yet has no name to go by. The choice above is for people bringing an account they already have.</div>';
 if(pin.enroll) html+='<div class="muted small" style="margin-top:10px">This was set where the server was started, so it can only be changed there.</div>';
 html+='<div class="muted small" style="margin-top:10px">You can see what people sign through this server, and nothing else: never their messages, and never enough of an account to act as them.</div>';
 return html;
}
function wireJoin(){
 for(const r of document.querySelectorAll('input[name=mode]')) r.onchange=()=>save({enroll:r.value});
 const o=$('saveowner'); if(o) o.onclick=()=>save({owner:$('owner').value.trim()},'Saved. This server now knows who you follow.');
 const i=$('saveinvites'); if(i) i.onclick=()=>save({invites:$('invites').value.split('\\n').map(s=>s.trim()).filter(Boolean)});
}
function acct(g){
 const who=g.name||(g.npub?g.npub.slice(0,16)+'…':'not set up yet');
 const pic=g.picture?'<img src="'+esc(g.picture)+'" referrerpolicy=no-referrer loading=lazy alt="" onerror="this.removeAttribute(\\'src\\')">':'<img alt="">';
 const line=g.pairing?'waiting for its phone'
  :[g.devices+' device'+(g.devices===1?'':'s'),g.otherServers+' other server'+(g.otherServers===1?'':'s'),g.sites?g.sites+' site'+(g.sites===1?'':'s'):''].filter(Boolean).join(' · ');
 if(confirming===g.id){
  const risk=g.otherServers?'They keep '+g.otherServers+' other server'+(g.otherServers===1?'':'s')+', so their account goes on working.'
   :'This is the only server left in their account: without it they cannot sign at all until they use their paper backup.';
  return '<div class=acct style="display:block"><div><b>Stop serving '+esc(who)+'?</b></div>'
   +'<div class="muted small" style="margin:4px 0 8px">'+risk+' This server tells their app, then deletes its piece of their account. It cannot be undone from here — they would have to add this server again.</div>'
   +'<div class=row><button class=danger data-go="'+g.id+'">Yes, stop serving it</button><button data-keep=1>Keep it</button></div></div>';
 }
 return '<div class=acct>'+pic+'<div class="who nowrap"><a href="g/'+g.id+'/">'+esc(who)+'</a>'
  +'<div class="muted small nowrap">'+line+'</div></div>'
  +'<button data-rm="'+g.id+'">Remove</button></div>';
}
async function tick(){const s=await (await fetch('status')).json();
 const up=s.relays.filter(r=>r.up).length;
 $('dot').className='dot'+(up?' on':'');
 $('sum').textContent=(up?'Connected':'Reconnecting…')+' · '+s.groups.length+' account'+(s.groups.length===1?'':'s')+' · since '+new Date(s.started).toLocaleTimeString();
 $('groups').innerHTML=s.groups.map(acct).join('')||'<div class=muted>None yet. Add yours with the code above.</div>';
 for(const b of document.querySelectorAll('button[data-rm]')) b.onclick=()=>{confirming=b.dataset.rm;tick();};
 for(const b of document.querySelectorAll('button[data-keep]')) b.onclick=()=>{confirming=null;tick();};
 for(const b of document.querySelectorAll('button[data-go]')) b.onclick=async()=>{b.disabled=true;await post('remove-account',{id:b.dataset.go});confirming=null;tick();};
 const n=s.groups.reduce((a,g)=>a+(g.signedToday||0),0);
 $('helped').textContent=n?('Helped sign '+n+' time'+(n===1?'':'s')+' today.'):'';
 // Left alone while something in it is being typed, so no half-written list is lost.
 if(s.join){
  const j=JSON.stringify(s.join)+said;
  if(j!==shown&&!typing()){ $('who').innerHTML=joinCard(s.join); wireJoin(); shown=j; }
  $('adv').textContent='New accounts: '+s.join.name+' (announced as '+s.join.announced+'), plus a code from this page.';
 }}
tick(); setInterval(tick,2000);
</script>`;
