// Add this module to the EXISTING Cloudflare Worker project; do not replace its Gemini code.
// npm install @block65/webcrypto-web-push
import { buildPushPayload } from '@block65/webcrypto-web-push';

const PUSH_ALLOWED_ORIGIN = 'https://894-tt.github.io';
const corsHeaders = {'Access-Control-Allow-Origin':PUSH_ALLOWED_ORIGIN,'Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Max-Age':'86400','Vary':'Origin'};
const json = (data, status=200) => new Response(JSON.stringify(data), {status,headers:{...corsHeaders,'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function hashToken(token) { return b64url(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))); }
function validSubscription(s) {
  try { const u=new URL(s.endpoint); return u.protocol==='https:' && typeof s.keys?.p256dh==='string' && typeof s.keys?.auth==='string'; } catch { return false; }
}
function localParts(date=new Date()) {
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Tokyo',year:'numeric',month:'2-digit',day:'2-digit',weekday:'short',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(date);
  return Object.fromEntries(parts.map(p=>[p.type,p.value]));
}
function dateAfterDays(iso, days) { const [y,m,d]=iso.split('-').map(Number); const dt=new Date(Date.UTC(y,m-1,d+days)); return `${dt.getUTCFullYear()}-${String(dt.getUTCMonth()+1).padStart(2,'0')}-${String(dt.getUTCDate()).padStart(2,'0')}`; }
const DOW_JA=['日','月','火','水','木','金','土'];
function weekdayForIso(iso) { const [y,m,d]=iso.split('-').map(Number); return new Date(Date.UTC(y,m-1,d)).getUTCDay(); }
function formatTomorrow(events, settings, tomorrow) {
  const [y,m,d]=tomorrow.split('-').map(Number); const dow=DOW_JA[weekdayForIso(tomorrow)];
  const selected=events.filter(e=>e.dateKey===tomorrow).sort((a,b)=>slotNum(a.slot)-slotNum(b.slot));
  const lines=[`明日(${m}/${String(d).padStart(2,'0')} ${dow})の予定です。`];
  const inc=settings.include||{};
  const labels=[['items','持ち物'],['homework','宿題'],['quiz','小テスト'],['location','場所'],['forgotten','忘れ物'],['notes','備考']];
  const detail=[];
  for(const [key,label] of labels) if(inc[key]) {
    const vals=selected.filter(e=>String(e[key]||'').trim()).map(e=>`${e.subject}: ${String(e[key]).trim()}`);
    if(vals.length) detail.push(`${label}: ${vals.join(' / ')}`);
  }
  if(detail.length) lines.push(detail.join('\n'));
  if(inc.schedule) {
    const periods=selected.filter(e=>e.subject).map(e=>`${e.slot}${e.endSlot&&e.endSlot!==e.slot?`〜${e.endSlot}`:''}: ${e.subject}${inc.location&&e.location?` (${e.location})`:''}`);
    if(periods.length) lines.push(periods.join('\n'));
  }
  return lines.join('\n\n').slice(0,3500);
}
function slotNum(v) { const n=Number(String(v||'').match(/[1-7]/)?.[0]); return Number.isFinite(n)?n:0; }

export async function handlePushRequest(request, env) {
  const url=new URL(request.url);
  if(!url.pathname.startsWith('/api/push/')) return null;
  if(request.headers.get('Origin')!==PUSH_ALLOWED_ORIGIN) return json({error:'Origin not allowed'},403);
  if(request.method==='OPTIONS') return new Response(null,{status:204,headers:corsHeaders});
  if(request.method!=='POST') return json({error:'Method not allowed'},405);
  let body; try { body=await request.json(); } catch { return json({error:'Invalid JSON'},400); }
  if(url.pathname==='/api/push/subscribe') {
    const token=String(body.token||'');
    if(!/^[a-f0-9]{64}$/.test(token) || !validSubscription(body.subscription)) return json({error:'Invalid subscription'},400);
    const settings=body.settings||{};
    if(!/^\d{2}:\d{2}$/.test(settings.time||'') || !Array.isArray(settings.days) || !settings.include) return json({error:'Invalid settings'},400);
    const tokenHash=await hashToken(token);
    await env.DB.prepare(`INSERT INTO push_devices(token_hash,subscription_json,settings_json,events_json,updated_at)
      VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(token_hash) DO UPDATE SET subscription_json=excluded.subscription_json,settings_json=excluded.settings_json,events_json=excluded.events_json,updated_at=CURRENT_TIMESTAMP`)
      .bind(tokenHash,JSON.stringify(body.subscription),JSON.stringify(settings),JSON.stringify(Array.isArray(body.events)?body.events:[])).run();
    return json({ok:true});
  }
  const auth=request.headers.get('Authorization')||'';
  const token=auth.startsWith('Bearer ')?auth.slice(7):'';
  if(!/^[a-f0-9]{64}$/.test(token)) return json({error:'Unauthorized'},401);
  const tokenHash=await hashToken(token);
  if(url.pathname==='/api/push/schedule') {
    const result=await env.DB.prepare('UPDATE push_devices SET events_json=?,updated_at=CURRENT_TIMESTAMP WHERE token_hash=?')
      .bind(JSON.stringify(Array.isArray(body.events)?body.events.slice(0,500):[]),tokenHash).run();
    return json({ok:true,updated:result.meta?.changes||0});
  }
  if(url.pathname==='/api/push/unsubscribe') {
    await env.DB.prepare('DELETE FROM push_devices WHERE token_hash=?').bind(tokenHash).run();
    return json({ok:true});
  }
  return json({error:'Not found'},404);
}

export async function sendScheduledPushes(env) {
  if(!env.DB || !env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !env.VAPID_SUBJECT) throw new Error('Missing D1 or VAPID configuration');
  const now=localParts(); const today=`${now.year}-${now.month}-${now.day}`; const tomorrow=dateAfterDays(today,1);
  const rows=await env.DB.prepare('SELECT token_hash,subscription_json,settings_json,events_json,last_sent_date FROM push_devices').all();
  for(const row of rows.results||[]) {
    let settings,subscription,events;
    try { settings=JSON.parse(row.settings_json); subscription=JSON.parse(row.subscription_json); events=JSON.parse(row.events_json||'[]'); } catch { continue; }
    if(!settings.enabled || settings.time!==`${now.hour}:${now.minute}` || !(settings.days||[]).includes(weekdayForIso(today)) || row.last_sent_date===today) continue;
    if(!events.some(e=>e.dateKey===tomorrow)) continue;
    const body=formatTomorrow(events,settings,tomorrow);
    if(!body) continue;
    const message={data:JSON.stringify({title:'明日の時間割',body,url:'./',sound:settings.sound!==false}),options:{ttl:60*60,urgency:'high'}};
    try {
      const payload=await buildPushPayload(message,subscription,{subject:env.VAPID_SUBJECT,publicKey:env.VAPID_PUBLIC_KEY,privateKey:env.VAPID_PRIVATE_KEY});
      const response=await fetch(subscription.endpoint,payload);
      if(response.status===404||response.status===410) { await env.DB.prepare('DELETE FROM push_devices WHERE token_hash=?').bind(row.token_hash).run(); continue; }
      if(!response.ok) throw new Error(`Push service returned ${response.status}`);
      await env.DB.prepare('UPDATE push_devices SET last_sent_date=?,updated_at=CURRENT_TIMESTAMP WHERE token_hash=?').bind(today,row.token_hash).run();
    } catch(err) { console.error('Push delivery failed',row.token_hash,err); }
  }
}
