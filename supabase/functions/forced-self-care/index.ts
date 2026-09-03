import 'jsr:@supabase/functions-js/edge-runtime.d.ts'
import { createClient } from 'jsr:@supabase/supabase-js@2'
import webpush from 'npm:web-push@3.6.7'

const db = () => createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  { auth: { autoRefreshToken: false, persistSession: false } },
)

const headers = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'access-control-allow-origin': 'https://evorah78.github.io',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type, x-fsc-session',
  'vary': 'origin',
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers })
const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
const sha256 = async (value: string) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))
const randomHex = (length = 32) => hex(crypto.getRandomValues(new Uint8Array(length)))
const VAPID_PUBLIC_KEY = 'BBq5eqs-4gZcXx31wYiJjdPeEl7TbyiCkLOHm4xpTRy1UB0TqIMnNUzWojL1olMWQcZ4-9OGa6jHi6SZHuxe0Ao'

let secretsPromise: Promise<{ vapidPrivateKey: string; reminderSecret: string }> | null = null
function runtimeSecrets() {
  if (!secretsPromise) secretsPromise = (async () => {
    const { data, error } = await db().from('fsc_settings').select('vapid_private_key,reminder_secret').eq('id', 1).single()
    if (error || !data?.vapid_private_key || !data?.reminder_secret) throw error || new Error('Notification secrets are not configured')
    return { vapidPrivateKey: data.vapid_private_key, reminderSecret: data.reminder_secret }
  })()
  return secretsPromise
}

type PushRow = { id: number; role: 'monitor' | 'taker'; endpoint: string; p256dh: string; auth: string }

async function pushTo(rows: PushRow[], payload: { title: string; body: string; tag: string; url?: string }, key: string) {
  const admin = db()
  const { vapidPrivateKey } = await runtimeSecrets()
  webpush.setVapidDetails('mailto:info@evorah.co.uk', VAPID_PUBLIC_KEY, vapidPrivateKey)
  for (const row of rows) {
    const notificationKey = `${key}:${row.id}`
    const { error: logError } = await admin.from('fsc_notification_log').insert({
      notification_key: notificationKey, notification_type: payload.tag, role: row.role,
    })
    if (logError?.code === '23505') continue
    if (logError) throw logError
    try {
      await webpush.sendNotification(
        { endpoint: row.endpoint, keys: { p256dh: row.p256dh, auth: row.auth } },
        JSON.stringify({ ...payload, url: payload.url || './' }),
        { TTL: 3600 },
      )
    } catch (error: any) {
      if ([404, 410].includes(Number(error?.statusCode))) await admin.from('fsc_push_subscriptions').delete().eq('id', row.id)
      else console.error('Push delivery failed', error)
    }
  }
}

async function pushRoles(roles: Array<'monitor' | 'taker'>, payload: { title: string; body: string; tag: string }, key: string) {
  const { data, error } = await db().from('fsc_push_subscriptions').select('id,role,endpoint,p256dh,auth').in('role', roles)
  if (error) throw error
  await pushTo((data || []) as PushRow[], payload, key)
}

async function pinHash(pin: string, salt: string) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 160000, hash: 'SHA-256' },
    key,
    256,
  )
  return hex(new Uint8Array(bits))
}

function londonDate(offsetDays = 0) {
  const shifted = new Date(Date.now() + offsetDays * 86400000)
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/London', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(shifted)
  const get = (type: string) => parts.find((p) => p.type === type)?.value
  return `${get('year')}-${get('month')}-${get('day')}`
}

async function session(request: Request, bodyToken = '') {
  const token = bodyToken || request.headers.get('x-fsc-session') || ''
  if (!token) return null
  const tokenHash = await sha256(token)
  const { data } = await db().from('fsc_sessions').select('role,expires_at').eq('token_hash', tokenHash).maybeSingle()
  if (!data || new Date(data.expires_at) <= new Date()) return null
  return { role: data.role as 'monitor' | 'taker', tokenHash }
}

async function issueSession(role: 'monitor' | 'taker') {
  const token = randomHex(32)
  const tokenHash = await sha256(token)
  const expiresAt = new Date(Date.now() + 30 * 86400000).toISOString()
  const { error } = await db().from('fsc_sessions').insert({ token_hash: tokenHash, role, expires_at: expiresAt })
  if (error) throw error
  return token
}

const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#52c7b4"/><stop offset=".48" stop-color="#82a8c9"/><stop offset="1" stop-color="#c78ac7"/></linearGradient><linearGradient id="b" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#a8e3d7"/><stop offset=".52" stop-color="#f8e7dc"/><stop offset="1" stop-color="#c8b5e8"/></linearGradient></defs>
<rect width="512" height="512" rx="104" fill="url(#b)"/><rect x="45" y="45" width="422" height="422" rx="88" fill="#fff"/>
<path d="M256 401C221 371 121 305 121 204c0-59 68-95 119-43l16 18 16-18c51-52 119-16 119 43 0 101-100 167-135 197Z" fill="none" stroke="url(#g)" stroke-width="13" stroke-linecap="round" stroke-linejoin="round"/>
<g transform="rotate(-42 256 254)" fill="none" stroke="url(#g)" stroke-width="13"><rect x="210" y="213" width="92" height="82" rx="39"/><path d="M256 213v82"/></g></svg>`

const manifest = {
  name: 'Forced Self Care', short_name: 'Self Care', start_url: '.', display: 'standalone',
  background_color: '#f7fbfa', theme_color: '#77bfb4',
  icons: [{ src: '?asset=icon', sizes: '512x512', type: 'image/svg+xml', purpose: 'any maskable' }],
}

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#77bfb4"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="default"><link rel="manifest" href="?asset=manifest"><link rel="apple-touch-icon" href="?asset=icon"><title>Forced Self Care</title>
<style>
:root{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",Inter,Arial,sans-serif;color:#263f43;background:#edf6f4;line-height:1.4}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 10% 0,#cceee8 0,transparent 38%),radial-gradient(circle at 95% 10%,#f6ddd3 0,transparent 34%),linear-gradient(160deg,#f8fcfb,#f6f1fb);padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}button,input,textarea{font:inherit}.shell{max-width:560px;margin:auto;min-height:100vh;padding:22px 18px 100px}.brand{display:flex;align-items:center;gap:13px;margin:6px 0 25px}.brand img{width:62px;height:62px;border-radius:16px;box-shadow:0 8px 24px #5d8d8730}.brand h1{font-size:25px;margin:0;letter-spacing:-.5px}.brand p{margin:2px 0 0;color:#688084;font-size:13px}.card{background:#ffffffdf;border:1px solid #ffffff;border-radius:25px;padding:20px;box-shadow:0 13px 40px #617b821c;backdrop-filter:blur(12px);margin-bottom:15px}.hero{text-align:center;padding:28px 22px}.hero img{width:104px;height:104px;border-radius:28px;box-shadow:0 12px 30px #759a9638}.hero h2{font-size:25px;margin:17px 0 4px}.muted{color:#718589}.role-grid{display:grid;grid-template-columns:1fr 1fr;gap:11px;margin:20px 0}.role{border:1.5px solid #dce9e7;background:#f9fcfb;border-radius:18px;padding:17px 10px;color:#38575a;font-weight:700}.role.active{border-color:#6cb7aa;background:#eaf7f4;color:#27685f}.pin{width:100%;text-align:center;letter-spacing:14px;font-size:28px;padding:15px;border:1.5px solid #d6e5e2;border-radius:17px;background:white;margin:10px 0}.primary,.secondary,.danger{width:100%;border:0;border-radius:16px;padding:15px;font-weight:750}.primary{background:linear-gradient(135deg,#5fb4a5,#839fc8);color:#fff;box-shadow:0 8px 20px #5e9d9440}.secondary{background:#edf5f3;color:#39645f}.danger{background:#fff0ef;color:#a24848}.topline{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}.badge{font-size:12px;font-weight:750;padding:7px 10px;border-radius:99px;background:#e9f6f3;color:#2d746a}.date{font-size:13px;color:#73878a}.progress{height:9px;background:#e7efee;border-radius:99px;overflow:hidden;margin:12px 0 5px}.progress span{display:block;height:100%;background:linear-gradient(90deg,#59b8a7,#8ca6d0);border-radius:99px}.med{display:grid;grid-template-columns:48px 1fr auto;gap:12px;align-items:center;padding:14px 4px;border-bottom:1px solid #edf1f1}.med:last-child{border-bottom:0}.med-icon{width:46px;height:46px;border-radius:15px;background:linear-gradient(145deg,#e4f7f3,#efeafa);display:grid;place-items:center;font-size:22px}.med h3{font-size:16px;margin:0}.med small{color:#7d8d90}.taken{color:#348274!important}.run_out,.not_taken{color:#b76258!important}.status{border:0;border-radius:13px;padding:10px 12px;background:#edf6f4;color:#356a64;font-weight:700;white-space:nowrap}.status.done{background:#dff3ed;color:#2c796b}.status.problem{background:#fff0ed;color:#a9574e}.menu{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:11px}.menu button{border:0;border-radius:13px;padding:11px 4px;font-size:12px;font-weight:700}.menu .yes{background:#e0f4ee;color:#2e796d}.menu .out{background:#fff1e8;color:#a85f37}.menu .no{background:#f7ecef;color:#98566a}.event{padding:11px 0;border-bottom:1px solid #edf1f1}.event:last-child{border:0}.event b{display:block;font-size:14px}.event small{color:#7b8d90}.notice{border-left:4px solid #d59d75;background:#fff8ef;padding:13px;border-radius:12px;color:#825d43;font-size:13px;margin:12px 0}.nav{position:fixed;left:50%;bottom:12px;transform:translateX(-50%);width:min(520px,calc(100% - 28px));display:grid;grid-template-columns:repeat(3,1fr);padding:7px;background:#ffffffed;border:1px solid white;border-radius:20px;box-shadow:0 12px 35px #435b6230;backdrop-filter:blur(15px)}.nav button{border:0;background:transparent;padding:10px 4px;border-radius:13px;color:#708488;font-size:12px;font-weight:700}.nav button.active{background:#e8f4f2;color:#36756c}.hidden{display:none!important}.modal{position:fixed;inset:0;background:#20363866;display:grid;align-items:end;z-index:20}.sheet{background:#fff;border-radius:28px 28px 0 0;padding:24px 20px calc(24px + env(safe-area-inset-bottom));max-width:560px;width:100%;margin:auto}.sheet h3{margin:0 0 6px}.sheet textarea{width:100%;min-height:95px;border:1.5px solid #d6e5e2;border-radius:15px;padding:13px;margin:12px 0}.error{color:#ad4d4d;font-size:13px;min-height:19px}.stack{display:grid;gap:10px}.empty{text-align:center;padding:27px;color:#7c8d90}@media(max-width:360px){.status{padding:9px 8px}.med{grid-template-columns:40px 1fr auto}.med-icon{width:40px;height:40px}}
</style></head><body><main class="shell"><header class="brand"><img src="?asset=icon" alt=""><div><h1>Forced Self Care</h1><p id="subtitle">A calmer daily routine</p></div></header><section id="app"></section></main><div id="modal" class="modal hidden"></div>
<script>
const API=location.origin+location.pathname, app=document.querySelector('#app'), modal=document.querySelector('#modal');let role='monitor',sessionToken=localStorage.getItem('fsc_session')||'',state=null;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(action,data={}){const r=await fetch(API,{method:'POST',headers:{'content-type':'application/json','x-fsc-session':sessionToken},body:JSON.stringify({action,...data})});const j=await r.json();if(!r.ok)throw new Error(j.error||'Something went wrong');return j}
function setupScreen(){app.innerHTML='<section class="card hero"><img src="?asset=icon"><h2>Create your private PINs</h2><p class="muted">Set one PIN for your monitoring phone and another for the medication taker.</p><div class="stack"><input id="mp" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••" aria-label="Monitor PIN"><input id="tp" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••" aria-label="Medication taker PIN"><button class="primary" id="create">Create Forced Self Care</button><div class="error" id="err"></div></div></section>';document.querySelector('#create').onclick=async()=>{try{const setupToken=new URLSearchParams(location.search).get('setup')||'';const j=await api('setup',{setupToken,monitorPin:mp.value,takerPin:tp.value});sessionToken=j.token;localStorage.setItem('fsc_session',sessionToken);history.replaceState({},'',location.pathname);await load()}catch(e){err.textContent=e.message}}}
function loginScreen(){app.innerHTML='<section class="card hero"><img src="?asset=icon"><h2>Welcome back</h2><p class="muted">Choose your role and enter your 4-digit PIN.</p><div class="role-grid"><button class="role active" data-role="monitor">Monitor</button><button class="role" data-role="taker">Medication taker</button></div><input id="pin" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••"><button class="primary" id="login">Unlock app</button><div class="error" id="err"></div></section>';document.querySelectorAll('.role').forEach(b=>b.onclick=()=>{role=b.dataset.role;document.querySelectorAll('.role').forEach(x=>x.classList.toggle('active',x===b))});login.onclick=async()=>{try{const j=await api('login',{role,pin:pin.value});sessionToken=j.token;localStorage.setItem('fsc_session',sessionToken);await load()}catch(e){err.textContent=e.message}}}
function medCard(m){const status=m.status||'';const label=status==='taken'?'Taken':status==='run_out'?'Run out':status==='not_taken'?'Not taken':'Confirm';return '<div class="med"><div class="med-icon">'+(status==='taken'?'✓':'◌')+'</div><div><h3>'+esc(m.name)+'</h3><small class="'+status+'">'+(m.reason?esc(m.reason):status==='taken'?'Confirmed '+new Date(m.updated_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}):'Daily')+'</small></div><button class="status '+(status==='taken'?'done':status?'problem':'')+'" onclick="toggleMenu('+m.id+')">'+label+'</button></div><div id="menu-'+m.id+'" class="menu hidden"><button class="yes" onclick="setStatus('+m.id+',&quot;taken&quot;)">Taken</button><button class="out" onclick="reason('+m.id+',&quot;run_out&quot;)">Run out</button><button class="no" onclick="reason('+m.id+',&quot;not_taken&quot;)">Not taken</button></div>'}
function mainScreen(){const taken=state.medications.filter(m=>m.status==='taken').length,total=state.medications.length,pct=Math.round(taken/total*100);app.innerHTML='<section id="today"><div class="topline"><div><span class="badge">'+(state.role==='monitor'?'Monitor':'Medication taker')+'</span></div><span class="date">'+new Date(state.date+'T12:00:00').toLocaleDateString('en-GB',{weekday:'short',day:'numeric',month:'short'})+'</span></div><section class="card"><div class="topline"><div><b>Today’s self care</b><div class="muted">'+taken+' of '+total+' taken</div></div><b>'+pct+'%</b></div><div class="progress"><span style="width:'+pct+'%"></span></div>'+state.medications.map(medCard).join('')+'</section>'+(state.role==='monitor'&&state.purchases.length?'<section class="card"><b>To buy</b>'+state.purchases.map(p=>'<div class="event"><b>'+esc(p.medication_name)+'</b><small>Reminder due '+new Date(p.due_date+'T14:00').toLocaleDateString('en-GB')+' at 2:00 pm</small></div>').join('')+'</section>':'')+'</section><section id="history" class="hidden"><section class="card"><b>Recent activity</b>'+(state.events.length?state.events.map(e=>'<div class="event"><b>'+esc(e.message)+'</b><small>'+new Date(e.created_at).toLocaleString('en-GB')+'</small></div>').join(''):'<div class="empty">No activity yet</div>')+'</section></section><section id="settings" class="hidden"><section class="card"><b>Account</b><p class="muted">Signed in as '+(state.role==='monitor'?'Monitor':'Medication taker')+'</p>'+(state.role==='monitor'?'<div class="notice">Only the Monitor account can reset the taker PIN or manage reminders.</div><button class="secondary" onclick="resetPin()">Reset medication-taker PIN</button>':'<div class="notice">Reminder controls are locked on this account.</div>')+'<button class="danger" style="margin-top:10px" onclick="logout()">Log out</button></section><section class="card"><b>Reminders</b><p>10:00 pm daily<br>11:00 pm if anything remains incomplete<br>2:00 pm next day when something runs out</p><div class="notice">Background push delivery is being connected and is not yet verified on both iPhones.</div></section></section><nav class="nav"><button class="active" onclick="tab(&quot;today&quot;,this)">Today</button><button onclick="tab(&quot;history&quot;,this)">History</button><button onclick="tab(&quot;settings&quot;,this)">Settings</button></nav>';document.querySelector('#subtitle').textContent=state.role==='monitor'?'Monitoring today’s routine':'Your daily routine'}
window.toggleMenu=id=>document.querySelector('#menu-'+id).classList.toggle('hidden');
window.setStatus=async(id,status,reason='')=>{try{await api('update',{medicationId:id,status,reason});await load()}catch(e){alert(e.message)}};
window.reason=(id,status)=>{const name=state.medications.find(m=>m.id===id)?.name||'Medication';modal.classList.remove('hidden');modal.innerHTML='<div class="sheet"><h3>'+esc(status==='run_out'?name+' has run out':'Why was '+name+' not taken?')+'</h3><p class="muted">A reason is required and the Monitor will see it.</p><textarea id="why" placeholder="Enter the reason"></textarea><div class="stack"><button class="primary" id="saveReason">Save reason</button><button class="secondary" onclick="closeModal()">Cancel</button></div></div>';saveReason.onclick=()=>{if(!why.value.trim())return alert('Please enter a reason');closeModal();setStatus(id,status,why.value.trim())}};
window.closeModal=()=>{modal.classList.add('hidden');modal.innerHTML=''};
window.tab=(id,b)=>{['today','history','settings'].forEach(x=>document.querySelector('#'+x).classList.toggle('hidden',x!==id));document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x===b))};
window.resetPin=()=>{modal.classList.remove('hidden');modal.innerHTML='<div class="sheet"><h3>Reset medication-taker PIN</h3><input id="newpin" class="pin" type="password" inputmode="numeric" maxlength="4" placeholder="••••"><div class="stack"><button class="primary" id="savePin">Save new PIN</button><button class="secondary" onclick="closeModal()">Cancel</button></div></div>';savePin.onclick=async()=>{try{await api('reset_taker_pin',{pin:newpin.value});closeModal();alert('Medication-taker PIN updated')}catch(e){alert(e.message)}}};
window.logout=async()=>{try{await api('logout')}catch{}localStorage.removeItem('fsc_session');sessionToken='';loginScreen()};
async function load(){try{state=await api('state');mainScreen()}catch{localStorage.removeItem('fsc_session');sessionToken='';loginScreen()}}
(async()=>{try{const s=await api('status');if(!s.initialized){if(new URLSearchParams(location.search).has('setup'))setupScreen();else app.innerHTML='<section class="card hero"><img src="?asset=icon"><h2>Setup link required</h2><p class="muted">Open the private setup link on the Monitor phone first.</p></section>'}else if(sessionToken)await load();else loginScreen()}catch(e){app.innerHTML='<section class="card"><b>Unable to open app</b><p>'+esc(e.message)+'</p></section>'}})();
</script></body></html>`

Deno.serve(async (request) => {
  const url = new URL(request.url)
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers })
  if (request.method === 'GET') {
    if (url.searchParams.get('asset') === 'manifest') return new Response(JSON.stringify(manifest), { headers: { 'content-type': 'application/manifest+json' } })
    if (url.searchParams.get('asset') === 'icon') return new Response(svgIcon, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'public,max-age=86400' } })
    return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } })
  }
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  try {
    const body = await request.json()
    const action = String(body.action || '')
    const admin = db()

    if (action === 'push_public_key') return json({ publicKey: VAPID_PUBLIC_KEY })

    if (action === 'reminders_tick') {
      const { reminderSecret } = await runtimeSecrets()
      if (String(body.secret || '') !== reminderSecret) return json({ error: 'Not allowed' }, 403)
      const parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Europe/London', hour: '2-digit', minute: '2-digit', hour12: false,
      }).formatToParts(new Date())
      const hour = Number(parts.find((p) => p.type === 'hour')?.value || -1)
      const minute = Number(parts.find((p) => p.type === 'minute')?.value || -1)
      const date = londonDate()
      const morningReminder = (minute === 30 && hour >= 8 && hour <= 14) || (hour === 15 && minute === 0)
      const magnesiumReminder = (hour === 22 && [0, 30].includes(minute)) || (hour === 23 && minute === 0)
      if (morningReminder || magnesiumReminder) {
        let medicationQuery = admin.from('fsc_medications').select('id,name').eq('active', true)
        medicationQuery = morningReminder ? medicationQuery.neq('name', 'Magnesium') : medicationQuery.eq('name', 'Magnesium')
        const { data: dueMedications, error: medicationError } = await medicationQuery.order('sort_order')
        if (medicationError) throw medicationError
        const medicationIds = (dueMedications || []).map((medication) => medication.id)
        let completedIds = new Set<number>()
        if (medicationIds.length) {
          const { data: completedRows, error: completedError } = await admin.from('fsc_daily_records')
            .select('medication_id,status,reason').eq('record_date', date).in('medication_id', medicationIds)
          if (completedError) throw completedError
          completedIds = new Set((completedRows || [])
            .filter((row) => row.status === 'taken' || ((row.status === 'run_out' || row.status === 'not_taken') && String(row.reason || '').trim()))
            .map((row) => Number(row.medication_id)))
        }
        const incomplete = (dueMedications || []).filter((medication) => !completedIds.has(Number(medication.id)))
        if (incomplete.length) {
          const slot = `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`
          await pushRoles(['taker'], {
            title: morningReminder ? 'Morning medication reminder' : 'Magnesium reminder',
            body: morningReminder ? `Still to take: ${incomplete.map((medication) => medication.name).join(', ')}.` : 'Magnesium is still waiting to be taken.',
            tag: morningReminder ? `morning-${slot}` : `magnesium-${slot}`,
          }, `${date}:${morningReminder ? 'morning' : 'magnesium'}:${slot}`)
          return json({ ok: true, sent: true })
        }
      }
      if (hour === 14 && minute === 0) {
        const { data: purchases } = await admin.from('fsc_purchase_reminders')
          .select('id,fsc_medications(name)').eq('due_date', date).is('resolved_at', null)
        if (purchases?.length) {
          const names = purchases.map((p: any) => p.fsc_medications?.name).filter(Boolean).join(', ')
          await pushRoles(['monitor'], {
            title: 'Restock reminder', body: `Buy: ${names || 'medication marked as run out'}.`, tag: 'restock',
          }, `${date}:restock`)
          return json({ ok: true, sent: true })
        }
      }
      return json({ ok: true, sent: false })
    }

    if (action === 'status') {
      const { data, error } = await admin.from('fsc_settings').select('initialized').eq('id', 1).single()
      if (error) throw error
      return json({ initialized: data.initialized })
    }

    if (action === 'setup') {
      const monitorPin = String(body.monitorPin || '')
      const takerPin = String(body.takerPin || '')
      if (!/^\d{4}$/.test(monitorPin) || !/^\d{4}$/.test(takerPin)) return json({ error: 'Both PINs must contain exactly 4 numbers' }, 400)
      if (monitorPin === takerPin) return json({ error: 'Use a different PIN for each role' }, 400)
      const { data: settings, error } = await admin.from('fsc_settings').select('*').eq('id', 1).single()
      if (error) throw error
      if (settings.initialized) return json({ error: 'The app has already been set up' }, 409)
      if (await sha256(String(body.setupToken || '')) !== settings.setup_token_hash) return json({ error: 'This setup link is not valid' }, 403)
      const monitorSalt = randomHex(16), takerSalt = randomHex(16)
      const { error: updateError } = await admin.from('fsc_settings').update({
        monitor_pin_hash: await pinHash(monitorPin, monitorSalt), monitor_pin_salt: monitorSalt,
        taker_pin_hash: await pinHash(takerPin, takerSalt), taker_pin_salt: takerSalt,
        initialized: true, setup_token_hash: await sha256(randomHex()), updated_at: new Date().toISOString(),
      }).eq('id', 1)
      if (updateError) throw updateError
      await admin.from('fsc_events').insert({ event_type: 'setup', role: 'system', message: 'Forced Self Care was set up' })
      return json({ token: await issueSession('monitor') })
    }

    if (action === 'login') {
      const pin = String(body.pin || '')
      if (!/^\d{4}$/.test(pin)) return json({ error: 'Enter your 4-digit PIN' }, 400)
      const { data: attemptRows } = await admin.from('fsc_login_attempts').select('*')
      if ((attemptRows || []).some((a) => a.blocked_until && new Date(a.blocked_until) > new Date())) return json({ error: 'Too many incorrect attempts. Try again later.' }, 429)
      const { data: settings, error } = await admin.from('fsc_settings').select('*').eq('id', 1).single()
      if (error) throw error
      const [monitorHash, takerHash] = await Promise.all([
        pinHash(pin, settings.monitor_pin_salt), pinHash(pin, settings.taker_pin_salt),
      ])
      const role = monitorHash === settings.monitor_pin_hash ? 'monitor' : takerHash === settings.taker_pin_hash ? 'taker' : null
      if (!role) {
        const failed = Math.max(0, ...(attemptRows || []).map((a) => Number(a.failed_count || 0))) + 1
        const blocked = failed >= 5 ? new Date(Date.now() + 15 * 60000).toISOString() : null
        await admin.from('fsc_login_attempts').upsert(['monitor', 'taker'].map((attemptRole) => ({ role: attemptRole, failed_count: blocked ? 0 : failed, blocked_until: blocked, updated_at: new Date().toISOString() })))
        return json({ error: blocked ? 'Too many incorrect attempts. Try again in 15 minutes.' : 'Incorrect PIN' }, 401)
      }
      await admin.from('fsc_login_attempts').upsert(['monitor', 'taker'].map((attemptRole) => ({ role: attemptRole, failed_count: 0, blocked_until: null, updated_at: new Date().toISOString() })))
      await admin.from('fsc_events').insert({ event_type: 'login', role, message: `${role === 'monitor' ? 'Monitor' : 'Medication taker'} signed in` })
      return json({ token: await issueSession(role) })
    }

    const auth = await session(request, String(body.sessionToken || ''))
    if (!auth) return json({ error: 'Please sign in again' }, 401)

    if (action === 'subscribe_push') {
      const subscription = body.subscription || {}
      const endpoint = String(subscription.endpoint || '')
      const p256dh = String(subscription.keys?.p256dh || '')
      const authKey = String(subscription.keys?.auth || '')
      if (!endpoint.startsWith('https://') || !p256dh || !authKey) return json({ error: 'The notification subscription is not valid' }, 400)
      const { error } = await admin.from('fsc_push_subscriptions').upsert({
        role: auth.role, endpoint, p256dh, auth: authKey, updated_at: new Date().toISOString(),
      }, { onConflict: 'endpoint' })
      if (error) throw error
      const { error: healthError } = await admin.from('fsc_device_notification_status').upsert({
        role: auth.role, enabled: true, permission: 'granted', has_subscription: true, checked_at: new Date().toISOString(),
      })
      if (healthError) throw healthError
      return json({ ok: true })
    }

    if (action === 'notification_health') {
      const permission = ['granted', 'denied', 'default', 'unsupported'].includes(String(body.permission)) ? String(body.permission) : 'unknown'
      const hasSubscription = body.hasSubscription === true
      const enabled = permission === 'granted' && hasSubscription
      const { data: previous } = await admin.from('fsc_device_notification_status').select('enabled').eq('role', auth.role).maybeSingle()
      const { error } = await admin.from('fsc_device_notification_status').upsert({
        role: auth.role, enabled, permission, has_subscription: hasSubscription, checked_at: new Date().toISOString(),
      })
      if (error) throw error
      if (auth.role === 'taker' && !enabled && previous?.enabled !== false) {
        await admin.from('fsc_events').insert({ event_type: 'notifications_off', role: 'taker', message: 'Medication-taker phone notifications are not enabled' })
        await pushRoles(['monitor'], {
          title: 'Taker notifications are off', body: 'Open Forced Self Care on the taker iPhone and enable notifications.', tag: 'notifications-off',
        }, `taker-notifications-off:${randomHex(8)}`)
      }
      return json({ ok: true, enabled })
    }

    if (action === 'send_test_push') {
      const endpoint = String(body.endpoint || '')
      const { data } = await admin.from('fsc_push_subscriptions')
        .select('id,role,endpoint,p256dh,auth').eq('endpoint', endpoint).eq('role', auth.role).maybeSingle()
      if (!data) return json({ error: 'Enable notifications on this phone first' }, 400)
      await pushTo([data as PushRow], {
        title: 'Forced Self Care', body: 'Notifications are working on this iPhone.', tag: 'test',
      }, `test:${randomHex(10)}`)
      return json({ ok: true })
    }

    if (action === 'state') {
      const date = londonDate()
      const [{ data: meds, error: medsError }, { data: records }, { data: events }, { data: purchases }, { data: notificationStatus }] = await Promise.all([
        admin.from('fsc_medications').select('id,name,sort_order').eq('active', true).order('sort_order'),
        admin.from('fsc_daily_records').select('*').eq('record_date', date),
        admin.from('fsc_events').select('id,message,created_at').order('created_at', { ascending: false }).limit(auth.role === 'monitor' ? 30 : 8),
        admin.from('fsc_purchase_reminders').select('id,due_date,medication_id,fsc_medications(name)').is('resolved_at', null).order('due_date'),
        auth.role === 'monitor' ? admin.from('fsc_device_notification_status').select('role,enabled,permission,has_subscription,checked_at') : Promise.resolve({ data: [] }),
      ])
      if (medsError) throw medsError
      const byId = new Map((records || []).map((r) => [r.medication_id, r]))
      const medications = (meds || []).map((m) => ({ ...m, ...(byId.get(m.id) || {}) }))
      return json({ role: auth.role, date, medications, events: events || [], notificationStatus: notificationStatus || [], purchases: (purchases || []).map((p: any) => ({ ...p, medication_name: p.fsc_medications?.name || 'Medication' })) })
    }

    if (action === 'update') {
      const medicationId = Number(body.medicationId)
      const status = String(body.status)
      const reason = String(body.reason || '').trim()
      if (!['taken', 'run_out', 'not_taken'].includes(status)) return json({ error: 'Choose a valid status' }, 400)
      if (auth.role === 'monitor') return json({ error: 'Only the medication taker can record a medication status' }, 403)
      if (status !== 'taken' && !reason) return json({ error: 'A reason is required' }, 400)
      const { data: med } = await admin.from('fsc_medications').select('name').eq('id', medicationId).single()
      if (!med) return json({ error: 'Medication not found' }, 404)
      const date = londonDate()
      const { error } = await admin.from('fsc_daily_records').upsert({ record_date: date, medication_id: medicationId, status, reason: status === 'taken' ? null : reason, updated_by: auth.role, updated_at: new Date().toISOString() })
      if (error) throw error
      const message = status === 'taken' ? `${med.name} marked as taken` : `${med.name} marked ${status === 'run_out' ? 'as run out' : 'not taken'}: ${reason}`
      await admin.from('fsc_events').insert({ event_type: status, medication_id: medicationId, role: auth.role, message })
      if (status === 'run_out') await admin.from('fsc_purchase_reminders').upsert({ medication_id: medicationId, due_date: londonDate(1) }, { onConflict: 'medication_id,due_date' })
      if (status !== 'taken') {
        await pushRoles(['monitor'], {
          title: status === 'run_out' ? `${med.name} has run out` : `${med.name} was not taken`,
          body: reason, tag: status,
        }, `${date}:${status}:${medicationId}:${randomHex(6)}`)
      }
      const [{ count: medicationCount }, { count: takenCount }] = await Promise.all([
        admin.from('fsc_medications').select('*', { count: 'exact', head: true }).eq('active', true),
        admin.from('fsc_daily_records').select('medication_id,fsc_medications!inner(active)', { count: 'exact', head: true }).eq('record_date', date).eq('status', 'taken').eq('fsc_medications.active', true),
      ])
      if (status === 'taken') {
        const allTaken = (medicationCount || 0) > 0 && takenCount === medicationCount
        await pushRoles(['monitor'], {
          title: allTaken ? 'All medication taken' : `${med.name} taken`,
          body: allTaken ? 'Today’s full checklist has been completed.' : `${med.name} has been marked as taken.`,
          tag: allTaken ? 'all-taken' : 'medication-taken',
        }, `${date}:taken:${medicationId}:${randomHex(6)}`)
      }
      return json({ ok: true })
    }

    if (action === 'reset_medication_status') {
      if (auth.role !== 'monitor') return json({ error: 'Only the Monitor can reset a medication status' }, 403)
      const medicationId = Number(body.medicationId)
      if (!Number.isInteger(medicationId) || medicationId < 1) return json({ error: 'Medication not found' }, 404)
      const date = londonDate()
      const [{ data: med }, { data: record }] = await Promise.all([
        admin.from('fsc_medications').select('name').eq('id', medicationId).eq('active', true).maybeSingle(),
        admin.from('fsc_daily_records').select('status').eq('record_date', date).eq('medication_id', medicationId).maybeSingle(),
      ])
      if (!med || !record) return json({ error: 'There is no status to reset for this medication today' }, 404)
      const { error } = await admin.from('fsc_daily_records').delete().eq('record_date', date).eq('medication_id', medicationId)
      if (error) throw error
      if (record.status === 'run_out') {
        await admin.from('fsc_purchase_reminders').delete().eq('medication_id', medicationId).eq('due_date', londonDate(1)).is('resolved_at', null)
      }
      await admin.from('fsc_events').insert({ event_type: 'status_reset', medication_id: medicationId, role: 'monitor', message: `${med.name} status was reset by the Monitor` })
      return json({ ok: true })
    }

    if (action === 'reset_taker_pin') {
      if (auth.role !== 'monitor') return json({ error: 'Only the Monitor can reset this PIN' }, 403)
      const pin = String(body.pin || '')
      if (!/^\d{4}$/.test(pin)) return json({ error: 'The PIN must contain exactly 4 numbers' }, 400)
      const salt = randomHex(16)
      const { error } = await admin.from('fsc_settings').update({ taker_pin_hash: await pinHash(pin, salt), taker_pin_salt: salt, updated_at: new Date().toISOString() }).eq('id', 1)
      if (error) throw error
      await admin.from('fsc_sessions').delete().eq('role', 'taker')
      await admin.from('fsc_events').insert({ event_type: 'pin_reset', role: 'monitor', message: 'Medication-taker PIN was reset' })
      return json({ ok: true })
    }

    if (action === 'reset_monitor_pin') {
      if (auth.role !== 'monitor') return json({ error: 'Only the Monitor can change this PIN' }, 403)
      const pin = String(body.pin || '')
      if (!/^\d{4}$/.test(pin)) return json({ error: 'The PIN must contain exactly 4 numbers' }, 400)
      const salt = randomHex(16)
      const { error } = await admin.from('fsc_settings').update({ monitor_pin_hash: await pinHash(pin, salt), monitor_pin_salt: salt, updated_at: new Date().toISOString() }).eq('id', 1)
      if (error) throw error
      await admin.from('fsc_sessions').delete().eq('role', 'monitor')
      const token = await issueSession('monitor')
      await admin.from('fsc_events').insert({ event_type: 'pin_reset', role: 'monitor', message: 'Monitor PIN was changed' })
      return json({ ok: true, token })
    }

    if (action === 'logout') {
      await admin.from('fsc_sessions').delete().eq('token_hash', auth.tokenHash)
      return json({ ok: true })
    }
    return json({ error: 'Unknown action' }, 400)
  } catch (error) {
    console.error(error)
    return json({ error: 'The app could not complete that action' }, 500)
  }
})
