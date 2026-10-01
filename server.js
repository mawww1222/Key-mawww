const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_USER = process.env.KEY_ADMIN_USER || 'mawwwhub';
const ADMIN_PASSWORD = process.env.KEY_ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.KEY_SESSION_SECRET || '';
const APP_NAME = process.env.KEY_APP_NAME || 'Mawww Hub';
const DEFAULT_PREFIX = normalizePrefix(process.env.KEY_PREFIX || 'MAWWW');

if (!DATABASE_URL) {
  console.error('[Mawww Key] DATABASE_URL is required.');
  process.exit(1);
}
if (SESSION_SECRET.length < 32) {
  console.warn('[Mawww Key] KEY_SESSION_SECRET should contain at least 32 characters.');
}
if (!ADMIN_PASSWORD) {
  console.warn('[Mawww Key] KEY_ADMIN_PASSWORD is not set; /dev login is disabled.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

function normalizePrefix(value) {
  return String(value || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 12) || 'MAWWW';
}
function normalizeKey(value) {
  return String(value || '').trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  })[char]);
}
function constantEqual(a, b) {
  const aa = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function createKey(prefix) {
  const chunk = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix}-${chunk()}-${chunk()}-${chunk()}`;
}
function expiryFromDays(value) {
  const days = Number(value);
  if (!Number.isFinite(days) || days <= 0) return null;
  return new Date(Date.now() + days * 86400000);
}
function createSession(user) {
  const payload = Buffer.from(JSON.stringify({
    user,
    exp: Date.now() + 12 * 60 * 60 * 1000
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function readSession(req) {
  const cookie = String(req.headers.cookie || '');
  const match = cookie.match(/(?:^|; )mawww_session=([^;]+)/);
  if (!match) return null;
  try {
    const parts = decodeURIComponent(match[1]).split('.');
    if (parts.length !== 2) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(parts[0]).digest('base64url');
    if (!constantEqual(parts[1], expected)) return null;
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return data && data.exp > Date.now() ? data.user : null;
  } catch {
    return null;
  }
}
function setSessionCookie(res, value, maxAge = 43200) {
  const secure = process.env.NODE_ENV === 'production' ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `mawww_session=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax;${secure} Max-Age=${maxAge}`);
}
function requireAdmin(req, res, next) {
  if (!readSession(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });
  next();
}

const rateStore = new Map();
function publicRateLimit(req, res, next) {
  const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
  const now = Date.now();
  const bucket = rateStore.get(ip) || { start: now, count: 0 };
  if (now - bucket.start >= 60000) { bucket.start = now; bucket.count = 0; }
  bucket.count += 1;
  rateStore.set(ip, bucket);
  if (bucket.count > 120) return res.status(429).json({ ok: false, error: 'rate_limited' });
  next();
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      id BIGSERIAL PRIMARY KEY,
      key_value TEXT UNIQUE NOT NULL,
      prefix TEXT NOT NULL,
      product TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
      note TEXT NOT NULL DEFAULT '',
      max_uses INTEGER NOT NULL DEFAULT 0 CHECK (max_uses >= 0),
      uses INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
      expires_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMPTZ NULL,
      created_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS license_keys_key_value_idx ON license_keys(key_value);
    CREATE INDEX IF NOT EXISTS license_keys_status_idx ON license_keys(status);
    CREATE TABLE IF NOT EXISTS license_usage (
      id BIGSERIAL PRIMARY KEY,
      key_id BIGINT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
      product TEXT NOT NULL,
      ip TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS license_usage_key_id_idx ON license_usage(key_id);
  `);
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'mawww-key-system' });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.get('/api', (_req, res) => {
  res.json({
    ok: true,
    name: APP_NAME,
    endpoints: {
      validate: `/api/validate?key=YOUR_KEY&product=${encodeURIComponent(APP_NAME)}`,
      status: '/api/status?key=YOUR_KEY'
    }
  });
});

app.get('/api/validate', publicRateLimit, async (req, res) => {
  const key = normalizeKey(req.query.key);
  const product = String(req.query.product || APP_NAME).trim().slice(0, 80);
  if (!key) return res.status(400).json({ ok: false, valid: false, error: 'missing_key' });

  try {
    const found = await pool.query('SELECT * FROM license_keys WHERE key_value=$1 LIMIT 1', [key]);
    if (!found.rowCount) return res.status(404).json({ ok: true, valid: false, reason: 'not_found' });

    const row = found.rows[0];
    if (row.status !== 'active') return res.json({ ok: true, valid: false, reason: 'revoked' });
    if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
      return res.json({ ok: true, valid: false, reason: 'expired' });
    }
    if (row.product.toLowerCase() !== product.toLowerCase()) {
      return res.json({ ok: true, valid: false, reason: 'wrong_product' });
    }
    if (row.max_uses > 0 && row.uses >= row.max_uses) {
      return res.json({ ok: true, valid: false, reason: 'usage_limit' });
    }

    const used = await pool.query(
      `UPDATE license_keys
       SET uses = uses + 1, last_used_at = NOW()
       WHERE id=$1 AND status='active' AND (max_uses=0 OR uses<max_uses)
       RETURNING uses`,
      [row.id]
    );
    if (!used.rowCount) return res.json({ ok: true, valid: false, reason: 'usage_limit' });

    const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim().slice(0, 200);
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 300);
    await pool.query(
      'INSERT INTO license_usage(key_id,product,ip,user_agent) VALUES($1,$2,$3,$4)',
      [row.id, product, ip, userAgent]
    );

    res.json({
      ok: true,
      valid: true,
      key: row.key_value,
      product: row.product,
      expires_at: row.expires_at,
      uses: used.rows[0].uses,
      max_uses: row.max_uses
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, valid: false, error: 'server_error' });
  }
});

app.get('/api/status', publicRateLimit, async (req, res) => {
  const key = normalizeKey(req.query.key);
  if (!key) return res.status(400).json({ ok: false, error: 'missing_key' });
  try {
    const r = await pool.query(
      `SELECT key_value, product, status, max_uses, uses, expires_at, created_at, last_used_at
       FROM license_keys WHERE key_value=$1 LIMIT 1`, [key]
    );
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
    res.json({ ok: true, ...r.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/dev/login', (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ ok: false, error: 'admin_not_configured' });
  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');
  if (!constantEqual(username, ADMIN_USER) || !constantEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  }
  setSessionCookie(res, createSession(ADMIN_USER));
  res.json({ ok: true });
});
app.post('/api/dev/logout', requireAdmin, (_req, res) => {
  setSessionCookie(res, '', 0);
  res.json({ ok: true });
});
app.get('/api/dev/me', req => readSession(req), (req, res) => {
  const user = readSession(req);
  res.json({ ok: true, logged_in: !!user, user: user || null });
});

app.get('/api/dev/keys', requireAdmin, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  try {
    const r = await pool.query(
      `SELECT id,key_value,prefix,product,status,note,max_uses,uses,expires_at,created_at,last_used_at
       FROM license_keys ORDER BY id DESC LIMIT $1`, [limit]
    );
    res.json({ ok: true, keys: r.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/dev/keys/generate', requireAdmin, async (req, res) => {
  const count = Math.min(Math.max(Number(req.body?.count || 1), 1), 100);
  const prefix = normalizePrefix(req.body?.prefix || DEFAULT_PREFIX);
  const product = String(req.body?.product || APP_NAME).trim().slice(0, 80) || APP_NAME;
  const note = String(req.body?.note || '').trim().slice(0, 250);
  const maxUses = Math.min(Math.max(Number(req.body?.max_uses || 0), 0), 1000000);
  const expiresAt = expiryFromDays(req.body?.expires_in_days);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const created = [];
    for (let i = 0; i < count; i += 1) {
      let inserted = null;
      for (let attempt = 0; attempt < 10 && !inserted; attempt += 1) {
        try {
          const r = await client.query(
            `INSERT INTO license_keys
              (key_value,prefix,product,note,max_uses,expires_at,created_by)
             VALUES($1,$2,$3,$4,$5,$6,$7)
             RETURNING id,key_value,prefix,product,status,note,max_uses,uses,expires_at,created_at`,
            [createKey(prefix), prefix, product, note, maxUses, expiresAt, ADMIN_USER]
          );
          inserted = r.rows[0];
        } catch (error) {
          if (error.code !== '23505') throw error;
        }
      }
      if (!inserted) throw new Error('key_generation_failed');
      created.push(inserted);
    }
    await client.query('COMMIT');
    res.json({ ok: true, keys: created });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ ok: false, error: 'generation_failed' });
  } finally {
    client.release();
  }
});

async function changeKeyStatus(req, res, status) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ ok: false, error: 'invalid_id' });
  try {
    const r = await pool.query(
      'UPDATE license_keys SET status=$1 WHERE id=$2 RETURNING id,key_value,status',
      [status, id]
    );
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
    res.json({ ok: true, key: r.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
}
app.post('/api/dev/keys/:id/revoke', requireAdmin, (req, res) => changeKeyStatus(req, res, 'revoked'));
app.post('/api/dev/keys/:id/activate', requireAdmin, (req, res) => changeKeyStatus(req, res, 'active'));

const STYLE = `
:root{--bg:#070a14;--card:#0e1426ee;--line:#29386c;--text:#edf2ff;--muted:#94a3ca;--blue:#4c9cff;--violet:#8a4dff;--green:#37d68a;--red:#ff5c78}
*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 10% 0,#17366e 0,transparent 35%),radial-gradient(circle at 90% 0,#32165e 0,transparent 34%),var(--bg)}
a{color:inherit;text-decoration:none}.wrap{max-width:1120px;margin:auto;padding:24px 16px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:18px}.brand{display:flex;align-items:center;gap:10px}.logo{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,var(--blue),var(--violet));display:grid;place-items:center;font-weight:900;box-shadow:0 0 30px #4c9cff40}.muted{color:var(--muted)}.actions{display:flex;gap:8px;flex-wrap:wrap}.card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:20px;box-shadow:0 20px 60px #0008, inset 0 1px #fff1;backdrop-filter:blur(10px)}.hero{display:grid;grid-template-columns:1.35fr .65fr;gap:16px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stat{padding:15px;border:1px solid var(--line);border-radius:15px;background:#0b1223}.stat b{display:block;font-size:22px;margin-bottom:4px}.form{display:grid;gap:10px}.field{display:grid;gap:6px}.field label{font-size:12px;color:#9cadd3}.field input{width:100%;padding:11px 12px;border-radius:11px;border:1px solid var(--line);background:#070c19;color:var(--text);outline:none}.field input:focus{border-color:#6a98ff;box-shadow:0 0 0 3px #4c9cff20}.row{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.btn{border:1px solid #31457c;border-radius:11px;padding:10px 13px;background:#111932;color:#edf2ff;cursor:pointer}.btn:hover{border-color:#5b7fe0}.primary{border-color:#667eff;background:linear-gradient(135deg,#285fda,#843cff)}.danger{border-color:#6e3344;background:#2a1018}.status{display:none;margin-top:12px;padding:11px 12px;border-radius:11px;border:1px solid var(--line)}.status.ok{display:block;background:#0a2018;border-color:#286c50}.status.bad{display:block;background:#250f17;border-color:#703548}.code{background:#050812;border:1px solid #263665;padding:9px;border-radius:9px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px}.table{width:100%;border-collapse:collapse;min-width:850px}.table th,.table td{padding:10px;border-bottom:1px solid #21315a;text-align:left;font-size:12px}.table th{color:#aab8db;background:#0c1427}.pill{display:inline-flex;padding:6px 9px;border-radius:999px;background:#142448;border:1px solid #304779;color:#a9ccff;font-size:12px}.center{min-height:80vh;display:grid;place-items:center}.login{width:min(430px,100%)}footer{margin-top:18px;text-align:center;color:#66759f;font-size:12px}
@media(max-width:780px){.hero{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
`;
function page(title, body, script = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body>${body}${script ? `<script>${script}</script>` : ''}</body></html>`;
}

const HOME = `
<div class="wrap">
  <div class="top"><div class="brand"><div class="logo">M</div><div><b>${escapeHtml(APP_NAME)}</b><div class="muted">Key System</div></div></div><div class="actions"><a class="btn" href="/dev">Developer</a><a class="btn" href="/api" target="_blank">API</a></div></div>
  <div class="hero">
    <section class="card"><span class="pill">● API ONLINE</span><h1>MAWWW KEY SYSTEM</h1><p class="muted">Public key verification for ${escapeHtml(APP_NAME)}. Developer generates keys in the private dashboard and gives them to customers.</p><div class="grid"><div class="stat"><b>Generate</b><span class="muted">1–100 keys</span></div><div class="stat"><b>Control</b><span class="muted">Revoke / activate</span></div><div class="stat"><b>API</b><span class="muted">JSON endpoint</span></div></div></section>
    <section class="card"><h2>Verify Key</h2><div class="form"><div class="field"><label>License Key</label><input id="key" placeholder="MAWWW-ABC123-DEF456-GHI789" autocomplete="off"></div><div class="field"><label>Product</label><input id="product" value="${escapeHtml(APP_NAME)}"></div><button class="btn primary" onclick="verifyKey()">Verify Key</button></div><div id="result" class="status"></div></section>
  </div>
  <footer>© ${new Date().getFullYear()} ${escapeHtml(APP_NAME)} Key System</footer>
</div>`;
const HOME_JS = `
async function verifyKey(){
  const box=document.getElementById('result'); const key=document.getElementById('key').value.trim(); const product=document.getElementById('product').value.trim();
  box.className='status'; box.style.display='block'; box.textContent='Checking...';
  if(!key){box.className='status bad';box.textContent='Masukkan key terlebih dahulu.';return;}
  try{
    const r=await fetch('/api/validate?key='+encodeURIComponent(key)+'&product='+encodeURIComponent(product));
    const d=await r.json();
    if(d.valid){box.className='status ok';box.innerHTML='<b>✓ KEY VALID</b><br>Product: '+esc(d.product)+'<br>Expiry: '+esc(d.expires_at||'Never')+'<br>Uses: '+d.uses+'/'+(d.max_uses||'∞');}
    else{box.className='status bad';box.innerHTML='<b>✕ KEY INVALID</b><br>Reason: '+esc(d.reason||d.error||'unknown');}
  }catch{box.className='status bad';box.textContent='API error.';}
}
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}
`;

const LOGIN = `
<div class="wrap center"><section class="card login"><div class="brand"><div class="logo">M</div><div><b>${escapeHtml(APP_NAME)}</b><div class="muted">Developer Login</div></div></div><div class="form" style="margin-top:18px"><div class="field"><label>Username</label><input id="u" autocomplete="username"></div><div class="field"><label>Password</label><input id="p" type="password" autocomplete="current-password"></div><button class="btn primary" onclick="login()">Login</button></div><div id="msg" class="status"></div></section></div>`;
const LOGIN_JS = `
async function login(){
  const msg=document.getElementById('msg');msg.className='status';msg.style.display='block';msg.textContent='Signing in...';
  try{const r=await fetch('/api/dev/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});const d=await r.json();if(d.ok)location='/dev';else{msg.className='status bad';msg.textContent='Login gagal: '+(d.error||'invalid_credentials')}}catch{msg.className='status bad';msg.textContent='Server error.'}
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')login()});
`;

const ADMIN = `
<div class="wrap"><div class="top"><div class="brand"><div class="logo">M</div><div><b>${escapeHtml(APP_NAME)}</b><div class="muted">Developer • Key Management</div></div></div><div class="actions"><a class="btn" href="/">Public</a><button class="btn" onclick="logout()">Logout</button></div></div>
<section class="card"><h2>Generate Keys</h2><div class="row"><div class="field"><label>Jumlah key</label><input id="count" type="number" min="1" max="100" value="1"></div><div class="field"><label>Prefix</label><input id="prefix" maxlength="12" value="${escapeHtml(DEFAULT_PREFIX)}"></div><div class="field"><label>Product</label><input id="product" value="${escapeHtml(APP_NAME)}"></div><div class="field"><label>Expire (hari, 0 = unlimited)</label><input id="days" type="number" min="0" value="30"></div><div class="field"><label>Max uses (0 = unlimited)</label><input id="uses" type="number" min="0" value="1"></div><div class="field"><label>Catatan</label><input id="note" maxlength="250" placeholder="Buyer #001"></div></div><button class="btn primary" onclick="generate()">Generate Key</button><div id="generated" class="status"></div></section>
<div style="height:14px"></div>
<section class="card"><div class="top"><div><h2 style="margin:0">Key Inventory</h2><div class="muted">Keys tersimpan di PostgreSQL Railway.</div></div><span id="total" class="pill">0 keys</span></div><div class="table-wrap"><table class="table"><thead><tr><th>Key</th><th>Product</th><th>Status</th><th>Uses</th><th>Expiry</th><th>Note</th><th>Action</th></tr></thead><tbody id="rows"></tbody></table></div></section></div>`;
const ADMIN_JS = `
async function boot(){const r=await fetch('/api/dev/me');const d=await r.json();if(!d.logged_in){location='/dev/login';return}load();}
async function load(){const r=await fetch('/api/dev/keys');if(r.status===401){location='/dev/login';return}const d=await r.json();const keys=d.keys||[];document.getElementById('total').textContent=keys.length+' keys';document.getElementById('rows').innerHTML=keys.map(k=>{const a=k.status==='active'?'<button class="btn danger" onclick="changeStatus('+k.id+',\'revoke\')">Revoke</button>':'<button class="btn" onclick="changeStatus('+k.id+',\'activate\')">Activate</button>';return '<tr><td><div class="code">'+esc(k.key_value)+'</div></td><td>'+esc(k.product)+'</td><td>'+esc(k.status)+'</td><td>'+k.uses+'/'+(k.max_uses||'∞')+'</td><td>'+esc(k.expires_at||'Never')+'</td><td>'+esc(k.note||'')+'</td><td>'+a+'</td></tr>'}).join('');}
async function generate(){const body={count:+document.getElementById('count').value||1,prefix:document.getElementById('prefix').value,product:document.getElementById('product').value,expires_in_days:+document.getElementById('days').value||0,max_uses:+document.getElementById('uses').value||0,note:document.getElementById('note').value};const r=await fetch('/api/dev/keys/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const d=await r.json();const box=document.getElementById('generated');box.style.display='block';if(!d.ok){box.className='status bad';box.textContent=d.error||'generation_failed';return}box.className='status ok';box.innerHTML='<b>Generated '+d.keys.length+' key(s)</b><div class="code" style="margin-top:8px">'+d.keys.map(k=>esc(k.key_value)).join('<br>')+'</div>';window.__keys=d.keys.map(k=>k.key_value).join('\\n');load();}
async function changeStatus(id,action){const r=await fetch('/api/dev/keys/'+id+'/'+action,{method:'POST'});if(r.status===401){location='/dev/login';return}load();}
async function logout(){await fetch('/api/dev/logout',{method:'POST'});location='/dev/login';}
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}
boot();
`;

app.get('/', (_req, res) => res.type('html').send(page(APP_NAME + ' Key System', HOME, HOME_JS)));
app.get('/dev/login', (_req, res) => res.type('html').send(page('Developer Login', LOGIN, LOGIN_JS)));
app.get('/dev', (req, res) => {
  if (!readSession(req)) return res.redirect('/dev/login');
  return res.type('html').send(page('Developer Console', ADMIN, ADMIN_JS));
});
app.use((_req, res) => res.status(404).type('html').send(page('404', '<div class="wrap center"><section class="card"><h1>404</h1><a class="btn" href="/">Back</a></section></div>')));

initDb()
  .then(() => app.listen(PORT, () => console.log(`[Mawww Key] listening on :${PORT}`)))
  .catch(error => { console.error('[Mawww Key] DB init failed', error); process.exit(1); });
