const { createClient } = require('@supabase/supabase-js');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const API_KEY = process.env.PHARMADESK_API_KEY;
const JWT_SECRET = process.env.PHARMADESK_JWT_SECRET;
const SETUP_KEY = process.env.PHARMADESK_SETUP_KEY;

const STORES = [
  'products','customers','sales','suppliers','reorders','expenses','payables',
  'staff','prescriptions','branches','proformas','activityLog','purchases',
  'creditNotes','payments','settings'
];

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: '15mb' }));

function requireApiKey(req, res, next) {
  if (req.header('X-API-Key') !== API_KEY) return res.status(401).json({ error: 'Invalid or missing API key' });
  next();
}
function requireAuth(req, res, next) {
  const header = req.header('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try { req.staff = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { return res.status(401).json({ error: 'Session expired' }); }
}
function requireAdmin(req, res, next) {
  if (req.staff.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}
function validStore(req, res, next) {
  if (!STORES.includes(req.params.store)) return res.status(404).json({ error: 'Unknown store' });
  next();
}

async function getStaff(staffId) {
  const { data } = await supabase.from('records').select('data').eq('store', 'staff').eq('key', staffId).single();
  return data ? data.data : null;
}

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/debug', (req, res) => {
  res.json({
    hasSupabaseUrl: !!process.env.SUPABASE_URL,
    hasSupabaseKey: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
    hasApiKey: !!process.env.PHARMADESK_API_KEY,
    hasJwtSecret: !!process.env.PHARMADESK_JWT_SECRET,
    hasSetupKey: !!process.env.PHARMADESK_SETUP_KEY,
    supabaseUrlPreview: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.slice(0, 15) + '...' : 'MISSING'
  });
});
app.post('/api/auth/bootstrap-admin', requireApiKey, async (req, res) => {
  if (req.body.setupKey !== SETUP_KEY) return res.status(403).json({ error: 'Bad setup key' });
  const { count } = await supabase.from('credentials').select('*', { count: 'exact', head: true });
  if (count > 0) return res.status(403).json({ error: 'An account already exists — use Settings → Staff inside the app instead.' });
  const { name, username, password } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'name, username, password required' });
  const staffId = 'stf_' + Date.now().toString(36);
  await supabase.from('records').upsert({ store: 'staff', key: staffId, data: { id: staffId, name, role: 'admin', username }, updated_at: new Date().toISOString() });
  const hash = await bcrypt.hash(password, 10);
  await supabase.from('credentials').insert({ username: username.toLowerCase(), staff_id: staffId, password_hash: hash });
  res.json({ ok: true, staffId });
});

app.post('/api/auth/login', requireApiKey, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const { data: cred } = await supabase.from('credentials').select('*').eq('username', username.toLowerCase()).single();
  if (!cred) return res.status(401).json({ error: 'Invalid username or password' });
  const ok = await bcrypt.compare(password, cred.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid username or password' });
  const staff = await getStaff(cred.staff_id);
  if (!staff) return res.status(401).json({ error: 'Account no longer exists' });
  const token = jwt.sign({ staffId: cred.staff_id, role: staff.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: cred.staff_id, name: staff.name, role: staff.role, branchId: staff.branchId || null } });
});

app.get('/api/auth/me', requireApiKey, requireAuth, async (req, res) => {
  const staff = await getStaff(req.staff.staffId);
  if (!staff) return res.status(401).json({ error: 'Account no longer exists' });
  res.json({ user: { id: staff.id, name: staff.name, role: staff.role, branchId: staff.branchId || null } });
});

app.post('/api/auth/set-credentials', requireApiKey, requireAuth, requireAdmin, async (req, res) => {
  const { staffId, username, password } = req.body;
  if (!staffId || !username || !password) return res.status(400).json({ error: 'staffId, username, password required' });
  const hash = await bcrypt.hash(password, 10);
  await supabase.from('credentials').delete().eq('staff_id', staffId);
  await supabase.from('credentials').insert({ username: username.toLowerCase(), staff_id: staffId, password_hash: hash });
  const staff = await getStaff(staffId);
  if (staff) await supabase.from('records').upsert({ store: 'staff', key: staffId, data: { ...staff, username }, updated_at: new Date().toISOString() });
  res.json({ ok: true });
});

app.get('/api/:store/all', requireApiKey, requireAuth, validStore, async (req, res) => {
  const { data, error } = await supabase.from('records').select('data').eq('store', req.params.store);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(r => r.data));
});

app.get('/api/:store/:key', requireApiKey, requireAuth, validStore, async (req, res) => {
  const { data } = await supabase.from('records').select('data').eq('store', req.params.store).eq('key', req.params.key).single();
  if (!data) return res.status(404).json({ error: 'Not found' });
  res.json(data.data);
});

app.put('/api/:store/:key', requireApiKey, requireAuth, validStore, async (req, res) => {
  const record = { ...req.body, updatedAt: new Date().toISOString() };
  const { error } = await supabase.from('records').upsert({
    store: req.params.store, key: req.params.key, data: record, updated_at: record.updatedAt
  });
  if (error) return res.status(500).json({ error: error.message });
  res.json(record);
});

app.delete('/api/:store/:key', requireApiKey, requireAuth, validStore, async (req, res) => {
  await supabase.from('records').delete().eq('store', req.params.store).eq('key', req.params.key);
  res.status(204).send();
});

app.delete('/api/:store', requireApiKey, requireAuth, validStore, async (req, res) => {
  await supabase.from('records').delete().eq('store', req.params.store);
  res.status(204).send();
});

app.get('/api/:store/pull', requireApiKey, requireAuth, validStore, async (req, res) => {
  const since = req.query.since || '1970-01-01T00:00:00.000Z';
  const { data } = await supabase.from('records').select('data').eq('store', req.params.store).gt('updated_at', since);
  res.json({ records: (data || []).map(r => r.data), deletedIds: [], serverTime: new Date().toISOString() });
});
app.post('/api/:store/push', requireApiKey, requireAuth, validStore, async (req, res) => {
  const rows = (req.body.records || [])
    .filter(rec => rec.key || rec.id)
    .map(rec => ({ store: req.params.store, key: rec.key || rec.id, data: { ...rec, updatedAt: new Date().toISOString() }, updated_at: new Date().toISOString() }));
  if (rows.length) await supabase.from('records').upsert(rows);
  res.json({ ok: true });
});

app.get('/api/backup', requireApiKey, requireAuth, requireAdmin, async (req, res) => {
  const out = {};
  for (const store of STORES) {
    const { data } = await supabase.from('records').select('data').eq('store', store);
    out[store] = (data || []).map(r => r.data);
  }
  res.json(out);
});

module.exports = app;
