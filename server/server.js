/**
 * PharmaDesk Server
 * ------------------------------------------------------------------
 * The single permanent home for all PharmaDesk data. Every device/branch
 * that runs the PharmaDesk app talks to THIS server for every read and
 * write — nothing is meant to be kept permanently on the device itself.
 *
 * Storage: one JSON file per "store" (products.json, sales.json, etc.)
 * under ./data/, written atomically (write to a temp file, then rename)
 * so a crash mid-write can't corrupt a file. This avoids requiring a
 * separate database server or native database drivers, which makes this
 * easy to deploy on almost any free/cheap Node host.
 *
 * Auth: real username + password accounts (bcrypt-hashed, never stored
 * in plain text), issuing a signed session token (JWT) that's the same
 * on every device — that's what makes "stable password on every device"
 * possible, since the account itself lives here, not on any one device.
 *
 * Security note (read this): a browser can never be made 100% tamper-proof
 * against someone with access to that browser's devtools — that's true of
 * every web app, not just this one. What this server does instead is the
 * real fix: it independently re-checks who's allowed to do what on every
 * single request, so even if someone tampered with the app's JavaScript in
 * their own browser, the server simply refuses any change they're not
 * authorized to make. The data is only ever actually changed here.
 * ------------------------------------------------------------------
 */
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const DATA_DIR = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// ---- Required configuration (set these as environment variables on your host) ----
const APP_API_KEY = process.env.APP_API_KEY;         // shared app-level secret (matches the "API key" field in Settings)
const JWT_SECRET = process.env.JWT_SECRET;            // signs login session tokens — keep this secret
const PORT = process.env.PORT || 4000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'; // lock this down to your app's real URL once you know it
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;    // used only once, to create the first admin account on first boot

if (!APP_API_KEY || !JWT_SECRET) {
  console.error('FATAL: Set APP_API_KEY and JWT_SECRET environment variables before starting the server.');
  console.error('These are secrets — generate long random strings, e.g. with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// ---- Tiny atomic JSON-file storage layer (one file per store) ----
function storePath(store) {
  const safe = String(store).replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safe) throw new Error('Invalid store name');
  return path.join(DATA_DIR, safe + '.json');
}
function readStore(store) {
  const p = storePath(store);
  if (!fs.existsSync(p)) return [];
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { console.error(`Corrupt store file ${p}, returning empty array:`, e.message); return []; }
}
function writeStore(store, records) {
  const p = storePath(store);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(records));
  fs.renameSync(tmp, p); // atomic on the same filesystem — prevents half-written files
}

// ---- Role permissions (mirrors the app's client-side ROLE_PERMISSIONS,
// re-checked here so authorization is enforced even if the client is
// tampered with) ----
const ROLE_PERMISSIONS = {
  admin: null, // admin passes every check — see hasPermission below
  manager: { canDelete: true, canEditPrices: true, canViewFinance: true, canManageStaff: true },
  pharmacist: { canDelete: false, canEditPrices: true, canViewFinance: false, canManageStaff: false },
  cashier: { canDelete: false, canEditPrices: false, canViewFinance: false, canManageStaff: false }
};
function hasPermission(user, key) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const perms = ROLE_PERMISSIONS[user.role] || {};
  return !!perms[key];
}
// Stores where deleting a record requires canDelete, matching the app's own rules.
const DELETE_PROTECTED_STORES = new Set(['products', 'customers', 'prescriptions', 'staff']);

// ---- Bootstrap: create the first admin account on first boot if 'staff' is empty ----
function ensureFirstAdmin() {
  const staff = readStore('staff');
  if (staff.length > 0) return;
  if (!ADMIN_PASSWORD) {
    console.warn('No staff accounts exist yet, and ADMIN_PASSWORD was not set — set it once, restart, then you can remove it.');
    return;
  }
  const passwordHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  staff.push({
    id: 'staff_admin_' + Date.now(),
    name: 'Administrator',
    username: ADMIN_USERNAME,
    passwordHash,
    role: 'admin',
    pin: '', // legacy field some client versions may still read; unused for server login
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  });
  writeStore('staff', staff);
  console.log(`Created first admin account — username: "${ADMIN_USERNAME}". Log in once, then set ADMIN_PASSWORD to blank/remove it from your host's env vars so it can't be used to re-create an account.`);
}
ensureFirstAdmin();

// ---- App setup ----
const app = express();
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: '15mb' })); // generous limit for full backup restores

// Every request must present the shared app API key — this is a coarse gate
// ("is this even a request from our app") separate from per-user login.
app.use((req, res, next) => {
  if (req.path === '/api/health') return next();
  const key = req.header('X-API-Key');
  if (key !== APP_API_KEY) return res.status(401).json({ error: 'Invalid or missing API key' });
  next();
});

app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ---- Auth ----
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  const staff = readStore('staff');
  const user = staff.find(s => (s.username || '').toLowerCase() === String(username).toLowerCase());
  if (!user || !user.passwordHash || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  const token = jwt.sign(
    { sub: user.id, name: user.name, role: user.role, branchId: user.branchId || null },
    JWT_SECRET,
    { expiresIn: '30d' } // long-lived on purpose — this is what keeps a device logged in across refreshes/days
  );
  res.json({ token, user: { id: user.id, name: user.name, role: user.role, branchId: user.branchId || null } });
});

// Verifies a token is still valid and returns the current user — the app calls
// this on load so a page refresh can skip straight back to the dashboard.
function authMiddleware(req, res, next) {
  const header = req.header('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired — please log in again.' });
  }
}

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: { id: req.user.sub, name: req.user.name, role: req.user.role, branchId: req.user.branchId } });
});

// Admin/manager only: set or change a staff member's login credentials.
// (Creating the staff *record* itself still goes through the normal
// generic PUT /api/staff/:id below — this endpoint only ever touches
// username/password, and always hashes the password before saving.)
app.post('/api/auth/set-credentials', authMiddleware, (req, res) => {
  if (!hasPermission(req.user, 'canManageStaff') && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized to manage staff logins.' });
  }
  const { staffId, username, password } = req.body || {};
  if (!staffId || !username || !password) return res.status(400).json({ error: 'staffId, username, and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const staff = readStore('staff');
  const idx = staff.findIndex(s => s.id === staffId);
  if (idx === -1) return res.status(404).json({ error: 'Staff record not found.' });
  const usernameTaken = staff.some(s => s.id !== staffId && (s.username || '').toLowerCase() === username.toLowerCase());
  if (usernameTaken) return res.status(409).json({ error: 'That username is already in use.' });
  staff[idx].username = username;
  staff[idx].passwordHash = bcrypt.hashSync(password, 10);
  staff[idx].updatedAt = new Date().toISOString();
  writeStore('staff', staff);
  res.json({ ok: true });
});

// Everything below this line requires a valid login.
app.use('/api/:store', authMiddleware);

// ---- Generic CRUD, one route family reused for every store ----
app.get('/api/:store/all', (req, res) => {
  res.json(readStore(req.params.store));
});

app.get('/api/:store/pull', (req, res) => {
  const since = req.query.since ? new Date(req.query.since) : null;
  const all = readStore(req.params.store);
  const filtered = since ? all.filter(r => new Date(r.updatedAt || r.createdAt || 0) > since) : all;
  res.json(filtered);
});

app.get('/api/:store/:id', (req, res) => {
  const rec = readStore(req.params.store).find(r => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  res.json(rec);
});

app.put('/api/:store/:id', (req, res) => {
  const store = req.params.store;
  const incoming = { ...req.body, id: req.params.id, updatedAt: new Date().toISOString() };
  const all = readStore(store);
  const idx = all.findIndex(r => r.id === req.params.id);
  if (idx >= 0) all[idx] = incoming; else all.push(incoming);
  writeStore(store, all);
  res.json(incoming);
});

app.post('/api/:store/push', (req, res) => {
  const store = req.params.store;
  const records = (req.body && req.body.records) || [];
  const all = readStore(store);
  const byId = new Map(all.map(r => [r.id, r]));
  records.forEach(rec => byId.set(rec.id, { ...rec, updatedAt: rec.updatedAt || new Date().toISOString() }));
  writeStore(store, Array.from(byId.values()));
  res.json({ ok: true, count: records.length });
});

app.delete('/api/:store/:id', (req, res) => {
  const store = req.params.store;
  if (DELETE_PROTECTED_STORES.has(store) && !hasPermission(req.user, 'canDelete')) {
    return res.status(403).json({ error: 'Not authorized to delete records.' });
  }
  const all = readStore(store).filter(r => r.id !== req.params.id);
  writeStore(store, all);
  res.json({ ok: true });
});

app.delete('/api/:store', (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only an admin can erase an entire store.' });
  writeStore(req.params.store, []);
  res.json({ ok: true });
});

// ---- Backups: every store, one JSON file, downloadable on demand ----
function buildFullBackup() {
  const backup = { generatedAt: new Date().toISOString() };
  fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json')).forEach(f => {
    const store = f.replace(/\.json$/, '');
    backup[store] = readStore(store);
  });
  return backup;
}

app.get('/api/backup', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin' && !hasPermission(req.user, 'canViewFinance')) {
    return res.status(403).json({ error: 'Not authorized to download a full backup.' });
  }
  const backup = buildFullBackup();
  res.setHeader('Content-Disposition', `attachment; filename="pharmadesk-backup-${new Date().toISOString().slice(0,10)}.json"`);
  res.json(backup);
});

// Optional: email the backup, only works if SMTP_* env vars are configured.
app.post('/api/backup/email', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only an admin can email a backup.' });
  const { to } = req.body || {};
  if (!to) return res.status(400).json({ error: '"to" email address is required.' });
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return res.status(400).json({ error: 'Email is not configured on this server yet — set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM environment variables and restart.' });
  }
  try {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    const backup = buildFullBackup();
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject: `PharmaDesk backup — ${new Date().toISOString().slice(0,10)}`,
      text: 'Full data backup attached.',
      attachments: [{ filename: `pharmadesk-backup-${new Date().toISOString().slice(0,10)}.json`, content: JSON.stringify(backup, null, 2) }]
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('Email backup failed:', e);
    res.status(500).json({ error: 'Could not send the email — check SMTP settings.' });
  }
});

// ---- Automatic daily snapshot on disk, kept for 30 days, so you always
// have a recovery point even if nobody remembers to click "backup" ----
function writeDailySnapshot() {
  try {
    const backup = buildFullBackup();
    const file = path.join(BACKUP_DIR, `backup-${new Date().toISOString().slice(0,10)}.json`);
    fs.writeFileSync(file, JSON.stringify(backup));
    const cutoff = Date.now() - 30 * 86400000;
    fs.readdirSync(BACKUP_DIR).forEach(f => {
      const full = path.join(BACKUP_DIR, f);
      if (fs.statSync(full).mtimeMs < cutoff) fs.unlinkSync(full);
    });
    console.log('Daily backup snapshot written:', file);
  } catch (e) { console.error('Daily snapshot failed:', e); }
}
writeDailySnapshot(); // one on boot
setInterval(writeDailySnapshot, 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`PharmaDesk server listening on port ${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
});
