'use strict';
require('dotenv').config();
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProd = process.env.NODE_ENV === 'production';

if (isProd) app.set('trust proxy', 1);

const SESSION_SECRET = (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32)
  ? process.env.SESSION_SECRET
  : crypto.createHash('sha256').update(process.env.TURSO_AUTH_TOKEN || 'lumen-academy-default-secret-key').digest('hex');

const db = process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN
  ? createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN })
  : null;

class CloudSessionStore extends session.Store {
  async get(sid, cb) {
    if (!db) return cb(null, null);
    try {
      const res = await db.execute({ sql: 'SELECT sess, expire FROM sessions WHERE sid = ?', args: [sid] });
      const row = res.rows[0];
      if (!row) return cb(null, null);
      if (Number(row.expire) < Date.now()) {
        await db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] });
        return cb(null, null);
      }
      cb(null, JSON.parse(row.sess));
    } catch (err) { cb(err); }
  }
  async set(sid, sess, cb) {
    if (!db) return cb && cb(null);
    try {
      const expire = sess?.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      await db.execute({
        sql: 'INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire',
        args: [sid, JSON.stringify(sess), expire]
      });
      cb && cb(null);
    } catch (err) { cb && cb(err); }
  }
  async destroy(sid, cb) {
    if (!db) return cb && cb(null);
    try {
      await db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] });
      cb && cb(null);
    } catch (err) { cb && cb(err); }
  }
}

let ready = false;
async function initDatabase() {
  if (ready) return;
  if (!db) throw new Error('Database not configured: add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in your host settings.');

  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('student','teacher','coordinator','principal','owner')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS invite_codes (
      code TEXT PRIMARY KEY,
      role TEXT NOT NULL CHECK(role IN ('student','teacher','coordinator','principal')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      author_id INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS progress (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      chapter_id TEXT NOT NULL,
      completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(user_id, chapter_id)
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expire INTEGER NOT NULL
    )`
  ], 'write');

  const countRes = await db.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'owner'");
  if (Number(countRes.rows[0]?.count || 0) === 0) {
    const ownerName = (process.env.OWNER_NAME || 'Srikanth').trim();
    const ownerEmail = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
    const ownerPass = process.env.OWNER_PASSWORD || '';
    if (ownerEmail && ownerPass.length >= 8) {
      const hash = await bcrypt.hash(ownerPass, 10);
      await db.execute({
        sql: 'INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
        args: [ownerName, ownerEmail, hash, 'owner']
      });
    }
  }
  ready = true;
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '64kb' }));

app.use(session({
  name: 'lumen.sid',
  store: new CloudSessionStore(),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24
  }
}));

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 10 minutes.' }
});

app.use('/api', async (req, res, next) => {
  try {
    await initDatabase();
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const sanitize = (str, max = 200) => (typeof str === 'string' ? str.trim().slice(0, max) : '');
const isEmail = (e) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const formatUser = (u) => u && ({ id: Number(u.id), n: u.name, e: u.email, r: u.role });

async function getSessionUser(req) {
  if (!req.session?.userId) return null;
  const res = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.session.userId] });
  return res.rows[0] || null;
}

async function requireLogin(req, res, next) {
  try {
    const user = await getSessionUser(req);
    if (!user) return res.status(401).json({ error: 'Please log in first.' });
    req.user = user;
    next();
  } catch (err) { next(err); }
}

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Permission denied.' });
    }
    next();
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, dbConnected: Boolean(db), ready });
});

app.get('/api/bootstrap', async (req, res, next) => {
  try {
    const user = await getSessionUser(req);
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');

    const postsRes = await db.execute(
      'SELECT p.id, p.title AS t, p.subject AS s, p.body AS b, p.created_at AS createdAt, u.name AS author FROM posts p JOIN users u ON u.id = p.author_id ORDER BY p.id DESC LIMIT 100'
    );

    let users = [], codes = [], done = {};
    if (user && ['teacher', 'coordinator', 'principal', 'owner'].includes(user.role)) {
      const q = user.role === 'owner'
        ? 'SELECT id, name AS n, email AS e, role AS r FROM users ORDER BY name'
        : "SELECT id, name AS n, email AS e, role AS r FROM users WHERE role != 'owner' ORDER BY name";
      users = (await db.execute(q)).rows;
    }
    if (user && user.role === 'owner') {
      codes = (await db.execute('SELECT code AS c, role AS r FROM invite_codes ORDER BY created_at DESC')).rows;
    }
    if (user) {
      const progRes = ['teacher', 'coordinator', 'principal', 'owner'].includes(user.role)
        ? await db.execute('SELECT users.email, progress.chapter_id FROM progress JOIN users ON users.id = progress.user_id')
        : await db.execute({ sql: 'SELECT ? AS email, chapter_id FROM progress WHERE user_id = ?', args: [user.email, user.id] });
      for (const row of progRes.rows) done[row.email + row.chapter_id] = 1;
    }

    res.json({
      csrfToken: req.session.csrfToken,
      me: formatUser(user),
      db: { users, posts: postsRes.rows, codes, done }
    });
  } catch (err) { next(err); }
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const name = sanitize(req.body.name, 80);
    const email = sanitize(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const invite = sanitize(req.body.invite, 80).toUpperCase();

    if (name.length < 2 || !isEmail(email) || password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Enter a valid name, email, and a password (8+ characters).' });
    }

    let role = 'student';
    if (invite) {
      const invRes = await db.execute({ sql: 'SELECT role FROM invite_codes WHERE code = ?', args: [invite] });
      if (!invRes.rows[0]) return res.status(400).json({ error: 'Invalid or already used invite code.' });
      role = invRes.rows[0].role;
    }

    const hash = await bcrypt.hash(password, 10);
    const ins = await db.execute({
      sql: 'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
      args: [name, email, hash, role]
    });

    if (invite) {
      await db.execute({ sql: 'DELETE FROM invite_codes WHERE code = ?', args: [invite] });
    }

    req.session.userId = Number(ins.lastInsertRowid);
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    const created = await getSessionUser(req);
    res.status(201).json({ me: formatUser(created), csrfToken: req.session.csrfToken });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const email = sanitize(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    const userRes = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
const user = userRes.rows[0];
if (!user || !(await bcrypt.compare(password, user.password_hash))) {
return res.status(401).json({ error: 'Incorrect email or password.' });
}
req.session.userId = Number(user.id);
req.session.csrfToken = crypto.randomBytes(24).toString('hex');
await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
res.json({ me: formatUser(user), csrfToken: req.session.csrfToken });
} catch (err) { next(err); }
});
app.post('/api/auth/logout', (req, res) => {
req.session.destroy(() => {
res.clearCookie('lumen.sid');
res.json({ ok: true });
});
});
app.post('/api/progress/:chapterId', requireLogin, async (req, res, next) => {
try {
if (req.user.role !== 'student') return res.status(403).json({ error: 'Only students can mark progress.' });
const chapterId = sanitize(req.params.chapterId, 100);
if (!/^[a-z0-9_-]+$/i.test(chapterId)) return res.status(400).json({ error: 'Invalid chapter ID.' });
await db.execute({ sql: 'INSERT OR IGNORE INTO progress (user_id, chapter_id) VALUES (?, ?)', args: [req.user.id, chapterId] });
res.json({ ok: true });
} catch (err) { next(err); }
});
app.post('/api/posts', requireLogin, allowRoles('teacher', 'owner'), async (req, res, next) => {
try {
const title = sanitize(req.body.title, 140);
const subject = sanitize(req.body.subject, 100);
const body = sanitize(req.body.body, 4000);
if (!title || !subject || !body) return res.status(400).json({ error: 'Title, subject, and message are required.' });
await db.execute({
sql: 'INSERT INTO posts (title, subject, body, author_id) VALUES (?, ?, ?, ?)',
args: [title, subject, body, req.user.id]
});
res.json({ ok: true });
} catch (err) { next(err); }
});
app.post('/api/invites', requireLogin, allowRoles('owner'), async (req, res, next) => {
try {
const role = req.body.role;
const prefixes = { student: 'STU', teacher: 'TCH', coordinator: 'COO', principal: 'PRI' };
if (!prefixes[role]) return res.status(400).json({ error: 'Invalid role.' });
const code = `${prefixes[role]}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
await db.execute({ sql: 'INSERT INTO invite_codes (code, role) VALUES (?, ?)', args: [code, role] });
res.status(201).json({ code, role });
} catch (err) { next(err); }
});
app.delete('/api/invites/:code', requireLogin, allowRoles('owner'), async (req, res, next) => {
try {
await db.execute({ sql: 'DELETE FROM invite_codes WHERE code = ?', args: [sanitize(req.params.code, 80)] });
res.json({ ok: true });
} catch (err) { next(err); }
});
app.delete('/api/users/:id', requireLogin, allowRoles('owner'), async (req, res, next) => {
try {
const id = Number(req.params.id);
if (!Number.isSafeInteger(id) || id === Number(req.user.id)) return res.status(400).json({ error: 'Invalid user ID.' });
await db.batch([
{ sql: 'DELETE FROM posts WHERE author_id = ?', args: [id] },
{ sql: "DELETE FROM users WHERE id = ? AND role != 'owner'", args: [id] }
], 'write');
res.json({ ok: true });
} catch (err) { next(err); }
});
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
console.error(err);
res.status(500).json({ error: err.message || 'Server error.' });
});
app.listen(PORT, () => console.log(`Lumen Academy server listening on port ${PORT}`));