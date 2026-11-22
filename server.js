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
const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set to a random value of at least 32 characters.');
}
if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  throw new Error('TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set.');
}
if (production && process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

class TursoSessionStore extends session.Store {
  async get(sid, cb) {
    try {
      const r = await db.execute({ sql: 'SELECT sess, expire FROM sessions WHERE sid = ?', args: [sid] });
      if (!r.rows.length) return cb(null, null);
      if (Number(r.rows[0].expire) < Date.now()) {
        await db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] });
        return cb(null, null);
      }
      cb(null, JSON.parse(r.rows[0].sess));
    } catch (e) { cb(e); }
  }
  async set(sid, sess, cb) {
    try {
      const expire = sess?.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 1000 * 60 * 60 * 8;
      await db.execute({
        sql: 'INSERT INTO sessions(sid, sess, expire) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expire=excluded.expire',
        args: [sid, JSON.stringify(sess), expire]
      });
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  async destroy(sid, cb) {
    try {
      await db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] });
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
}

let initPromise = null;
function ensureInit() {
  if (!initPromise) {
    initPromise = (async () => {
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

      const ownerRes = await db.execute("SELECT COUNT(*) AS n FROM users WHERE role='owner'");
      if (!Number(ownerRes.rows[0].n)) {
        const name = (process.env.OWNER_NAME || '').trim();
        const email = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
        const password = process.env.OWNER_PASSWORD || '';
        if (!name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12) {
          throw new Error('Set OWNER_NAME, OWNER_EMAIL and OWNER_PASSWORD (12+ chars).');
        }
        await db.execute({
          sql: 'INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)',
          args: [name, email, await bcrypt.hash(password, 12), 'owner']
        });
      }
    })().catch(err => { initPromise = null; throw err; });
  }
  return initPromise;
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(async (req, res, next) => { try { await ensureInit(); next(); } catch (e) { next(e); } });
app.use(session({
  name: 'lumen.sid',
  store: new TursoSessionStore(),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: production, sameSite: 'strict', maxAge: 1000 * 60 * 60 * 8 }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Please wait 15 minutes and try again.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', apiLimiter);

const publicUser = u => u && ({ id: Number(u.id), n: u.name, e: u.email, r: u.role });
async function currentUser(req) {
  if (!req.session.userId) return null;
  const r = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [req.session.userId] });
  return r.rows[0] || null;
}
async function requireAuth(req, res, next) {
  try {
    const u = await currentUser(req);
    if (!u) return res.status(401).json({ error: 'Please log in.' });
    req.user = u;
    next();
  } catch (e) { next(e); }
}
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) return res.status(403).json({ error: 'You do not have permission for this action.' });
    next();
  };
}
function csrf(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.get('origin');
  if (origin) {
    try {
      if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Invalid request origin.' });
    } catch { return res.status(403).json({ error: 'Invalid request origin.' }); }
  }
  if (req.path === '/auth/login' || req.path === '/auth/signup') return next();
  const token = req.get('x-csrf-token');
  const supplied = Buffer.from(token || '');
  const expected = Buffer.from(req.session.csrfToken || '');
  if (!req.session.csrfToken || !token || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.status(403).json({ error: 'Security token expired. Refresh the page and try again.' });
  }
  next();
}
app.use('/api', csrf);

const validEmail = e => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const clean = (s, max) => typeof s === 'string' ? s.trim().slice(0, max) : '';

app.get('/api/bootstrap', async (req, res, next) => {
  try {
    const u = await currentUser(req);
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    const postsRes = await db.execute('SELECT p.id,p.title AS t,p.subject AS s,p.body AS b,p.created_at AS createdAt,u.name AS author FROM posts p JOIN users u ON u.id=p.author_id ORDER BY p.id DESC LIMIT 100');
    let users = [], codes = [], done = {};
    if (u && ['teacher', 'coordinator', 'principal', 'owner'].includes(u.role)) {
      const ur = await db.execute("SELECT id,name AS n,email AS e,role AS r FROM users WHERE role!='owner' ORDER BY name");
      users = ur.rows;
    }
    if (u && u.role === 'owner') {
      const ur = await db.execute('SELECT id,name AS n,email AS e,role AS r FROM users ORDER BY name');
      const cr = await db.execute('SELECT code AS c,role AS r FROM invite_codes ORDER BY created_at DESC');
      users = ur.rows;
      codes = cr.rows;
    }
    if (u) {
      const pr = ['teacher', 'coordinator', 'principal', 'owner'].includes(u.role)
        ? await db.execute('SELECT users.email, progress.chapter_id FROM progress JOIN users ON users.id=progress.user_id')
        : await db.execute({ sql: 'SELECT ? AS email, chapter_id FROM progress WHERE user_id=?', args: [u.email, u.id] });
      for (const p of pr.rows) done[p.email + p.chapter_id] = 1;
    }
    res.json({ csrfToken: req.session.csrfToken, me: publicUser(u), db: { users, posts: postsRes.rows, codes, done } });
  } catch (e) { next(e); }
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const name = clean(req.body.name, 80), email = clean(req.body.email, 254).toLowerCase(), password = req.body.password, invite = clean(req.body.invite, 80).toUpperCase();
  if (name.length < 2 || !validEmail(email) || typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: 'Enter a name, valid email and a password of at least 12 characters.' });
  }
  const codeRes = invite ? await db.execute({ sql: 'SELECT * FROM invite_codes WHERE code=?', args: [invite] }) : null;
  const code = codeRes?.rows[0] || null;
  if (invite && !code) return res.status(400).json({ error: 'That invitation code is invalid or has already been used.' });
  const role = code ? code.role : 'student';
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = await db.execute({ sql: 'INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', args: [name, email, hash, role] });
    if (code) await db.execute({ sql: 'DELETE FROM invite_codes WHERE code=?', args: [invite] });
Use code with caution.
await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
req.session.userId = Number(info.lastInsertRowid);
req.session.csrfToken = crypto.randomBytes(32).toString('hex');
res.status(201).json({ me: publicUser(await currentUser(req)), csrfToken: req.session.csrfToken });
} catch (e) {
if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'An account with that email already exists.' });
console.error(e);
res.status(500).json({ error: 'Could not create the account.' });
}
});
app.post('/api/auth/login', authLimiter, async (req, res, next) => {
try {
const email = clean(req.body.email, 254).toLowerCase(), password = typeof req.body.password === 'string' ? req.body.password : '';
const ur = await db.execute({ sql: 'SELECT * FROM users WHERE email=?', args: [email] });
const u = ur.rows[0];
if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
req.session.userId = Number(u.id);
req.session.csrfToken = crypto.randomBytes(32).toString('hex');
res.json({ me: publicUser(u), csrfToken: req.session.csrfToken });
} catch (e) { next(e); }
});
app.post('/api/auth/logout', requireAuth, (req, res) => {
req.session.destroy(() => {
res.clearCookie('lumen.sid', { httpOnly: true, sameSite: 'strict', secure: production });
res.json({ ok: true });
});
});
app.post('/api/progress/:chapterId', requireAuth, async (req, res, next) => {
try {
if (req.user.role !== 'student') return res.status(403).json({ error: 'Only student accounts can mark chapters complete.' });
const id = clean(req.params.chapterId, 100);
if (!/^[a-z0-9_-]+$/i.test(id)) return res.status(400).json({ error: 'Invalid chapter.' });
await db.execute({ sql: 'INSERT OR IGNORE INTO progress(user_id,chapter_id) VALUES(?,?)', args: [req.user.id, id] });
res.json({ ok: true });
} catch (e) { next(e); }
});
app.post('/api/posts', requireAuth, requireRole('teacher', 'owner'), async (req, res, next) => {
try {
const title = clean(req.body.title, 140), subject = clean(req.body.subject, 100), body = clean(req.body.body, 4000);
if (!title || !subject || !body) return res.status(400).json({ error: 'Enter a title, subject and message.' });
await db.execute({ sql: 'INSERT INTO posts(title,subject,body,author_id) VALUES(?,?,?,?)', args: [title, subject, body, req.user.id] });
res.json({ ok: true });
} catch (e) { next(e); }
});
app.post('/api/invites', requireAuth, requireRole('owner'), async (req, res, next) => {
try {
const role = req.body.role;
if (!['student', 'teacher', 'coordinator', 'principal'].includes(role)) return res.status(400).json({ error: 'Invalid account type.' });
const prefix = { student: 'STU', teacher: 'TCH', coordinator: 'COO', principal: 'PRI' }[role];
let code, exists;
do {
code = prefix + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
exists = await db.execute({ sql: 'SELECT 1 FROM invite_codes WHERE code=?', args: [code] });
} while (exists.rows.length);
await db.execute({ sql: 'INSERT INTO invite_codes(code,role) VALUES(?,?)', args: [code, role] });
res.status(201).json({ code, role });
} catch (e) { next(e); }
});
app.delete('/api/invites/:code', requireAuth, requireRole('owner'), async (req, res, next) => {
try {
await db.execute({ sql: 'DELETE FROM invite_codes WHERE code=?', args: [clean(req.params.code, 80)] });
res.json({ ok: true });
} catch (e) { next(e); }
});
app.delete('/api/users/:id', requireAuth, requireRole('owner'), async (req, res, next) => {
try {
const id = Number(req.params.id);
if (!Number.isSafeInteger(id) || id === Number(req.user.id)) return res.status(400).json({ error: 'Invalid account.' });
await db.batch([
{ sql: 'DELETE FROM posts WHERE author_id=?', args: [id] },
{ sql: "DELETE FROM users WHERE id=? AND role!='owner'", args: [id] }
], 'write');
res.json({ ok: true });
} catch (e) { next(e); }
});
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Unexpected server error.' }); });
if (require.main === module) {
app.listen(PORT, () => console.log(Lumen Academy running at http://localhost:${PORT}));
}
module.exports = app;
