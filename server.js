'use strict';
require('dotenv').config();
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set to a random value of at least 32 characters.');
}
if (production && process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'lumen.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('student','teacher','coordinator','principal','owner')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS invite_codes (
 code TEXT PRIMARY KEY,
 role TEXT NOT NULL CHECK(role IN ('student','teacher','coordinator','principal')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 subject TEXT NOT NULL,
 body TEXT NOT NULL,
 author_id INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS progress (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 chapter_id TEXT NOT NULL,
 completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id, chapter_id)
);
`);

// Create the first owner from environment variables. There is no public owner signup.
const ownerCount = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='owner'").get().n;
if (!ownerCount) {
  const name = (process.env.OWNER_NAME || '').trim();
  const email = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
  const password = process.env.OWNER_PASSWORD || '';
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12 || password === 'change-this-to-a-long-unique-password') {
    throw new Error('First run: set OWNER_NAME, OWNER_EMAIL and a unique OWNER_PASSWORD (12+ chars) in .env.');
  }
  db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)')
    .run(name, email, bcrypt.hashSync(password, 12), 'owner');
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(session({
  name: 'lumen.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, table: 'sessions' }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: production, sameSite: 'strict', maxAge: 1000 * 60 * 60 * 8 }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Please wait 15 minutes and try again.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', apiLimiter);
const roles = ['student','teacher','coordinator','principal','owner'];
const publicUser = u => u && ({ id: u.id, n: u.name, e: u.email, r: u.role });
const currentUser = req => req.session.userId ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId) : null;
function requireAuth(req,res,next){ const u=currentUser(req); if(!u) return res.status(401).json({error:'Please log in.'}); req.user=u; next(); }
function requireRole(...allowed){ return (req,res,next)=>{ if(!req.user || !allowed.includes(req.user.role)) return res.status(403).json({error:'You do not have permission for this action.'}); next(); }; }
function csrf(req,res,next){
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.get('origin');
  if (origin) { try { if (new URL(origin).host !== req.get('host')) return res.status(403).json({error:'Invalid request origin.'}); } catch { return res.status(403).json({error:'Invalid request origin.'}); } }
  const token=req.get('x-csrf-token');
  const supplied=Buffer.from(token || '');
  const expected=Buffer.from(req.session.csrfToken || '');
  if (!req.session.csrfToken || !token || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return res.status(403).json({error:'Security token expired. Refresh the page and try again.'});
  next();
}
app.use('/api', csrf);
const validEmail = e => typeof e==='string' && e.length<=254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const clean = (s,max) => typeof s==='string' ? s.trim().slice(0,max) : '';

app.get('/api/bootstrap',(req,res)=>{
  const u=currentUser(req);
  if (!req.session.csrfToken) req.session.csrfToken=crypto.randomBytes(32).toString('hex');
  const posts=db.prepare('SELECT p.id,p.title AS t,p.subject AS s,p.body AS b,p.created_at AS createdAt,u.name AS author FROM posts p JOIN users u ON u.id=p.author_id ORDER BY p.id DESC LIMIT 100').all();
  let users=[],codes=[],done={};
  if(u && ['teacher','coordinator','principal','owner'].includes(u.role)) users=db.prepare("SELECT id,name AS n,email AS e,role AS r FROM users WHERE role!='owner' ORDER BY name").all();
  if(u && u.role==='owner') {
    users=db.prepare('SELECT id,name AS n,email AS e,role AS r FROM users ORDER BY name').all();
    codes=db.prepare('SELECT code AS c,role AS r FROM invite_codes ORDER BY created_at DESC').all();
  }
  if(u) {
    const rows = ['teacher','coordinator','principal','owner'].includes(u.role)
      ? db.prepare('SELECT users.email, progress.chapter_id FROM progress JOIN users ON users.id=progress.user_id').all()
      : db.prepare('SELECT ? AS email, chapter_id FROM progress WHERE user_id=?').all(u.email,u.id);
    for(const p of rows) done[p.email+p.chapter_id]=1;
  }
  // Student accounts receive only their own progress; staff dashboards receive the records needed for school metrics.
  res.json({csrfToken:req.session.csrfToken,me:publicUser(u),db:{users,posts,codes,done}});
});

app.post('/api/auth/signup',authLimiter,async(req,res)=>{
  const name=clean(req.body.name,80), email=clean(req.body.email,254).toLowerCase(), password=req.body.password, invite=clean(req.body.invite,80).toUpperCase();
  if(name.length<2 || !validEmail(email) || typeof password!=='string' || password.length<12 || password.length>128) return res.status(400).json({error:'Enter a name, valid email and a password of at least 12 characters.'});
  const code=invite ? db.prepare('SELECT * FROM invite_codes WHERE code=?').get(invite) : null;
  if(invite && !code) return res.status(400).json({error:'That invitation code is invalid or has already been used.'});
  const role=code ? code.role : 'student';
  try {
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(name,email,hash,role);
    if(code) db.prepare('DELETE FROM invite_codes WHERE code=?').run(invite);
    await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
    req.session.userId=Number(info.lastInsertRowid); req.session.csrfToken=crypto.randomBytes(32).toString('hex');
    res.status(201).json({me:publicUser(currentUser(req)),csrfToken:req.session.csrfToken});
  } catch(e) { if(String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({error:'An account with that email already exists.'}); console.error(e); res.status(500).json({error:'Could not create the account.'}); }
});
app.post('/api/auth/login',authLimiter,async(req,res)=>{
  const email=clean(req.body.email,254).toLowerCase(), password=typeof req.body.password==='string'?req.body.password:'';
  const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
  await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
  req.session.userId=u.id; req.session.csrfToken=crypto.randomBytes(32).toString('hex');
  res.json({me:publicUser(u),csrfToken:req.session.csrfToken});
});
app.post('/api/auth/logout',requireAuth,(req,res)=>req.session.destroy(()=>{res.clearCookie('lumen.sid',{httpOnly:true,sameSite:'strict',secure:production});res.json({ok:true});}));

app.post('/api/progress/:chapterId',requireAuth,(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Only student accounts can mark chapters complete.'});
  const id=clean(req.params.chapterId,100);
  if(!/^[a-z0-9_-]+$/i.test(id)) return res.status(400).json({error:'Invalid chapter.'});
  db.prepare('INSERT OR IGNORE INTO progress(user_id,chapter_id) VALUES(?,?)').run(req.user.id,id);
  res.json({ok:true});
});
app.post('/api/posts',requireAuth,requireRole('teacher','owner'),(req,res)=>{
  const title=clean(req.body.title,140), subject=clean(req.body.subject,100), body=clean(req.body.body,4000);
  if(!title || !subject || !body) return res.status(400).json({error:'Enter a title, subject and message.'});
  db.prepare('INSERT INTO posts(title,subject,body,author_id) VALUES(?,?,?,?)').run(title,subject,body,req.user.id);
  res.json({ok:true});
});
app.post('/api/invites',requireAuth,requireRole('owner'),(req,res)=>{
  const role=req.body.role;
  if(!['student','teacher','coordinator','principal'].includes(role)) return res.status(400).json({error:'Invalid account type.'});
  const prefix={student:'STU',teacher:'TCH',coordinator:'COO',principal:'PRI'}[role];
  let code; do { code=prefix+'-'+crypto.randomBytes(4).toString('hex').toUpperCase(); } while(db.prepare('SELECT 1 FROM invite_codes WHERE code=?').get(code));
  db.prepare('INSERT INTO invite_codes(code,role) VALUES(?,?)').run(code,role);
  res.status(201).json({code,role});
});
app.delete('/api/invites/:code',requireAuth,requireRole('owner'),(req,res)=>{db.prepare('DELETE FROM invite_codes WHERE code=?').run(clean(req.params.code,80));res.json({ok:true});});
app.delete('/api/users/:id',requireAuth,requireRole('owner'),(req,res)=>{
  const id=Number(req.params.id); if(!Number.isSafeInteger(id) || id===req.user.id) return res.status(400).json({error:'Invalid account.'});
  const remove=db.transaction(()=>{ db.prepare('DELETE FROM posts WHERE author_id=?').run(id); db.prepare("DELETE FROM users WHERE id=? AND role!='owner'").run(id); });
  remove(id); res.json({ok:true});
});

app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});
app.listen(PORT,()=>console.log(`Lumen Academy running at http://localhost:${PORT}`));
