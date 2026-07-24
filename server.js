require('dotenv').config();

const express   = require('express');
const session   = require('express-session');
const passport  = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Pool }  = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

// ── DATABASE ──────────────────────────────────────────────────────────────
let db = null;
const memStore = { members: [], pending: [] };

if (process.env.DATABASE_URL) {
  db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  db.query(`
    CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" varchar NOT NULL COLLATE "default",
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL,
      CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
    );
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
  `).then(() => console.log('DB ready')).catch(e => console.error('DB init error:', e.message));
}

async function dbGet(key) {
  if (!db) return memStore[key] ?? [];
  const r = await db.query('SELECT value FROM kv_store WHERE key=$1', [key]);
  return r.rows[0] ? JSON.parse(r.rows[0].value) : [];
}
async function dbSet(key, value) {
  if (!db) { memStore[key] = value; return; }
  await db.query(
    'INSERT INTO kv_store(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
    [key, JSON.stringify(value)]
  );
}

// ── SESSION ───────────────────────────────────────────────────────────────
app.use(express.json());
const sessionStore = db ? new PgSession({ pool: db, tableName: 'session', createTableIfMissing: true }) : undefined;
app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'portal-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ── PASSPORT (Google OAuth) ─────────────────────────────────────────────────
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID     || 'PLACEHOLDER',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'PLACEHOLDER',
  callbackURL:  process.env.GOOGLE_CALLBACK_URL  || '/auth/google/callback'
}, (_at, _rt, profile, done) => {
  done(null, {
    id: profile.id,
    email: profile.emails?.[0]?.value || '',
    name: profile.displayName,
    photo: profile.photos?.[0]?.value || ''
  });
}));
passport.serializeUser((u, done) => done(null, u));
passport.deserializeUser((u, done) => done(null, u));
app.use(passport.initialize());
app.use(passport.session());

// ── AUTH ROUTES ───────────────────────────────────────────────────────────
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?error=auth_failed' }),
  (req, res) => res.redirect('/')
);
app.get('/auth/logout', (req, res) => req.logout(() => res.redirect('/')));

// ── ROLE ──────────────────────────────────────────────────────────────────
// owner: theo OWNER_EMAIL trong biến môi trường (toàn quyền duyệt access)
// member: email đã được owner duyệt (được xem Portal)
// none: đã đăng nhập nhưng chưa được duyệt → tự động vào hàng chờ "pending"
async function getRole(email) {
  if (!email) return 'none';
  const owner = process.env.OWNER_EMAIL || '';
  if (email === owner) return 'owner';
  const members = await dbGet('members');
  if (members.includes(email)) return 'member';
  return 'none';
}

app.get('/api/me', async (req, res) => {
  const user = req.user || null;
  const role = user ? await getRole(user.email) : 'none';

  if (user && role === 'none') {
    const pending = await dbGet('pending');
    if (!pending.includes(user.email)) {
      pending.push(user.email);
      await dbSet('pending', pending);
    }
  }
  res.json({ user, role });
});

// ── API: ACCESS CONTROL (chỉ Owner) ─────────────────────────────────────────
function requireOwner(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  getRole(req.user.email).then(role => {
    if (role !== 'owner') return res.status(403).json({ error: 'Forbidden' });
    next();
  });
}

app.get('/api/access', requireOwner, async (_req, res) => {
  res.json({ members: await dbGet('members'), pending: await dbGet('pending') });
});

app.post('/api/access/approve', requireOwner, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  let members = await dbGet('members');
  let pending = await dbGet('pending');
  if (!members.includes(email)) members.push(email);
  pending = pending.filter(e => e !== email);
  await dbSet('members', members);
  await dbSet('pending', pending);
  res.json({ ok: true });
});

app.delete('/api/access/pending/:email', requireOwner, async (req, res) => {
  const email = decodeURIComponent(req.params.email);
  const pending = (await dbGet('pending')).filter(e => e !== email);
  await dbSet('pending', pending);
  res.json({ ok: true });
});

app.delete('/api/access/members/:email', requireOwner, async (req, res) => {
  const email = decodeURIComponent(req.params.email);
  const members = (await dbGet('members')).filter(e => e !== email);
  await dbSet('members', members);
  res.json({ ok: true });
});

// ── STATIC ────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Portal on port ${PORT}`));
