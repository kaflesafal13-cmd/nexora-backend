'use strict';
// Nexora backend: accounts, sessions, wallet ledger, top-up requests, admin tools.
// Zero npm dependencies. Needs Node 22.13+ (uses the built-in node:sqlite).
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const scrypt = promisify(crypto.scrypt);

const PORT = Number(process.env.PORT) || 3000;
const SECURE = process.env.COOKIE_SECURE === 'true';      // set true when served over HTTPS
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';   // set true behind nginx/Caddy
const SESSION_MS = 7 * 24 * 3600 * 1000;
const MAX_AMOUNT = 1000000;                               // Rs, per transaction
const METHODS = ['Mobile wallet', 'Bank transfer', 'Other'];
const PUBLIC = path.join(__dirname, 'public');
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'nexora.db');

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'client' CHECK(role IN('client','admin')),
  balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL CHECK(type IN('credit','debit')), amount INTEGER NOT NULL CHECK(amount>0),
  balance_after INTEGER NOT NULL, method TEXT, reference TEXT, note TEXT,
  created_by INTEGER REFERENCES users(id), idem_key TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS tx_user ON transactions(user_id, id DESC);
CREATE TABLE IF NOT EXISTS topup_requests(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  amount INTEGER NOT NULL CHECK(amount>0), method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','rejected')),
  txn_id INTEGER REFERENCES transactions(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')), resolved_at TEXT);
`);

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const DUMMY_SALT = crypto.randomBytes(16).toString('hex');

// ---------- passwords: scrypt + per-user salt (plaintext is never stored) ----------
async function hashPw(pw, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  return { salt: salt.toString('hex'), hash: (await scrypt(pw, salt, 64)).toString('hex') };
}
async function verifyPw(pw, row) {
  if (!row) { await hashPw(pw, DUMMY_SALT); return false; } // same cost whether or not user exists
  const { hash } = await hashPw(pw, row.pw_salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(row.pw_hash, 'hex'));
}

// ---------- sessions (random token in httpOnly cookie; only its hash is stored) ----------
function cookies(req) {
  const o = {};
  for (const p of (req.headers.cookie || '').split(';')) { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }
  return o;
}
function cookieHeader(v, maxAge) {
  return `sid=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${SECURE ? '; Secure' : ''}`;
}
function startSession(res, uid) {
  const t = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(sha(t), uid, Date.now() + SESSION_MS);
  res.setHeader('Set-Cookie', cookieHeader(t, SESSION_MS / 1000));
}
function sessionUser(req) {
  const t = cookies(req).sid;
  if (!t) return null;
  return db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(sha(t), Date.now()) || null;
}

// ---------- tiny in-memory rate limiter ----------
const hits = new Map();
function limit(key, max, windowMs) {
  const now = Date.now(); let h = hits.get(key);
  if (!h || h.t < now) { h = { n: 0, t: now + windowMs }; hits.set(key, h); }
  if (++h.n > max) throw new HttpError(429, 'Too many attempts. Please try again later.');
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.t < n) hits.delete(k); }, 60000).unref();

// ---------- validation ----------
const uname = s => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_.]{3,24}$/.test(s.trim())) throw new HttpError(400, 'Username: 3 to 24 letters, numbers, dot or underscore.');
  return s.trim().toLowerCase();
};
const amt = n => {
  if (!Number.isInteger(n) || n < 1 || n > MAX_AMOUNT) throw new HttpError(400, 'Amount must be a whole number of Rs between 1 and 1,000,000.');
  return n;
};
const txt = (s, max) => (typeof s === 'string' && s.trim() ? s.trim().slice(0, max) : null);
const pub = u => ({ username: u.username, role: u.role, balance: u.balance });

// ---------- money movement: one atomic DB transaction = balance change + ledger row ----------
function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}
function move(userId, type, amount, o = {}) {   // call inside tx()
  const idem = o.idem ? `${userId}:${o.idem}` : null;
  if (idem) {
    const dup = db.prepare('SELECT * FROM transactions WHERE idem_key=?').get(idem);
    if (dup) return { txn: dup, duplicate: true };
  }
  const u = db.prepare('SELECT balance FROM users WHERE id=?').get(userId);
  if (!u) throw new HttpError(404, 'User not found.');
  const nb = u.balance + (type === 'credit' ? amount : -amount);
  if (nb < 0) throw new HttpError(400, `Insufficient balance (Rs ${u.balance}).`);
  db.prepare('UPDATE users SET balance=? WHERE id=?').run(nb, userId);
  const r = db.prepare('INSERT INTO transactions(user_id,type,amount,balance_after,method,reference,note,created_by,idem_key) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(userId, type, amount, nb, o.method || null, o.reference || null, o.note || null, o.by || null, idem);
  return { txn: db.prepare('SELECT * FROM transactions WHERE id=?').get(r.lastInsertRowid), duplicate: false };
}
const TXN_COLS = 'id,type,amount,balance_after,method,reference,note,created_at';

// ---------- routes ----------
const routes = [];
const route = (m, p, role, fn) => routes.push({ m, role, fn, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$') });
const send = (res, status, obj) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };

route('POST', '/api/register', null, async ({ res, body, ip }) => {
  limit('reg:' + ip, 10, 3600e3);
  const u = uname(body.username), p = body.password;
  if (typeof p !== 'string' || p.length < 8 || p.length > 128) throw new HttpError(400, 'Password must be 8 to 128 characters.');
  const { salt, hash } = await hashPw(p);
  let id;
  try { id = db.prepare('INSERT INTO users(username,pw_salt,pw_hash) VALUES(?,?,?)').run(u, salt, hash).lastInsertRowid; }
  catch (e) { if (/UNIQUE/i.test(e.message)) throw new HttpError(409, 'That username is already taken.'); throw e; }
  startSession(res, Number(id));
  send(res, 201, pub(db.prepare('SELECT * FROM users WHERE id=?').get(id)));
});

route('POST', '/api/login', null, async ({ res, body, ip }) => {
  const u = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  limit('ip:' + ip, 30, 15 * 60e3); limit('u:' + u, 8, 15 * 60e3);
  const row = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  if (!(await verifyPw(typeof body.password === 'string' ? body.password.slice(0, 128) : '', row))) throw new HttpError(401, 'Wrong username or password.');
  startSession(res, row.id);
  send(res, 200, pub(row));
});

route('POST', '/api/logout', null, ({ req, res }) => {
  const t = cookies(req).sid;
  if (t) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(t));
  res.setHeader('Set-Cookie', cookieHeader('', 0));
  send(res, 200, { ok: true });
});

route('GET', '/api/me', 'user', ({ res, user }) => send(res, 200, pub(user)));

route('GET', '/api/transactions', 'user', ({ res, user }) =>
  send(res, 200, { transactions: db.prepare(`SELECT ${TXN_COLS} FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 50`).all(user.id) }));

route('POST', '/api/topup-requests', 'user', ({ res, user, body }) => {
  const amount = amt(body.amount);
  if (!METHODS.includes(body.method)) throw new HttpError(400, 'Choose a payment method.');
  if (db.prepare("SELECT COUNT(*) c FROM topup_requests WHERE user_id=? AND status='pending'").get(user.id).c >= 5)
    throw new HttpError(429, 'You already have 5 pending top-up requests.');
  const r = db.prepare('INSERT INTO topup_requests(user_id,amount,method) VALUES(?,?,?)').run(user.id, amount, body.method);
  send(res, 201, { id: Number(r.lastInsertRowid), amount, method: body.method, status: 'pending' });
});

route('GET', '/api/topup-requests', 'user', ({ res, user }) =>
  send(res, 200, { requests: db.prepare('SELECT id,amount,method,status,created_at,resolved_at FROM topup_requests WHERE user_id=? ORDER BY id DESC LIMIT 50').all(user.id) }));

// ----- admin -----
route('GET', '/api/admin/users', 'admin', ({ res }) =>
  send(res, 200, { users: db.prepare("SELECT username,role,balance,created_at FROM users ORDER BY username").all() }));

route('GET', '/api/admin/topup-requests', 'admin', ({ res, url }) => {
  const st = ['pending', 'approved', 'rejected'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : 'pending';
  send(res, 200, { requests: db.prepare('SELECT r.id,u.username,r.amount,r.method,r.status,r.created_at FROM topup_requests r JOIN users u ON u.id=r.user_id WHERE r.status=? ORDER BY r.id').all(st) });
});

route('POST', '/api/admin/topup-requests/:id/approve', 'admin', ({ res, user, params }) => {
  const out = tx(() => {
    const r = db.prepare("SELECT * FROM topup_requests WHERE id=? AND status='pending'").get(Number(params.id));
    if (!r) throw new HttpError(404, 'No pending request with that id.');
    const m = move(r.user_id, 'credit', r.amount, { method: r.method, note: `Top-up request #${r.id}`, by: user.id, idem: 'topup:' + r.id });
    db.prepare("UPDATE topup_requests SET status='approved', txn_id=?, resolved_at=datetime('now') WHERE id=?").run(m.txn.id, r.id);
    return { username: db.prepare('SELECT username FROM users WHERE id=?').get(r.user_id).username, amount: r.amount, balance: m.txn.balance_after };
  });
  send(res, 200, out);
});

route('POST', '/api/admin/topup-requests/:id/reject', 'admin', ({ res, params }) => {
  const r = db.prepare("UPDATE topup_requests SET status='rejected', resolved_at=datetime('now') WHERE id=? AND status='pending'").run(Number(params.id));
  if (!r.changes) throw new HttpError(404, 'No pending request with that id.');
  send(res, 200, { ok: true });
});

for (const type of ['credit', 'debit']) {
  route('POST', `/api/admin/users/:username/${type}`, 'admin', ({ res, user, params, body }) => {
    const target = db.prepare('SELECT id FROM users WHERE username=?').get(uname(decodeURIComponent(params.username)));
    if (!target) throw new HttpError(404, 'No customer with that username.');
    const amount = amt(body.amount);
    const idem = txt(body.idempotencyKey, 80);
    const m = tx(() => move(target.id, type, amount, { method: txt(body.method, 40), reference: txt(body.reference, 80), note: txt(body.note, 200), by: user.id, idem }));
    send(res, 200, { transaction: m.txn, balance: m.txn.balance_after, duplicate: m.duplicate });
  });
}

route('GET', '/api/admin/transactions', 'admin', ({ res, url }) => {
  const u = url.searchParams.get('username');
  const lim = Math.min(Number(url.searchParams.get('limit')) || 100, 500);
  const rows = u
    ? db.prepare('SELECT t.*,x.username FROM transactions t JOIN users x ON x.id=t.user_id WHERE x.username=? ORDER BY t.id DESC LIMIT ?').all(uname(u), lim)
    : db.prepare('SELECT t.*,x.username FROM transactions t JOIN users x ON x.id=t.user_id ORDER BY t.id DESC LIMIT ?').all(lim);
  send(res, 200, { transactions: rows });
});

// ---------- http plumbing ----------
function readBody(req) {
  return new Promise((ok, bad) => {
    let n = 0, over = false; const c = [];
    req.on('data', d => { n += d.length; if (n > 10240) over = true; else c.push(d); });
    req.on('end', () => {
      if (over) return bad(new HttpError(413, 'Request too large.'));
      try {
        const b = c.length ? JSON.parse(Buffer.concat(c).toString()) : {};
        if (!b || typeof b !== 'object' || Array.isArray(b)) throw 0;
        ok(b);
      } catch { bad(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', bad);
  });
}

async function handleApi(req, res, url) {
  const r = routes.map(x => x.m === req.method && { x, m: x.re.exec(url.pathname) }).find(v => v && v.m);
  if (!r) throw new HttpError(404, 'Not found.');
  let body = {};
  if (req.method === 'POST') {
    const o = req.headers.origin;                      // CSRF defence on top of SameSite cookies
    if (o && new URL(o).host !== req.headers.host) throw new HttpError(403, 'Bad origin.');
    if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Send JSON.');
    body = await readBody(req);
  }
  const user = sessionUser(req);
  if (r.x.role && !user) throw new HttpError(401, 'Please log in.');
  if (r.x.role === 'admin' && user.role !== 'admin') throw new HttpError(403, 'Admins only.');
  const ip = (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
  await r.x.fn({ req, res, url, body, user, ip, params: r.m.groups || {} });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed.');
  let p; try { p = decodeURIComponent(url.pathname); } catch { throw new HttpError(400, 'Bad path.'); }
  if (p === '/') p = '/index.html';
  const f = path.normalize(path.join(PUBLIC, p));
  if (!f.startsWith(PUBLIC + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) throw new HttpError(404, 'Not found.');
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url); else serveStatic(req, res, url);
  } catch (e) {
    const s = e.status || 500;
    if (s === 500) console.error(e);
    if (!res.headersSent) send(res, s, { error: s === 500 ? 'Server error.' : e.message });
  }
});

(async () => {
  // Admin account comes from environment variables, never from public sign-up.
  const { ADMIN_USERNAME: au, ADMIN_PASSWORD: ap } = process.env;
  if (au && ap) {
    const u = uname(au); const { salt, hash } = await hashPw(ap);
    if (db.prepare('SELECT 1 FROM users WHERE username=?').get(u))
      db.prepare("UPDATE users SET pw_salt=?, pw_hash=?, role='admin' WHERE username=?").run(salt, hash, u);
    else db.prepare("INSERT INTO users(username,pw_salt,pw_hash,role) VALUES(?,?,?,'admin')").run(u, salt, hash);
    db.prepare("UPDATE users SET role='client' WHERE role='admin' AND username<>?").run(u); // only the .env admin keeps admin rights
    console.log(`Admin account ready: ${u}`);
  } else console.warn('ADMIN_USERNAME / ADMIN_PASSWORD not set: no admin can approve top-ups.');
  setInterval(() => db.prepare('DELETE FROM sessions WHERE expires_at<?').run(Date.now()), 3600e3).unref();
  server.listen(PORT, () => console.log(`Nexora backend listening on http://localhost:${PORT}`));
})();
