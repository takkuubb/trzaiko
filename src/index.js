const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3008;
const BASE = '/trzaiko';
const RP_ID = process.env.RP_ID || 'app-ai.xvps.jp';
const RP_ORIGIN = process.env.RP_ORIGIN || 'https://app-ai.xvps.jp';

const upload = multer({ dest: '/tmp/trzaiko_uploads/' });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

function auth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'ログインが必要です' });
  next();
}
function admin(req, res, next) {
  if (req.session?.user?.role !== 'admin') return res.status(403).json({ error: '管理者権限が必要です' });
  next();
}
function center(req, res, next) {
  const r = req.session?.user?.role;
  if (r !== 'center' && r !== 'admin') return res.status(403).json({ error: 'センター権限が必要です' });
  next();
}
function sales(req, res, next) {
  if (req.session?.user?.role !== 'sales') return res.status(403).json({ error: '営業権限が必要です' });
  next();
}

// === Pages ===
app.get(`${BASE}/`, (req, res) => {
  if (!req.session?.user) return res.redirect(`${BASE}/login`);
  res.sendFile(path.join(__dirname, 'views', 'app.html'));
});
app.get(`${BASE}/login`, (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));

// === Auth ===
app.post(`${BASE}/api/auth/login`, (req, res) => {
  const { username, password } = req.body;
  const user = db.authenticate(username, password);
  if (!user) return res.status(401).json({ error: 'ユーザー名またはパスワードが正しくありません' });
  req.session.user = user;
  res.json({ success: true, user });
});
app.get(`${BASE}/api/auth/me`, (req, res) => {
  res.json(req.session?.user ? { logged_in: true, user: req.session.user } : { logged_in: false });
});
app.post(`${BASE}/api/auth/logout`, (req, res) => { req.session.destroy(); res.json({ success: true }); });

// === Passkey ===
app.post(`${BASE}/api/passkey/register-options`, auth, async (req, res) => {
  try {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    const u = req.session.user;
    const existing = db.getPasskeysByUser(u.id);
    const options = await generateRegistrationOptions({
      rpName: '東洋リース在庫管理', rpID: RP_ID,
      userID: new TextEncoder().encode(String(u.id)),
      userName: u.username, userDisplayName: u.username,
      excludeCredentials: existing.map(k => ({ id: k.credential_id, type: 'public-key' })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }
    });
    req.session.pkChallenge = options.challenge;
    res.json(options);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post(`${BASE}/api/passkey/register-verify`, auth, async (req, res) => {
  try {
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    const v = await verifyRegistrationResponse({
      response: req.body, expectedChallenge: req.session.pkChallenge,
      expectedOrigin: RP_ORIGIN, expectedRPID: RP_ID
    });
    if (v.verified && v.registrationInfo) {
      const ri = v.registrationInfo;
      db.savePasskey(req.session.user.id, ri.credentialID,
        Buffer.from(ri.credentialPublicKey).toString('base64'),
        ri.counter, req.body.response?.transports || []);
      res.json({ success: true });
    } else res.status(400).json({ error: '検証失敗' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post(`${BASE}/api/passkey/auth-options`, async (req, res) => {
  try {
    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
    const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'preferred' });
    req.session.pkChallenge = options.challenge;
    res.json(options);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post(`${BASE}/api/passkey/auth-verify`, async (req, res) => {
  try {
    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    const pk = db.getPasskeyByCred(req.body.id);
    if (!pk) return res.status(400).json({ error: 'パスキー未登録' });
    const v = await verifyAuthenticationResponse({
      response: req.body, expectedChallenge: req.session.pkChallenge,
      expectedOrigin: RP_ORIGIN, expectedRPID: RP_ID,
      credential: { id: pk.credential_id, publicKey: Buffer.from(pk.public_key, 'base64'), counter: pk.counter }
    });
    if (v.verified) {
      db.updatePasskeyCounter(req.body.id, v.authenticationInfo.newCounter);
      const u = db.getUser(pk.user_id);
      if (!u || !u.active) return res.status(401).json({ error: '無効アカウント' });
      req.session.user = { id: u.id, username: u.username, role: u.role };
      res.json({ success: true, user: req.session.user });
    } else res.status(400).json({ error: '認証失敗' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === Notifications ===
app.get(`${BASE}/api/notifications/count`, auth, (req, res) => {
  res.json({ count: db.getUnreadCount(req.session.user.id, req.session.user.role) });
});
app.get(`${BASE}/api/notifications`, auth, (req, res) => {
  res.json(db.listNotifications(req.session.user.id, req.session.user.role));
});
app.post(`${BASE}/api/notifications/:id/read`, auth, (req, res) => {
  db.markNotificationRead(req.params.id, req.session.user.id, req.session.user.role);
  res.json({ success: true });
});

// === Products ===
app.get(`${BASE}/api/products`, auth, (req, res) => {
  res.json(db.listProducts(req.session.user.role === 'admin'));
});
app.post(`${BASE}/api/products`, auth, admin, (req, res) => {
  try {
    const { code, name, stock } = req.body;
    if (!code || !name) return res.status(400).json({ error: '商品コードと商品名は必須' });
    if (!/^[a-zA-Z0-9\-_]+$/.test(code)) return res.status(400).json({ error: '商品コードは半角英数字・ハイフン・アンダースコアのみ' });
    db.createProduct(code, name, parseInt(stock) || 0);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message.includes('UNIQUE') ? '商品コード重複' : e.message }); }
});
app.put(`${BASE}/api/products/:id`, auth, admin, (req, res) => {
  db.updateProduct(req.params.id, req.body);
  res.json({ success: true });
});
app.post(`${BASE}/api/products/csv`, auth, admin, upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'CSVファイルを選択してください' });
    const fs = require('fs');
    let content = fs.readFileSync(req.file.path, 'utf-8');
    // Remove BOM
    if (content.charCodeAt(0) === 0xFEFF) content = content.substring(1);
    const lines = content.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) return res.status(400).json({ error: 'データ行がありません' });
    let created = 0, updated = 0, errors = [];
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split(',').map(c => c.replace(/^"|"$/g, '').trim());
      if (cols.length < 3) { errors.push(`行${i + 1}: 列不足`); continue; }
      const [code, name, stockStr] = cols;
      if (!code || !name) { errors.push(`行${i + 1}: 商品コードまたは商品名が空`); continue; }
      if (!/^[a-zA-Z0-9\-_]+$/.test(code)) { errors.push(`行${i + 1}: 商品コード不正 "${code}"`); continue; }
      const stock = parseInt(stockStr);
      if (isNaN(stock) || stock < 0) { errors.push(`行${i + 1}: 在庫数不正`); continue; }
      const r = db.upsertProductCSV(code, name, stock);
      if (r.action === 'created') created++; else updated++;
    }
    fs.unlinkSync(req.file.path);
    res.json({ success: true, created, updated, errors });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === Cases ===
app.post(`${BASE}/api/cases`, auth, sales, (req, res) => {
  try {
    const { name, items } = req.body;
    if (!name || !items || !items.length) return res.status(400).json({ error: '案件名と商品を入力してください' });
    for (const i of items) { if (!i.product_id || !i.quantity || i.quantity < 1) return res.status(400).json({ error: '商品と数量を正しく入力してください' }); }
    const id = db.createCase(name, req.session.user.id, items);
    res.json({ success: true, id });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get(`${BASE}/api/cases`, auth, (req, res) => {
  const u = req.session.user;
  const filters = { status: req.query.status || '', search: req.query.search || '' };
  if (u.role === 'sales') filters.requested_by = u.id;
  res.json(db.listCases(filters));
});

app.get(`${BASE}/api/cases/:id`, auth, (req, res) => {
  const c = db.getCase(req.params.id);
  if (!c) return res.status(404).json({ error: '案件が見つかりません' });
  const u = req.session.user;
  if (u.role === 'sales' && c.requested_by !== u.id) return res.status(403).json({ error: '権限がありません' });
  // Mark notifications read
  db.markCaseNotificationsRead(c.id, u.id, u.role);
  res.json(c);
});

app.post(`${BASE}/api/cases/:id/lend`, auth, center, (req, res) => {
  try {
    db.processLending(req.params.id, req.session.user.id, req.body.items || []);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post(`${BASE}/api/cases/:id/return`, auth, center, (req, res) => {
  try {
    db.processReturn(req.params.id, req.session.user.id, req.body.items || []);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// === Transactions ===
app.get(`${BASE}/api/transactions`, auth, (req, res) => {
  const r = req.session.user.role;
  if (r !== 'center' && r !== 'admin') return res.status(403).json({ error: '権限がありません' });
  res.json(db.listTransactions({ product_id: req.query.product_id, product_search: req.query.search }));
});

// === Inventory Check ===
app.post(`${BASE}/api/inventory-check`, auth, (req, res) => {
  const r = req.session.user.role;
  if (r !== 'center' && r !== 'admin') return res.status(403).json({ error: '権限がありません' });
  try {
    const count = db.processInventoryCheck(req.body.checks || [], req.session.user.id);
    res.json({ success: true, count });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get(`${BASE}/api/inventory-checks`, auth, (req, res) => {
  const r = req.session.user.role;
  if (r !== 'center' && r !== 'admin') return res.status(403).json({ error: '権限がありません' });
  res.json(db.listInventoryChecks(req.query.product_id));
});

// === Admin: Users ===
app.get(`${BASE}/api/admin/users`, auth, admin, (req, res) => res.json(db.listUsers()));
app.post(`${BASE}/api/admin/users`, auth, admin, (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password || !role) return res.status(400).json({ error: '全項目を入力してください' });
    db.createUser(username, password, role);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message.includes('UNIQUE') ? 'ユーザー名重複' : e.message }); }
});
app.put(`${BASE}/api/admin/users/:id`, auth, admin, (req, res) => {
  db.updateUser(req.params.id, req.body);
  res.json({ success: true });
});
app.delete(`${BASE}/api/admin/users/:id`, auth, admin, (req, res) => {
  db.deleteUser(req.params.id);
  res.json({ success: true });
});

// Init
db.getDb();
app.listen(PORT, '0.0.0.0', () => console.log(`東洋リース在庫管理 on http://0.0.0.0:${PORT}${BASE}/`));
