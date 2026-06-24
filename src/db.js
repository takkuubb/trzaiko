const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'trzaiko.db');
let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','sales','center')),
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      updated_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS passkeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      credential_id TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      stock INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      updated_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','lending','returned')),
      requested_by INTEGER NOT NULL REFERENCES users(id),
      requested_at TEXT DEFAULT (datetime('now','localtime')),
      lent_by INTEGER REFERENCES users(id),
      lent_at TEXT,
      returned_by INTEGER REFERENCES users(id),
      returned_at TEXT
    );

    CREATE TABLE IF NOT EXISTS case_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL REFERENCES cases(id),
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL DEFAULT 1,
      returned_quantity INTEGER NOT NULL DEFAULT 0,
      center_ref TEXT DEFAULT '',
      picked INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS stock_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL REFERENCES products(id),
      case_id INTEGER REFERENCES cases(id),
      type TEXT NOT NULL CHECK(type IN ('out','in','adjust')),
      quantity INTEGER NOT NULL,
      processed_by INTEGER NOT NULL REFERENCES users(id),
      processed_at TEXT DEFAULT (datetime('now','localtime')),
      memo TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS inventory_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL REFERENCES products(id),
      logical_stock INTEGER NOT NULL,
      physical_stock INTEGER NOT NULL,
      diff INTEGER NOT NULL,
      memo TEXT DEFAULT '',
      checked_by INTEGER NOT NULL REFERENCES users(id),
      checked_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      target_role TEXT,
      case_id INTEGER NOT NULL REFERENCES cases(id),
      type TEXT NOT NULL,
      message TEXT NOT NULL DEFAULT '',
      read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
    CREATE INDEX IF NOT EXISTS idx_cases_requested_by ON cases(requested_by);
    CREATE INDEX IF NOT EXISTS idx_case_items_case ON case_items(case_id);
    CREATE INDEX IF NOT EXISTS idx_stock_tx_product ON stock_transactions(product_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_role ON notifications(target_role);
    CREATE INDEX IF NOT EXISTS idx_passkeys_cred ON passkeys(credential_id);
  `);

  const cnt = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (cnt === 0) {
    const hash = bcrypt.hashSync('trzaiko2026', 10);
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)').run('admin', hash, 'admin');
    console.log('Created default admin: admin / trzaiko2026');
  }
}

// === Auth ===
function authenticate(username, password) {
  const u = getDb().prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(username);
  if (!u || !bcrypt.compareSync(password, u.password_hash)) return null;
  return { id: u.id, username: u.username, role: u.role };
}
function getUser(id) {
  return getDb().prepare('SELECT id, username, role, active, created_at FROM users WHERE id = ?').get(id);
}
function listUsers() {
  return getDb().prepare('SELECT id, username, role, active, created_at FROM users ORDER BY id').all();
}
function createUser(username, password, role) {
  const hash = bcrypt.hashSync(password, 10);
  return getDb().prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)').run(username, hash, role);
}
function updateUser(id, data) {
  const d = getDb();
  if (data.password) d.prepare("UPDATE users SET password_hash=?, updated_at=datetime('now','localtime') WHERE id=?").run(bcrypt.hashSync(data.password, 10), id);
  if (data.username !== undefined) d.prepare("UPDATE users SET username=?, updated_at=datetime('now','localtime') WHERE id=?").run(data.username, id);
  if (data.role !== undefined) d.prepare("UPDATE users SET role=?, updated_at=datetime('now','localtime') WHERE id=?").run(data.role, id);
  if (data.active !== undefined) d.prepare("UPDATE users SET active=?, updated_at=datetime('now','localtime') WHERE id=?").run(data.active ? 1 : 0, id);
}
function deleteUser(id) { getDb().prepare('DELETE FROM users WHERE id = ?').run(id); }

// === Passkey ===
function getPasskeysByUser(uid) { return getDb().prepare('SELECT * FROM passkeys WHERE user_id=?').all(uid); }
function savePasskey(uid, credId, pubKey, counter, transports) {
  return getDb().prepare('INSERT INTO passkeys (user_id,credential_id,public_key,counter,transports) VALUES(?,?,?,?,?)').run(uid, credId, pubKey, counter, JSON.stringify(transports || []));
}
function getPasskeyByCred(credId) { return getDb().prepare('SELECT * FROM passkeys WHERE credential_id=?').get(credId); }
function updatePasskeyCounter(credId, counter) { getDb().prepare('UPDATE passkeys SET counter=? WHERE credential_id=?').run(counter, credId); }

// === Products ===
function listProducts(includeInactive) {
  return getDb().prepare(includeInactive ? 'SELECT * FROM products ORDER BY code' : 'SELECT * FROM products WHERE active=1 ORDER BY code').all();
}
function getProduct(id) { return getDb().prepare('SELECT * FROM products WHERE id=?').get(id); }
function getProductByCode(code) { return getDb().prepare('SELECT * FROM products WHERE code=?').get(code); }
function createProduct(code, name, stock) {
  return getDb().prepare('INSERT INTO products (code,name,stock) VALUES(?,?,?)').run(code, name, stock || 0);
}
function updateProduct(id, data) {
  const d = getDb();
  if (data.code !== undefined) d.prepare('UPDATE products SET code=? WHERE id=?').run(data.code, id);
  if (data.name !== undefined) d.prepare('UPDATE products SET name=? WHERE id=?').run(data.name, id);
  if (data.stock !== undefined) d.prepare('UPDATE products SET stock=? WHERE id=?').run(data.stock, id);
  if (data.active !== undefined) d.prepare('UPDATE products SET active=? WHERE id=?').run(data.active ? 1 : 0, id);
  d.prepare("UPDATE products SET updated_at=datetime('now','localtime') WHERE id=?").run(id);
}
function upsertProductCSV(code, name, stock) {
  const existing = getProductByCode(code);
  if (existing) {
    getDb().prepare("UPDATE products SET name=?, stock=?, updated_at=datetime('now','localtime') WHERE id=?").run(name, stock, existing.id);
    return { action: 'updated', id: existing.id };
  } else {
    const r = createProduct(code, name, stock);
    return { action: 'created', id: r.lastInsertRowid };
  }
}

// === Cases ===
function createCase(name, requestedBy, items) {
  const d = getDb();
  const tx = d.transaction(() => {
    const r = d.prepare('INSERT INTO cases (name, requested_by) VALUES(?,?)').run(name, requestedBy);
    const caseId = r.lastInsertRowid;
    const stmt = d.prepare('INSERT INTO case_items (case_id, product_id, quantity) VALUES(?,?,?)');
    for (const item of items) {
      stmt.run(caseId, item.product_id, item.quantity);
    }
    // Notify all center users
    d.prepare("INSERT INTO notifications (target_role, case_id, type, message) VALUES('center',?,?,?)").run(caseId, 'new_request', `新規依頼: ${name}`);
    return caseId;
  });
  return tx();
}

function getCase(id) {
  const c = getDb().prepare(`SELECT c.*, u.username as requester_name,
    l.username as lender_name, ret.username as returner_name
    FROM cases c
    LEFT JOIN users u ON c.requested_by = u.id
    LEFT JOIN users l ON c.lent_by = l.id
    LEFT JOIN users ret ON c.returned_by = ret.id
    WHERE c.id = ?`).get(id);
  if (!c) return null;
  c.items = getDb().prepare(`SELECT ci.*, p.code as product_code, p.name as product_name, p.stock as current_stock
    FROM case_items ci LEFT JOIN products p ON ci.product_id = p.id
    WHERE ci.case_id = ? ORDER BY ci.id`).all(id);
  return c;
}

function listCases(filters) {
  const conds = [], params = [];
  if (filters.status) { conds.push('c.status=?'); params.push(filters.status); }
  if (filters.requested_by) { conds.push('c.requested_by=?'); params.push(filters.requested_by); }
  if (filters.search) { conds.push("c.name LIKE ?"); params.push('%' + filters.search + '%'); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  return getDb().prepare(`SELECT c.*, u.username as requester_name,
    (SELECT COUNT(*) FROM case_items WHERE case_id=c.id) as item_count
    FROM cases c LEFT JOIN users u ON c.requested_by = u.id
    ${where} ORDER BY c.requested_at DESC LIMIT 200`).all(...params);
}

function processLending(caseId, userId, itemUpdates) {
  const d = getDb();
  const tx = d.transaction(() => {
    const c = d.prepare('SELECT * FROM cases WHERE id=? AND status=?').get(caseId, 'requested');
    if (!c) throw new Error('案件が見つからないか、既に処理済みです');
    // Update items (center_ref, picked)
    const stmtRef = d.prepare('UPDATE case_items SET center_ref=?, picked=1 WHERE id=? AND case_id=?');
    const stmtTx = d.prepare('INSERT INTO stock_transactions (product_id, case_id, type, quantity, processed_by, memo) VALUES(?,?,?,?,?,?)');
    const stmtStock = d.prepare('UPDATE products SET stock = stock - ?, updated_at=datetime(\'now\',\'localtime\') WHERE id=?');
    const items = d.prepare('SELECT * FROM case_items WHERE case_id=?').all(caseId);
    for (const item of items) {
      const upd = itemUpdates?.find(u => u.id === item.id);
      const ref = upd?.center_ref || '';
      stmtRef.run(ref, item.id, caseId);
      stmtStock.run(item.quantity, item.product_id);
      stmtTx.run(item.product_id, caseId, 'out', item.quantity, userId, '貸出');
    }
    d.prepare("UPDATE cases SET status='lending', lent_by=?, lent_at=datetime('now','localtime') WHERE id=?").run(userId, caseId);
    // Notify requester
    d.prepare('INSERT INTO notifications (user_id, case_id, type, message) VALUES(?,?,?,?)').run(c.requested_by, caseId, 'status_change', `案件「${c.name}」が貸出中になりました`);
    return true;
  });
  return tx();
}

function processReturn(caseId, userId, returnItems) {
  const d = getDb();
  const tx = d.transaction(() => {
    const c = d.prepare('SELECT * FROM cases WHERE id=? AND status=?').get(caseId, 'lending');
    if (!c) throw new Error('案件が見つからないか、貸出中ではありません');
    const stmtRet = d.prepare('UPDATE case_items SET returned_quantity = returned_quantity + ? WHERE id=? AND case_id=?');
    const stmtTx = d.prepare('INSERT INTO stock_transactions (product_id, case_id, type, quantity, processed_by, memo) VALUES(?,?,?,?,?,?)');
    const stmtStock = d.prepare('UPDATE products SET stock = stock + ?, updated_at=datetime(\'now\',\'localtime\') WHERE id=?');
    for (const ri of returnItems) {
      if (ri.return_qty <= 0) continue;
      const item = d.prepare('SELECT * FROM case_items WHERE id=? AND case_id=?').get(ri.id, caseId);
      if (!item) continue;
      const maxReturn = item.quantity - item.returned_quantity;
      const qty = Math.min(ri.return_qty, maxReturn);
      if (qty <= 0) continue;
      stmtRet.run(qty, ri.id, caseId);
      stmtStock.run(qty, item.product_id);
      stmtTx.run(item.product_id, caseId, 'in', qty, userId, '返却');
    }
    // Check if all returned
    const remaining = d.prepare('SELECT SUM(quantity - returned_quantity) as remaining FROM case_items WHERE case_id=?').get(caseId);
    if (remaining.remaining <= 0) {
      d.prepare("UPDATE cases SET status='returned', returned_by=?, returned_at=datetime('now','localtime') WHERE id=?").run(userId, caseId);
      d.prepare('INSERT INTO notifications (user_id, case_id, type, message) VALUES(?,?,?,?)').run(c.requested_by, caseId, 'status_change', `案件「${c.name}」が返却完了しました`);
    }
    return true;
  });
  return tx();
}

// === Stock Transactions ===
function listTransactions(filters) {
  const conds = [], params = [];
  if (filters.product_id) { conds.push('st.product_id=?'); params.push(filters.product_id); }
  if (filters.case_id) { conds.push('st.case_id=?'); params.push(filters.case_id); }
  if (filters.product_search) { conds.push("(p.code LIKE ? OR p.name LIKE ?)"); params.push('%' + filters.product_search + '%', '%' + filters.product_search + '%'); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  return getDb().prepare(`SELECT st.*, p.code as product_code, p.name as product_name,
    c.name as case_name, u.username as processor_name
    FROM stock_transactions st
    LEFT JOIN products p ON st.product_id = p.id
    LEFT JOIN cases c ON st.case_id = c.id
    LEFT JOIN users u ON st.processed_by = u.id
    ${where} ORDER BY st.processed_at DESC LIMIT 500`).all(...params);
}

// === Inventory Check ===
function processInventoryCheck(checks, userId) {
  const d = getDb();
  const tx = d.transaction(() => {
    const stmtCheck = d.prepare('INSERT INTO inventory_checks (product_id, logical_stock, physical_stock, diff, memo, checked_by) VALUES(?,?,?,?,?,?)');
    const stmtStock = d.prepare("UPDATE products SET stock=?, updated_at=datetime('now','localtime') WHERE id=?");
    const stmtTx = d.prepare('INSERT INTO stock_transactions (product_id, type, quantity, processed_by, memo) VALUES(?,?,?,?,?)');
    let count = 0;
    for (const c of checks) {
      if (c.physical === undefined || c.physical === null) continue;
      const p = d.prepare('SELECT * FROM products WHERE id=?').get(c.product_id);
      if (!p) continue;
      const diff = c.physical - p.stock;
      stmtCheck.run(p.id, p.stock, c.physical, diff, c.memo || '', userId);
      if (diff !== 0) {
        stmtStock.run(c.physical, p.id);
        stmtTx.run(p.id, 'adjust', diff, userId, '棚卸調整: ' + (c.memo || ''));
      }
      count++;
    }
    return count;
  });
  return tx();
}

function listInventoryChecks(productId) {
  const q = productId
    ? 'SELECT ic.*, p.code as product_code, p.name as product_name, u.username as checker_name FROM inventory_checks ic LEFT JOIN products p ON ic.product_id=p.id LEFT JOIN users u ON ic.checked_by=u.id WHERE ic.product_id=? ORDER BY ic.checked_at DESC LIMIT 100'
    : 'SELECT ic.*, p.code as product_code, p.name as product_name, u.username as checker_name FROM inventory_checks ic LEFT JOIN products p ON ic.product_id=p.id LEFT JOIN users u ON ic.checked_by=u.id ORDER BY ic.checked_at DESC LIMIT 500';
  return productId ? getDb().prepare(q).all(productId) : getDb().prepare(q).all();
}

// === Notifications ===
function getUnreadCount(userId, role) {
  const d = getDb();
  if (role === 'center') {
    return d.prepare("SELECT COUNT(*) as c FROM notifications WHERE (target_role='center' OR user_id=?) AND read=0").get(userId).c;
  }
  return d.prepare('SELECT COUNT(*) as c FROM notifications WHERE user_id=? AND read=0').get(userId).c;
}

function listNotifications(userId, role) {
  const d = getDb();
  if (role === 'center') {
    return d.prepare("SELECT n.*, c.name as case_name FROM notifications n LEFT JOIN cases c ON n.case_id=c.id WHERE (n.target_role='center' OR n.user_id=?) AND n.read=0 ORDER BY n.created_at DESC LIMIT 20").all(userId);
  }
  return d.prepare('SELECT n.*, c.name as case_name FROM notifications n LEFT JOIN cases c ON n.case_id=c.id WHERE n.user_id=? AND n.read=0 ORDER BY n.created_at DESC LIMIT 20').all(userId);
}

function markNotificationRead(id, userId, role) {
  if (role === 'center') {
    getDb().prepare('UPDATE notifications SET read=1 WHERE id=?').run(id);
  } else {
    getDb().prepare('UPDATE notifications SET read=1 WHERE id=? AND user_id=?').run(id, userId);
  }
}

function markCaseNotificationsRead(caseId, userId, role) {
  if (role === 'center') {
    getDb().prepare("UPDATE notifications SET read=1 WHERE case_id=? AND (target_role='center' OR user_id=?)").run(caseId, userId);
  } else {
    getDb().prepare('UPDATE notifications SET read=1 WHERE case_id=? AND user_id=?').run(caseId, userId);
  }
}

module.exports = {
  getDb, authenticate, getUser, listUsers, createUser, updateUser, deleteUser,
  getPasskeysByUser, savePasskey, getPasskeyByCred, updatePasskeyCounter,
  listProducts, getProduct, getProductByCode, createProduct, updateProduct, upsertProductCSV,
  createCase, getCase, listCases, processLending, processReturn,
  listTransactions, processInventoryCheck, listInventoryChecks,
  getUnreadCount, listNotifications, markNotificationRead, markCaseNotificationsRead
};
