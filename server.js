const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json({ limit: '15mb' }));
app.use(express.static('.'));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const SECRET = process.env.JWT_SECRET || 'almaqam_secret_2024';

// Init DB
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      full_name TEXT NOT NULL, role TEXT NOT NULL, email TEXT, phone TEXT,
      active INTEGER DEFAULT 1, last_login TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS employees (
      id SERIAL PRIMARY KEY, full_name TEXT NOT NULL, position TEXT, phone TEXT, email TEXT,
      active INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS cases (
      id SERIAL PRIMARY KEY, case_number TEXT NOT NULL, client_name TEXT NOT NULL,
      client_phone TEXT, opponent_name TEXT, case_type TEXT, court TEXT, chamber TEXT,
      court_number TEXT, police_number TEXT, room TEXT, decision TEXT,
      session_date TEXT, postpone_date TEXT,
      assigned_to INTEGER, priority TEXT DEFAULT 'عادي', status TEXT DEFAULT 'نشطة',
      notes TEXT, created_by INTEGER, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS procedures (
      id SERIAL PRIMARY KEY, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
      action_required TEXT NOT NULL, assigned_to INTEGER, session_date TEXT, session_time TEXT,
      status TEXT DEFAULT 'قيد التنفيذ', priority TEXT DEFAULT 'عادي', notes TEXT,
      created_by INTEGER, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS procedure_logs (
      id SERIAL PRIMARY KEY, procedure_id INTEGER REFERENCES procedures(id) ON DELETE CASCADE,
      updated_by INTEGER, old_status TEXT, new_status TEXT, done_text TEXT,
      postpone_reason TEXT, new_date TEXT, note TEXT, created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wa_log (
      id SERIAL PRIMARY KEY, case_num TEXT, client TEXT, type TEXT,
      sent_by TEXT, sent_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT, label TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY, user_id INTEGER, user_name TEXT, action TEXT,
      entity_type TEXT, entity_id INTEGER, entity_label TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Seed admin
  const admin = await pool.query('SELECT id FROM users WHERE username=$1', ['admin']);
  if (admin.rows.length === 0) {
    const hash = bcrypt.hashSync('Admin@1234', 10);
    await pool.query('INSERT INTO users (username,password,full_name,role,email) VALUES ($1,$2,$3,$4,$5)',
      ['admin', hash, 'طارق الشطي', 'admin', 'tareq@almaqamlawfirm.com']);
  }
  // Seed settings
  const s = await pool.query('SELECT COUNT(*) FROM settings');
  if (parseInt(s.rows[0].count) === 0) {
    await pool.query(`INSERT INTO settings VALUES 
      ('office_name','مكتب المقام للمحاماة','اسم المكتب'),
      ('office_phone','+965 25359316','هاتف المكتب'),
      ('office_email','info@almaqamlawfirm.com','البريد الإلكتروني'),
      ('office_address','الكويت','العنوان'),
      ('wa_office_name','مكتب المقام للمحاماة','اسم المكتب في واتساب')`);
  }
  // Seed employees table from existing users (one-time, keeps same IDs so
  // existing cases/procedures assigned_to values keep pointing to the right person)
  const empCount = await pool.query('SELECT COUNT(*) FROM employees');
  if (parseInt(empCount.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO employees (id, full_name, phone, email)
      SELECT id, full_name, phone, email FROM users
      ON CONFLICT (id) DO NOTHING
    `);
    await pool.query(`SELECT setval('employees_id_seq', COALESCE((SELECT MAX(id) FROM employees), 1))`);
  }
  // Add new columns if not exist (migration)
  const migrations = [
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS court_number TEXT",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS police_number TEXT", 
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS room TEXT",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS decision TEXT",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS session_date TEXT",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS postpone_date TEXT",
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS position TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active TIMESTAMP",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS prosecution_number TEXT",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS client_capacity TEXT",
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS court_degree TEXT",
  ];
  for(const sql of migrations){
    try{ await pool.query(sql); }catch(e){}
  }
  console.log('DB ready');
}

// Auth middleware
function auth(req, res, next) {
  const t = req.headers.authorization?.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'غير مصرح' });
  try {
    req.user = jwt.verify(t, SECRET);
    pool.query('UPDATE users SET last_active=NOW() WHERE id=$1', [req.user.id]).catch(()=>{});
    next();
  }
  catch { res.status(401).json({ error: 'انتهت الجلسة، يرجى تسجيل الدخول مجدداً' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'للمدير فقط' });
  next();
}

async function logAudit(user, action, entityType, entityId, entityLabel) {
  try {
    await pool.query(
      'INSERT INTO audit_log (user_id,user_name,action,entity_type,entity_id,entity_label) VALUES ($1,$2,$3,$4,$5,$6)',
      [user.id, user.full_name, action, entityType, entityId, entityLabel]
    );
  } catch (e) { /* never let logging break the actual request */ }
}

// AUTH
app.get('/api/auth/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id,username,full_name,role,email FROM users WHERE id=$1 AND active=1', [req.user.id]);
  if(!r.rows[0]) return res.status(401).json({error:'غير موجود'});
  res.json(r.rows[0]);
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE username=$1 AND active=1', [username]);
  const u = r.rows[0];
  if (!u || !bcrypt.compareSync(password, u.password)) return res.status(401).json({ error: 'بيانات خاطئة' });
  await pool.query('UPDATE users SET last_login=NOW() WHERE id=$1', [u.id]);
  const token = jwt.sign({ id: u.id, username: u.username, full_name: u.full_name, role: u.role }, SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: u.id, username: u.username, full_name: u.full_name, role: u.role, email: u.email } });
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  const { old_password, new_password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!bcrypt.compareSync(old_password, r.rows[0].password)) return res.status(400).json({ error: 'كلمة المرور القديمة خاطئة' });
  await pool.query('UPDATE users SET password=$1 WHERE id=$2', [bcrypt.hashSync(new_password, 10), req.user.id]);
  res.json({ message: 'تم تغيير كلمة المرور' });
});

// USERS
app.get('/api/users', auth, async (req, res) => {
  const r = await pool.query('SELECT id,username,full_name,role,email,phone,active,last_login FROM users ORDER BY full_name');
  res.json(r.rows);
});
app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { username, password, full_name, role, email, phone } = req.body;
  const exists = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
  if (exists.rows.length > 0) return res.status(400).json({ error: 'اسم المستخدم موجود' });
  const r = await pool.query('INSERT INTO users (username,password,full_name,role,email,phone) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
    [username, bcrypt.hashSync(password, 10), full_name, role, email || null, phone || null]);
  await logAudit(req.user, 'إنشاء', 'مستخدم', r.rows[0].id, full_name);
  res.status(201).json({ id: r.rows[0].id });
});
app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const { full_name, role, email, phone, active } = req.body;
  await pool.query('UPDATE users SET full_name=$1,role=$2,email=$3,phone=$4,active=$5 WHERE id=$6',
    [full_name, role, email, phone, active ?? 1, req.params.id]);
  await logAudit(req.user, 'تعديل', 'مستخدم', req.params.id, full_name);
  res.json({ message: 'تم التحديث' });
});
app.put('/api/users/:id/reset-password', auth, adminOnly, async (req, res) => {
  await pool.query('UPDATE users SET password=$1 WHERE id=$2', [bcrypt.hashSync(req.body.new_password, 10), req.params.id]);
  const un = await pool.query('SELECT full_name FROM users WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'إعادة تعيين كلمة مرور', 'مستخدم', req.params.id, un.rows[0]?.full_name);
  res.json({ message: 'تم إعادة تعيين كلمة المرور' });
});
app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  await pool.query('UPDATE users SET active=0 WHERE id=$1', [req.params.id]);
  const un = await pool.query('SELECT full_name FROM users WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'تعطيل', 'مستخدم', req.params.id, un.rows[0]?.full_name);
  res.json({ message: 'تم تعطيل المستخدم' });
});

// EMPLOYEES (task-assignment roster, separate from login accounts)
app.get('/api/employees', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM employees WHERE active=1 ORDER BY full_name');
  res.json(r.rows);
});
app.post('/api/employees', auth, adminOnly, async (req, res) => {
  const { full_name, position, phone, email } = req.body;
  if (!full_name) return res.status(400).json({ error: 'الاسم مطلوب' });
  const r = await pool.query('INSERT INTO employees (full_name,position,phone,email) VALUES ($1,$2,$3,$4) RETURNING id',
    [full_name, position || null, phone || null, email || null]);
  await logAudit(req.user, 'إنشاء', 'موظف', r.rows[0].id, full_name);
  res.status(201).json({ id: r.rows[0].id });
});
app.put('/api/employees/:id', auth, adminOnly, async (req, res) => {
  const { full_name, position, phone, email, active } = req.body;
  await pool.query('UPDATE employees SET full_name=$1,position=$2,phone=$3,email=$4,active=$5 WHERE id=$6',
    [full_name, position || null, phone || null, email || null, active ?? 1, req.params.id]);
  await logAudit(req.user, 'تعديل', 'موظف', req.params.id, full_name);
  res.json({ message: 'تم التحديث' });
});
app.delete('/api/employees/:id', auth, adminOnly, async (req, res) => {
  const en = await pool.query('SELECT full_name FROM employees WHERE id=$1', [req.params.id]);
  await pool.query('UPDATE employees SET active=0 WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'تعطيل', 'موظف', req.params.id, en.rows[0]?.full_name);
  res.json({ message: 'تم تعطيل الموظف' });
});

// CASES
app.get('/api/cases', auth, async (req, res) => {
  const { search, status, assigned_to } = req.query;
  let q = 'SELECT c.*, e.full_name as assigned_name FROM cases c LEFT JOIN employees e ON c.assigned_to=e.id WHERE 1=1';
  const params = [];
  if (req.user.role !== 'admin') { params.push(req.user.id); q += ` AND c.assigned_to=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (c.case_number ILIKE $${params.length} OR c.client_name ILIKE $${params.length} OR c.opponent_name ILIKE $${params.length})`; }
  if (status) { params.push(status); q += ` AND c.status=$${params.length}`; }
  if (assigned_to) { params.push(assigned_to); q += ` AND c.assigned_to=$${params.length}`; }
  q += ' ORDER BY c.updated_at DESC';
  const r = await pool.query(q, params);
  res.json(r.rows);
});
app.post('/api/cases', auth, async (req, res) => {
  const { case_number, client_name, client_phone, opponent_name, case_type, court, chamber, court_number, police_number, prosecution_number, client_capacity, court_degree, room, decision, session_date, postpone_date, assigned_to, priority, notes } = req.body;
  const r = await pool.query(
    'INSERT INTO cases (case_number,client_name,client_phone,opponent_name,case_type,court,chamber,court_number,police_number,prosecution_number,client_capacity,court_degree,room,decision,session_date,postpone_date,assigned_to,priority,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) RETURNING id',
    [case_number, client_name, client_phone, opponent_name, case_type, court, chamber, court_number||null, police_number||null, prosecution_number||null, client_capacity||null, court_degree||null, room||null, decision||null, session_date||null, postpone_date||null, assigned_to || null, priority || 'عادي', notes, req.user.id]);
  await logAudit(req.user, 'إنشاء', 'قضية', r.rows[0].id, case_number);
  res.status(201).json({ id: r.rows[0].id });
});
app.put('/api/cases/:id', auth, async (req, res) => {
  const { client_name, client_phone, opponent_name, case_type, court, chamber, court_number, police_number, prosecution_number, client_capacity, court_degree, room, decision, session_date, postpone_date, assigned_to, priority, status, notes } = req.body;
  await pool.query('UPDATE cases SET client_name=$1,client_phone=$2,opponent_name=$3,case_type=$4,court=$5,chamber=$6,court_number=$7,police_number=$8,prosecution_number=$9,client_capacity=$10,court_degree=$11,room=$12,decision=$13,session_date=$14,postpone_date=$15,assigned_to=$16,priority=$17,status=$18,notes=$19,updated_at=NOW() WHERE id=$20',
    [client_name, client_phone, opponent_name, case_type, court, chamber, court_number||null, police_number||null, prosecution_number||null, client_capacity||null, court_degree||null, room||null, decision||null, session_date||null, postpone_date||null, assigned_to, priority, status, notes, req.params.id]);
  const cn = await pool.query('SELECT case_number FROM cases WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'تعديل', 'قضية', req.params.id, cn.rows[0]?.case_number);
  res.json({ message: 'تم التحديث' });
});
app.delete('/api/cases/:id', auth, adminOnly, async (req, res) => {
  const cn = await pool.query('SELECT case_number FROM cases WHERE id=$1', [req.params.id]);
  await pool.query('DELETE FROM cases WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'حذف', 'قضية', req.params.id, cn.rows[0]?.case_number);
  res.json({ message: 'تم الحذف' });
});

// PROCEDURES
app.get('/api/procedures', auth, async (req, res) => {
  const { status, case_id, search } = req.query;
  let q = `SELECT p.*, c.case_number, c.client_name, c.client_phone, c.opponent_name, c.court, c.chamber,
    e.full_name as assigned_name FROM procedures p LEFT JOIN cases c ON p.case_id=c.id LEFT JOIN employees e ON p.assigned_to=e.id WHERE 1=1`;
  const params = [];
  if (req.user.role !== 'admin') { params.push(req.user.id); q += ` AND p.assigned_to=$${params.length}`; }
  if (case_id) { params.push(case_id); q += ` AND p.case_id=$${params.length}`; }
  if (status) { params.push(status); q += ` AND p.status=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (c.case_number ILIKE $${params.length} OR c.client_name ILIKE $${params.length} OR p.action_required ILIKE $${params.length})`; }
  q += ' ORDER BY p.session_date ASC';
  const r = await pool.query(q, params);
  res.json(r.rows);
});
app.get('/api/procedures/today', auth, async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  let q = `SELECT p.*, c.case_number, c.client_name, c.client_phone, c.opponent_name, c.court, c.chamber,
    e.full_name as assigned_name FROM procedures p LEFT JOIN cases c ON p.case_id=c.id LEFT JOIN employees e ON p.assigned_to=e.id WHERE p.session_date=$1`;
  const params = [today];
  if (req.user.role !== 'admin') { params.push(req.user.id); q += ` AND p.assigned_to=$${params.length}`; }
  q += ' ORDER BY p.session_time ASC';
  const r = await pool.query(q, params);
  res.json(r.rows);
});
app.get('/api/procedures/:id', auth, async (req, res) => {
  const r = await pool.query(`SELECT p.*, c.case_number, c.client_name, c.client_phone, c.opponent_name, c.court, c.chamber,
    e.full_name as assigned_name FROM procedures p LEFT JOIN cases c ON p.case_id=c.id LEFT JOIN employees e ON p.assigned_to=e.id WHERE p.id=$1`, [req.params.id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'غير موجود' });
  const logs = await pool.query('SELECT l.*, u.full_name as updated_by_name FROM procedure_logs l LEFT JOIN users u ON l.updated_by=u.id WHERE l.procedure_id=$1 ORDER BY l.created_at DESC', [req.params.id]);
  res.json({ ...r.rows[0], logs: logs.rows });
});
app.post('/api/procedures', auth, async (req, res) => {
  const { case_id, action_required, assigned_to, session_date, session_time, priority, notes } = req.body;
  const r = await pool.query('INSERT INTO procedures (case_id,action_required,assigned_to,session_date,session_time,priority,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
    [case_id, action_required, assigned_to || null, session_date, session_time, priority || 'عادي', notes, req.user.id]);
  await pool.query('UPDATE cases SET updated_at=NOW() WHERE id=$1', [case_id]);
  await logAudit(req.user, 'إنشاء', 'إجراء', r.rows[0].id, action_required);
  res.status(201).json({ id: r.rows[0].id });
});
app.put('/api/procedures/:id/update-status', auth, async (req, res) => {
  const { new_status, done_text, postpone_reason, new_date, note, assigned_to } = req.body;
  const old = await pool.query('SELECT status FROM procedures WHERE id=$1', [req.params.id]);
  await pool.query('UPDATE procedures SET status=$1,updated_at=NOW() WHERE id=$2', [new_status, req.params.id]);
  if (new_status === 'مؤجل' && new_date) await pool.query('UPDATE procedures SET session_date=$1 WHERE id=$2', [new_date, req.params.id]);
  if (assigned_to !== undefined) await pool.query('UPDATE procedures SET assigned_to=$1 WHERE id=$2', [assigned_to || null, req.params.id]);
  await pool.query('INSERT INTO procedure_logs (procedure_id,updated_by,old_status,new_status,done_text,postpone_reason,new_date,note) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [req.params.id, req.user.id, old.rows[0].status, new_status, done_text, postpone_reason, new_date, note]);
  const pr = await pool.query('SELECT action_required FROM procedures WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'تحديث حالة', 'إجراء', req.params.id, pr.rows[0]?.action_required);
  res.json({ message: 'تم التحديث' });
});
app.delete('/api/procedures/:id', auth, adminOnly, async (req, res) => {
  const pr = await pool.query('SELECT action_required FROM procedures WHERE id=$1', [req.params.id]);
  await pool.query('DELETE FROM procedures WHERE id=$1', [req.params.id]);
  await logAudit(req.user, 'حذف', 'إجراء', req.params.id, pr.rows[0]?.action_required);
  res.json({ message: 'تم الحذف' });
});

// STATS
app.get('/api/stats', auth, async (req, res) => {
  const uid = req.user.id;
  const isAdmin = req.user.role === 'admin';
  const today = new Date().toISOString().split('T')[0];
  const base = isAdmin ? '' : ` WHERE assigned_to=${uid}`;
  const pbase = isAdmin ? '' : ` AND assigned_to=${uid}`;
  const [tc, ts, pd, pp, po] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM cases${base}`),
    pool.query(`SELECT COUNT(*) FROM procedures WHERE session_date='${today}'${pbase}`),
    pool.query(`SELECT COUNT(*) FROM procedures WHERE status='منجز'${pbase}`),
    pool.query(`SELECT COUNT(*) FROM procedures WHERE status='قيد التنفيذ'${pbase}`),
    pool.query(`SELECT COUNT(*) FROM procedures WHERE status='مؤجل'${pbase}`),
  ]);
  res.json({ total_cases: parseInt(tc.rows[0].count), today_sessions: parseInt(ts.rows[0].count), done: parseInt(pd.rows[0].count), pending: parseInt(pp.rows[0].count), postponed: parseInt(po.rows[0].count) });
});

// SETTINGS
app.get('/api/settings', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM settings');
  const obj = {};
  r.rows.forEach(row => obj[row.key] = { value: row.value, label: row.label });
  res.json(obj);
});
app.put('/api/settings', auth, adminOnly, async (req, res) => {
  for (const [key, value] of Object.entries(req.body)) {
    await pool.query('UPDATE settings SET value=$1 WHERE key=$2', [value, key]);
  }
  res.json({ message: 'تم الحفظ' });
});

// AUDIT LOG
app.get('/api/audit-log', auth, adminOnly, async (req, res) => {
  const r = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 300');
  res.json(r.rows);
});

// BACKUP
app.get('/api/backup', auth, adminOnly, async (req, res) => {
  try {
    const [usersR, employeesR, casesR, proceduresR, logsR, waR, settingsR, auditR] = await Promise.all([
      pool.query('SELECT * FROM users'),
      pool.query('SELECT * FROM employees'),
      pool.query('SELECT * FROM cases'),
      pool.query('SELECT * FROM procedures'),
      pool.query('SELECT * FROM procedure_logs'),
      pool.query('SELECT * FROM wa_log'),
      pool.query('SELECT * FROM settings'),
      pool.query('SELECT * FROM audit_log'),
    ]);
    const backup = {
      generated_at: new Date().toISOString(),
      users: usersR.rows,
      employees: employeesR.rows,
      cases: casesR.rows,
      procedures: proceduresR.rows,
      procedure_logs: logsR.rows,
      wa_log: waR.rows,
      settings: settingsR.rows,
      audit_log: auditR.rows,
    };
    const filename = `almaqam-backup-${new Date().toISOString().slice(0,10)}.json`;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(JSON.stringify(backup, null, 2));
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// RESTORE (destructive: replaces all current data with the uploaded backup)
app.post('/api/restore', auth, adminOnly, async (req, res) => {
  const b = req.body;
  if (!b || !Array.isArray(b.users) || !Array.isArray(b.cases)) {
    return res.status(400).json({ error: 'ملف النسخة الاحتياطية غير صالح' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // delete children first
    await client.query('DELETE FROM procedure_logs');
    await client.query('DELETE FROM procedures');
    await client.query('DELETE FROM wa_log');
    await client.query('DELETE FROM cases');
    await client.query('DELETE FROM employees');
    await client.query('DELETE FROM users');
    await client.query('DELETE FROM settings');
    await client.query('DELETE FROM audit_log');

    for (const u of b.users) {
      await client.query(
        'INSERT INTO users (id,username,password,full_name,role,email,phone,active,last_login,last_active) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
        [u.id, u.username, u.password, u.full_name, u.role, u.email, u.phone, u.active, u.last_login, u.last_active]);
    }
    for (const e of (b.employees||[])) {
      await client.query(
        'INSERT INTO employees (id,full_name,position,phone,email,active,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [e.id, e.full_name, e.position, e.phone, e.email, e.active, e.created_at]);
    }
    for (const s of (b.settings||[])) {
      await client.query('INSERT INTO settings (key,value,label) VALUES ($1,$2,$3)', [s.key, s.value, s.label]);
    }
    for (const c of b.cases) {
      await client.query(
        `INSERT INTO cases (id,case_number,client_name,client_phone,opponent_name,case_type,court,chamber,court_number,police_number,prosecution_number,client_capacity,court_degree,room,decision,session_date,postpone_date,assigned_to,priority,status,notes,created_by,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
        [c.id,c.case_number,c.client_name,c.client_phone,c.opponent_name,c.case_type,c.court,c.chamber,c.court_number,c.police_number,c.prosecution_number,c.client_capacity,c.court_degree,c.room,c.decision,c.session_date,c.postpone_date,c.assigned_to,c.priority,c.status,c.notes,c.created_by,c.created_at,c.updated_at]);
    }
    for (const p of (b.procedures||[])) {
      await client.query(
        `INSERT INTO procedures (id,case_id,action_required,assigned_to,session_date,session_time,status,priority,notes,created_by,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [p.id,p.case_id,p.action_required,p.assigned_to,p.session_date,p.session_time,p.status,p.priority,p.notes,p.created_by,p.created_at,p.updated_at]);
    }
    for (const l of (b.procedure_logs||[])) {
      await client.query(
        `INSERT INTO procedure_logs (id,procedure_id,updated_by,old_status,new_status,done_text,postpone_reason,new_date,note,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [l.id,l.procedure_id,l.updated_by,l.old_status,l.new_status,l.done_text,l.postpone_reason,l.new_date,l.note,l.created_at]);
    }
    for (const w of (b.wa_log||[])) {
      await client.query('INSERT INTO wa_log (id,case_num,client,type,sent_by,sent_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [w.id,w.case_num,w.client,w.type,w.sent_by,w.sent_at]);
    }
    for (const a of (b.audit_log||[])) {
      await client.query('INSERT INTO audit_log (id,user_id,user_name,action,entity_type,entity_id,entity_label,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [a.id,a.user_id,a.user_name,a.action,a.entity_type,a.entity_id,a.entity_label,a.created_at]);
    }

    // realign auto-increment sequences so future inserts don't collide with restored IDs
    const seqFixes = [
      ['users','users_id_seq'], ['employees','employees_id_seq'], ['cases','cases_id_seq'],
      ['procedures','procedures_id_seq'], ['procedure_logs','procedure_logs_id_seq'], ['wa_log','wa_log_id_seq'],
      ['audit_log','audit_log_id_seq']
    ];
    for (const [table, seq] of seqFixes) {
      await client.query(`SELECT setval('${seq}', COALESCE((SELECT MAX(id) FROM ${table}), 1))`);
    }

    await client.query('COMMIT');
    res.json({ message: 'تمت الاستعادة بنجاح' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'فشلت الاستعادة: ' + err.message });
  } finally {
    client.release();
  }
});

// WA LOG
app.post('/api/wa-log', auth, async (req, res) => {
  const { case_num, client, type } = req.body;
  await pool.query('INSERT INTO wa_log (case_num,client,type,sent_by) VALUES ($1,$2,$3,$4)', [case_num, client, type, req.user.full_name]);
  res.json({ message: 'تم' });
});
app.get('/api/wa-log', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM wa_log ORDER BY sent_at DESC LIMIT 50');
  res.json(r.rows);
});

// Schedule route
app.get('/api/schedule/:week', async (req, res) => {
  try {
    const { week } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    if(!token) return res.status(401).json({error:'غير مصرح'});
    const jwt = require('jsonwebtoken');
    const SECRET = process.env.JWT_SECRET || 'almaqam_secret_2024';
    jwt.verify(token, SECRET);
    
    const [yr, wk] = week.split('-W').map(Number);
    const simple = new Date(yr, 0, 1 + (wk - 1) * 7);
    const dow = simple.getDay();
    const weekStart = new Date(simple);
    if (dow <= 4) weekStart.setDate(simple.getDate() - simple.getDay() + 1);
    else weekStart.setDate(simple.getDate() + 8 - simple.getDay());
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6);
    const startStr = weekStart.toISOString().split('T')[0];
    const endStr = weekEnd.toISOString().split('T')[0];

    const result = await pool.query(`
      SELECT c.*, e.full_name as assigned_name,
        (SELECT p2.session_date FROM procedures p2 WHERE p2.case_id=c.id 
         AND p2.session_date < $1 ORDER BY p2.session_date DESC LIMIT 1) as prev_session
      FROM cases c LEFT JOIN employees e ON c.assigned_to = e.id
      WHERE (c.session_date BETWEEN $1 AND $2) OR (c.postpone_date BETWEEN $1 AND $2)
      ORDER BY COALESCE(c.session_date, c.postpone_date) ASC
    `, [startStr, endStr]);

    res.json({ start: startStr, end: endStr, cases: result.rows });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// PWA files
app.get('/manifest.json', (req, res) => res.sendFile(path.join(__dirname, 'manifest.json')));
app.get('/sw.js', (req, res) => { res.setHeader('Content-Type','application/javascript'); res.sendFile(path.join(__dirname, 'sw.js')); });
app.get('/icon-192.png', (req, res) => res.sendFile(path.join(__dirname, 'icon-192.png')));
app.get('/icon-512.png', (req, res) => res.sendFile(path.join(__dirname, 'icon-512.png')));

// Serve frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'almaqam.html')));

const PORT = process.env.PORT || 3000;
initDB().then(() => app.listen(PORT, () => console.log(`Running on ${PORT}`)));
