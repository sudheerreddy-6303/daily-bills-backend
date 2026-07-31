const express   = require('express');
const cors      = require('cors');
const mysql     = require('mysql2/promise');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
require('dotenv').config();

const app = express();

// ── Security ────────────────────────────────────────────────────
// Disable helmet policies that block Render/cross-origin requests
app.use(helmet({ crossOriginResourcePolicy: false, crossOriginOpenerPolicy: false }));

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(o => o.trim());
app.use(cors({
  origin: (origin, cb) => {
    // Allow no-origin requests (health checks, curl, Render internal)
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true,
}));
// Handle preflight for all routes
app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({ windowMs: 15*60*1000, max: 300 });
app.use('/api/', limiter);

const writeLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });

// ── JWT Auth Middleware ─────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dailybills-secret';

const requireAuth = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ success: false, message: 'Unauthorized.' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Token expired or invalid.' });
  }
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin')
      return res.status(403).json({ success: false, message: 'Admin only.' });
    next();
  });
};

// ── DB Pool ─────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'dailybills',
  port:     parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: false },
  dateStrings: true,
});

// ── DB Init ─────────────────────────────────────────────────────
async function initDB() {
  const conn = await pool.getConnection();
  try {
    // Users table
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        username    VARCHAR(50)  NOT NULL UNIQUE,
        password    VARCHAR(255) NOT NULL,
        display     VARCHAR(100) NOT NULL,
        role        ENUM('admin','user') NOT NULL DEFAULT 'user',
        site        VARCHAR(100),
        active      TINYINT(1) DEFAULT 1,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Bills table
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS bills (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        voucher_no    VARCHAR(30)  NOT NULL UNIQUE,
        date          DATE         NOT NULL,
        description   TEXT         NOT NULL,
        purpose_site  VARCHAR(255),
        category      VARCHAR(100),
        sub_category  VARCHAR(100),
        vendor        VARCHAR(255),
        paid_by       VARCHAR(100),
        payment_mode  VARCHAR(80) DEFAULT 'Cash',
        amount        DECIMAL(12,2) NOT NULL DEFAULT 0,
        gst_tax       VARCHAR(50),
        bill_attached ENUM('Yes','No') DEFAULT 'No',
        approved_by   VARCHAR(100),
        notes         TEXT,
        created_by    INT,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Seed default users — INSERT IGNORE means existing users are skipped safely
    const seedUser = async (username, password, display, role, site) => {
      const [existing] = await conn.execute('SELECT id FROM users WHERE username=?', [username]);
      if (existing.length === 0) {
        const hash = await bcrypt.hash(password, 10);
        await conn.execute(
          'INSERT INTO users (username, password, display, role, site) VALUES (?,?,?,?,?)',
          [username, hash, display, role, site || null]
        );
        console.log(`Seeded user: ${username}`);
      }
    };
    await seedUser('admin',  'admin@123', 'Administrator', 'admin', null);
    await seedUser('ramya',  'user@123',  'Ramya',         'user',  'Experience Center 1');
    await seedUser('ramya',  'user@123',  'Ramya',         'user',  'Experience Center 1');
    await seedUser('teja',   'user@123',  'Teja',          'user',  'EC2');

    // Voucher counter table
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS voucher_counter (
        id      INT PRIMARY KEY DEFAULT 1,
        counter INT NOT NULL DEFAULT 0
      )
    `);
    const [vc] = await conn.execute('SELECT COUNT(*) as c FROM voucher_counter');
    if (vc[0].c === 0) {
      await conn.execute('INSERT INTO voucher_counter VALUES (1, 0)');
    }

    // Add attachment columns if not exist (migration)
    const ac = async (col, def) => {
      try { await conn.execute(`ALTER TABLE bills ADD COLUMN ${col} ${def}`); } catch {}
    };
    await ac('attachment_name', 'VARCHAR(500)');
    await ac('attachment_data', 'LONGTEXT');
    await ac('attachment_type', 'VARCHAR(100)');
    await ac('submitted_by',    'VARCHAR(100)');

    // Custom dropdown options table
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS dropdown_options (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        field_name VARCHAR(50) NOT NULL,
        value      VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_field_value (field_name, value)
      )
    `);

    // ── Migrate payment_mode from ENUM to VARCHAR if needed ──────────
    try {
      await conn.execute("ALTER TABLE bills MODIFY COLUMN payment_mode VARCHAR(80) DEFAULT 'Cash'");
    } catch(e) { /* already VARCHAR or doesn't exist yet */ }

    // ── RESET & re-seed category + sub_category (removes old ones) ──
    await conn.execute("DELETE FROM dropdown_options WHERE field_name IN ('category','sub_category')");

    // ── Seed dropdown options ─────────────────────────────────────
    const SEED_OPTS = [
      // ── Categories (11 only) ──────────────────────────────────
      ...['Plywood','Laminates','Transport','Salary','IT Bills','Petty Cash',
          'Current Bills','Rent','Stationary','Food','Maintanance']
        .map(v => ['category', v]),

      // ── Sub-categories (mapped to their parent category) ──────
      // Plywood
      ...['16mm Plywood','9mm Plywood','12mm Plywood','18mm Plywood',
          '19mm Plywood 8/4','19mm Plywood 7/4',
          '16mm HDHMR','18mm HDHMR','12mm HDHMR','9mm HDHMR']
        .map(v => ['sub_category', v]),
      // Laminates
      ...['0.8mm Laminate Linear','1mm Colour Laminates','1.25mm Acrylic Sheets']
        .map(v => ['sub_category', v]),
      // Transport
      ...['Material','Man Power']
        .map(v => ['sub_category', v]),
      // IT Bills
      ...['Internet Bills','Computers','Printers']
        .map(v => ['sub_category', v]),
      // Current Bills / Rent / Maintanance shared locations
      ...['Medhal','Suchitra','Nanakram Guda','Kompally']
        .map(v => ['sub_category', v]),
      // Stationary
      ...['Pens','Books','Batteries']
        .map(v => ['sub_category', v]),
      // Salary, Petty Cash, Food — no defaults (add-new only)

      // ── Other dropdowns (INSERT IGNORE — preserve user additions) ─
      ...['Medhal Office','Suchitra','Nanakram Guda','Kompally','Head Office']
        .map(v => ['purpose_site', v]),
      ...['Cash','UPI','Bank Transfer','Cheque','Credit Card','Other']
        .map(v => ['payment_mode', v]),
      ...['Ramya','Teja','Sundar','Bank Account','Petty Cash Box']
        .map(v => ['paid_by', v]),
      ...['Ramya','Sundar','Seshagiri Raju','Manager']
        .map(v => ['approved_by', v]),
      ...['Yes','No','5%','12%','18%','28%']
        .map(v => ['gst_tax', v]),
    ];

    for (const [field_name, value] of SEED_OPTS) {
      try {
        // Use INSERT IGNORE for non-category fields to preserve user-added items
        await conn.execute(
          'INSERT IGNORE INTO dropdown_options (field_name, value) VALUES (?,?)',
          [field_name, value]
        );
      } catch(e) { /* ignore */ }
    }

    // ── Collections table (payments received per project) ──────────
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS collections (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        project_name    VARCHAR(255) NOT NULL,
        total_booked    DECIMAL(14,2) NOT NULL DEFAULT 0,
        received_amount DECIMAL(14,2) NOT NULL DEFAULT 0,
        payment_method  VARCHAR(80) DEFAULT 'Cash',
        received_by     VARCHAR(100),
        notes           TEXT,
        created_by      INT,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    console.log('DB initialized successfully.');
  } finally { conn.release(); }
}

// ── Generate Voucher No ─────────────────────────────────────────
async function nextVoucher() {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute('UPDATE voucher_counter SET counter = counter + 1 WHERE id = 1');
    const [rows] = await conn.execute('SELECT counter FROM voucher_counter WHERE id = 1');
    await conn.commit();
    const n = rows[0].counter;
    return `VCH-${String(n).padStart(3, '0')}`;
  } catch(e) { await conn.rollback(); throw e; }
  finally { conn.release(); }
}

// ════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'Username and password required.' });
  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username=? AND active=1', [username.trim()]);
    if (!rows.length)
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const token = jwt.sign(
      { id: user.id, username: user.username, display: user.display, role: user.role, site: user.site },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ success: true, token, user: { id: user.id, username: user.username, display: user.display, role: user.role, site: user.site } });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 6)
    return res.status(400).json({ success: false, message: 'New password must be at least 6 characters.' });
  try {
    const [rows] = await pool.execute('SELECT password FROM users WHERE id=?', [req.user.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'User not found.' });
    const valid = await bcrypt.compare(currentPassword, rows[0].password);
    if (!valid) return res.status(400).json({ success: false, message: 'Current password is incorrect.' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.execute('UPDATE users SET password=? WHERE id=?', [hash, req.user.id]);
    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  USER MANAGEMENT (Admin only)
// ════════════════════════════════════════════════════════════════

// GET /api/users
app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id,username,display,role,site,active,created_at FROM users ORDER BY id');
    res.json({ success: true, data: rows });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// POST /api/users
app.post('/api/users', requireAdmin, writeLimiter, async (req, res) => {
  const { username, password, display, role, site } = req.body;
  if (!username || !password || !display)
    return res.status(400).json({ success: false, message: 'Username, password and display name are required.' });
  if (password.length < 4)
    return res.status(400).json({ success: false, message: 'Password must be at least 4 characters.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.execute(
      'INSERT INTO users (username, password, display, role, site) VALUES (?,?,?,?,?)',
      [username.trim().toLowerCase(), hash, display.trim(), role || 'user', site || null]
    );
    res.status(201).json({ success: true, message: `User "${display}" created.` });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ success: false, message: 'Username already exists.' });
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// PATCH /api/users/:id/toggle
app.patch('/api/users/:id/toggle', requireAdmin, async (req, res) => {
  try {
    await pool.execute('UPDATE users SET active = 1 - active WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// PUT /api/users/:id — update user details (admin only)
app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const { display, role, site, password } = req.body;
  if (!display || !display.trim())
    return res.status(400).json({ success: false, message: 'Display name is required.' });
  try {
    const [existing] = await pool.execute('SELECT role FROM users WHERE id=?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ success: false, message: 'User not found.' });
    // Prevent demoting last admin
    if (existing[0].role === 'admin' && role !== 'admin') {
      const [admins] = await pool.execute('SELECT COUNT(*) as c FROM users WHERE role="admin" AND active=1');
      if (admins[0].c <= 1) return res.status(400).json({ success: false, message: 'Cannot demote the last admin.' });
    }
    if (password && password.trim()) {
      if (password.length < 4) return res.status(400).json({ success: false, message: 'Password must be at least 4 characters.' });
      const hash = await bcrypt.hash(password, 10);
      await pool.execute(
        'UPDATE users SET display=?, role=?, site=?, password=? WHERE id=?',
        [display.trim(), role || 'user', site || null, hash, req.params.id]
      );
    } else {
      await pool.execute(
        'UPDATE users SET display=?, role=?, site=? WHERE id=?',
        [display.trim(), role || 'user', site || null, req.params.id]
      );
    }
    res.json({ success: true, message: 'User updated.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  try {
    await pool.execute('DELETE FROM users WHERE id=? AND role != "admin"', [req.params.id]);
    res.json({ success: true });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// ════════════════════════════════════════════════════════════════
//  BILLS ROUTES
// ════════════════════════════════════════════════════════════════

// GET /api/bills  — with filters
app.get('/api/bills', requireAuth, async (req, res) => {
  try {
    const { search, category, payment_mode, date_from, date_to, site, page = 1, limit = 50 } = req.query;
    let where = [];
    let params = [];

    if (search) {
      where.push('(b.description LIKE ? OR b.vendor LIKE ? OR b.voucher_no LIKE ? OR b.notes LIKE ?)');
      const s = `%${search}%`;
      params.push(s, s, s, s);
    }
    if (category)     { where.push('b.category = ?');      params.push(category); }
    if (payment_mode) { where.push('b.payment_mode = ?');  params.push(payment_mode); }
    if (date_from)    { where.push('b.date >= ?');         params.push(date_from); }
    if (date_to)      { where.push('b.date <= ?');         params.push(date_to); }
    if (site)         { where.push('b.purpose_site LIKE ?'); params.push(`%${site}%`); }

    const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const [rows] = await pool.execute(
      `SELECT b.id, b.voucher_no, b.date, b.description, b.purpose_site,
              b.category, b.sub_category, b.vendor, b.paid_by, b.payment_mode,
              b.amount, b.gst_tax, b.bill_attached, b.approved_by, b.notes,
              b.attachment_name, b.attachment_type, b.submitted_by, b.created_by, b.created_at,
              u.display as created_by_name
       FROM bills b
       LEFT JOIN users u ON u.id = b.created_by
       ${whereStr}
       ORDER BY b.date DESC, b.id DESC
       LIMIT ${parseInt(limit)} OFFSET ${offset}`,
      params
    );
    const [[{ total }]] = await pool.execute(
      `SELECT COUNT(*) as total FROM bills b ${whereStr}`, params
    );
    res.json({ success: true, data: rows, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error('GET /bills:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/bills/dashboard  — summary stats (admin: all; user: own)
app.get('/api/bills/dashboard', requireAuth, async (req, res) => {
  try {
    const { month, year, site, date_from, date_to, category, sub_category,
            paid_by, payment_mode, vendor, approved_by, created_by } = req.query;
    const now = new Date();

    // Build base WHERE clause
    let baseWhere = 'WHERE 1=1';
    let baseParams = [];

    // Date filtering: if date_from/date_to provided, use those; else use month/year
    if (date_from || date_to) {
      if (date_from) { baseWhere += ' AND date >= ?'; baseParams.push(date_from); }
      if (date_to)   { baseWhere += ' AND date <= ?'; baseParams.push(date_to); }
    } else {
      const m = parseInt(month) || (now.getMonth() + 1);
      const y = parseInt(year)  || now.getFullYear();
      baseWhere += ' AND MONTH(date)=? AND YEAR(date)=?';
      baseParams.push(m, y);
    }

    // Non-admins only see their own bills
    if (req.user.role !== 'admin') {
      baseWhere += ' AND created_by=?';
      baseParams.push(req.user.id);
    } else if (created_by) {
      baseWhere += ' AND created_by=?';
      baseParams.push(created_by);
    }

    if (site)         { baseWhere += ' AND purpose_site=?';  baseParams.push(site); }
    if (category)     { baseWhere += ' AND category=?';      baseParams.push(category); }
    if (sub_category) { baseWhere += ' AND sub_category=?';  baseParams.push(sub_category); }
    if (paid_by)      { baseWhere += ' AND paid_by=?';       baseParams.push(paid_by); }
    if (payment_mode) { baseWhere += ' AND payment_mode=?';  baseParams.push(payment_mode); }
    if (vendor)       { baseWhere += ' AND vendor LIKE ?';   baseParams.push(`%${vendor}%`); }
    if (approved_by)  { baseWhere += ' AND approved_by=?';   baseParams.push(approved_by); }

    const [[totals]] = await pool.query(`
      SELECT
        COUNT(*)                                                                   as total_count,
        COALESCE(SUM(amount), 0)                                                   as total_amount,
        COALESCE(SUM(CASE WHEN payment_mode='Cash'          THEN amount END), 0)   as cash_total,
        COALESCE(SUM(CASE WHEN payment_mode='UPI'           THEN amount END), 0)   as upi_total,
        COALESCE(SUM(CASE WHEN payment_mode='Bank Transfer' THEN amount END), 0)   as bank_total,
        COALESCE(SUM(CASE WHEN payment_mode='Cheque'        THEN amount END), 0)   as cheque_total
      FROM bills ${baseWhere}
    `, baseParams);

    const [byCategory] = await pool.query(`
      SELECT category, COALESCE(SUM(amount),0) as total, COUNT(*) as count
      FROM bills ${baseWhere}
      GROUP BY category ORDER BY total DESC
    `, baseParams);

    const [bySite] = await pool.query(`
      SELECT purpose_site, COALESCE(SUM(amount),0) as total, COUNT(*) as count
      FROM bills ${baseWhere}
      GROUP BY purpose_site ORDER BY total DESC LIMIT 10
    `, baseParams);

    const [byPaidBy] = await pool.query(`
      SELECT paid_by, COALESCE(SUM(amount),0) as total, COUNT(*) as count
      FROM bills ${baseWhere}
      GROUP BY paid_by ORDER BY total DESC LIMIT 8
    `, baseParams);

    const [daily] = await pool.query(`
      SELECT DATE_FORMAT(date,'%Y-%m-%d') as day_key,
             LPAD(DAY(MIN(date)),2,'0') as day,
             COALESCE(SUM(amount),0) as total
      FROM bills ${baseWhere}
      GROUP BY DATE_FORMAT(date,'%Y-%m-%d')
      ORDER BY day_key ASC
    `, baseParams);

    // Recent bills — explicitly exclude attachment_data (too large)
    let recentWhere = req.user.role !== 'admin' ? 'WHERE b.created_by=?' : 'WHERE 1=1';
    let recentParams = req.user.role !== 'admin' ? [req.user.id] : [];
    if (req.user.role === 'admin') {
      if (created_by)   { recentWhere += ' AND b.created_by=?';    recentParams.push(created_by); }
      if (site)         { recentWhere += ' AND b.purpose_site=?';  recentParams.push(site); }
      if (category)     { recentWhere += ' AND b.category=?';      recentParams.push(category); }
      if (sub_category) { recentWhere += ' AND b.sub_category=?';  recentParams.push(sub_category); }
      if (paid_by)      { recentWhere += ' AND b.paid_by=?';       recentParams.push(paid_by); }
      if (payment_mode) { recentWhere += ' AND b.payment_mode=?';  recentParams.push(payment_mode); }
      if (approved_by)  { recentWhere += ' AND b.approved_by=?';   recentParams.push(approved_by); }
      if (date_from)    { recentWhere += ' AND b.date >= ?';        recentParams.push(date_from); }
      if (date_to)      { recentWhere += ' AND b.date <= ?';        recentParams.push(date_to); }
      if (!date_from && !date_to) {
        const m = parseInt(month) || (now.getMonth() + 1);
        const y = parseInt(year)  || now.getFullYear();
        recentWhere += ' AND MONTH(b.date)=? AND YEAR(b.date)=?';
        recentParams.push(m, y);
      }
    }

    const [recent] = await pool.query(`
      SELECT b.id, b.voucher_no, b.date, b.description, b.purpose_site,
             b.category, b.vendor, b.paid_by, b.payment_mode, b.amount,
             b.bill_attached, b.attachment_name, b.attachment_type,
             u.display as created_by_name
      FROM bills b
      LEFT JOIN users u ON u.id = b.created_by
      ${recentWhere}
      ORDER BY b.created_at DESC LIMIT 8
    `, recentParams);

    // All sites for filter dropdown
    const [allSites] = await pool.execute(
      'SELECT DISTINCT purpose_site FROM bills WHERE purpose_site IS NOT NULL AND purpose_site != "" ORDER BY purpose_site'
    );
    const [allCategories] = await pool.execute(
      'SELECT DISTINCT category FROM bills WHERE category IS NOT NULL AND category != "" ORDER BY category'
    );
    const [allSubCategories] = await pool.execute(
      'SELECT DISTINCT sub_category FROM bills WHERE sub_category IS NOT NULL AND sub_category != "" ORDER BY sub_category'
    );
    const [allPaidBy] = await pool.execute(
      'SELECT DISTINCT paid_by FROM bills WHERE paid_by IS NOT NULL AND paid_by != "" ORDER BY paid_by'
    );
    const [allApprovedBy] = await pool.execute(
      'SELECT DISTINCT approved_by FROM bills WHERE approved_by IS NOT NULL AND approved_by != "" ORDER BY approved_by'
    );
    const [allUsers] = await pool.execute(
      'SELECT id, display FROM users WHERE active=1 ORDER BY display'
    );
    const paymentModes = ['Cash','UPI','Bank Transfer','Cheque','Other'];

    // Monthly trend (last 6 months)
    let trendWhere = req.user.role !== 'admin' ? 'WHERE created_by=?' : '';
    let trendParams = req.user.role !== 'admin' ? [req.user.id] : [];
    const [monthly] = await pool.query(`
      SELECT YEAR(date) as yr,
             MONTH(date) as mo,
             DATE_FORMAT(MIN(date),'%b %Y') as month_label,
             COALESCE(SUM(amount),0) as total
      FROM bills ${trendWhere}
      GROUP BY YEAR(date), MONTH(date)
      ORDER BY yr DESC, mo DESC
      LIMIT 6
    `, trendParams);

    const m = parseInt(month) || (now.getMonth() + 1);
    const y = parseInt(year)  || now.getFullYear();

    res.json({
      success: true,
      data: {
        totals, byCategory, bySite, byPaidBy, daily, recent,
        monthly: monthly.reverse(),
        allSites:       allSites.map(s => s.purpose_site),
        allCategories:  allCategories.map(s => s.category),
        allSubCategories: allSubCategories.map(s => s.sub_category),
        allPaidBy:      allPaidBy.map(s => s.paid_by),
        allApprovedBy:  allApprovedBy.map(s => s.approved_by),
        allUsers:       allUsers,
        paymentModes,
        currentMonth: m,
        currentYear: y,
      }
    });
  } catch (err) {
    console.error('Dashboard error:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/bills/:id
app.get('/api/bills/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT b.*, u.display as created_by_name FROM bills b LEFT JOIN users u ON u.id=b.created_by WHERE b.id=?',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Bill not found.' });
    res.json({ success: true, data: rows[0] });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// POST /api/bills
app.post('/api/bills', requireAuth, writeLimiter, async (req, res) => {
  const b = req.body;
  if (!b.date || !b.description || b.amount === undefined)
    return res.status(400).json({ success: false, message: 'Date, description and amount are required.' });
  try {
    const voucher = await nextVoucher();
    const [r] = await pool.execute(
      `INSERT INTO bills
       (voucher_no,date,description,purpose_site,category,sub_category,vendor,
        paid_by,payment_mode,amount,gst_tax,bill_attached,approved_by,notes,
        attachment_name,attachment_data,attachment_type,submitted_by,created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        voucher,
        b.date,
        b.description.trim(),
        b.purpose_site || '',
        b.category     || '',
        b.sub_category || '',
        b.vendor       || '',
        b.paid_by      || '',
        b.payment_mode || 'Cash',
        parseFloat(b.amount) || 0,
        b.gst_tax      || '',
        b.bill_attached || 'No',
        b.approved_by  || '',
        b.notes        || '',
        b.attachment_name || null,
        b.attachment_data || null,
        b.attachment_type || null,
        req.user.display || '',
        req.user.id,
      ]
    );
    res.status(201).json({ success: true, id: r.insertId, voucher_no: voucher, message: 'Bill saved.' });
  } catch (err) {
    console.error('POST /bills:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// PUT /api/bills/:id
app.put('/api/bills/:id', requireAuth, writeLimiter, async (req, res) => {
  const b = req.body;
  if (!b.date || !b.description)
    return res.status(400).json({ success: false, message: 'Date and description required.' });
  try {
    // Non-admins can only edit their own bills
    const [existing] = await pool.execute('SELECT created_by FROM bills WHERE id=?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ success: false, message: 'Bill not found.' });
    if (req.user.role !== 'admin' && existing[0].created_by !== req.user.id)
      return res.status(403).json({ success: false, message: 'You can only edit your own bills.' });

    await pool.execute(
      `UPDATE bills SET
       date=?,description=?,purpose_site=?,category=?,sub_category=?,vendor=?,
       paid_by=?,payment_mode=?,amount=?,gst_tax=?,bill_attached=?,approved_by=?,notes=?,
       attachment_name=?,attachment_data=?,attachment_type=?
       WHERE id=?`,
      [
        b.date, b.description.trim(), b.purpose_site||'', b.category||'', b.sub_category||'',
        b.vendor||'', b.paid_by||'', b.payment_mode||'Cash',
        parseFloat(b.amount)||0, b.gst_tax||'', b.bill_attached||'No',
        b.approved_by||'', b.notes||'',
        b.attachment_name||null, b.attachment_data||null, b.attachment_type||null,
        req.params.id
      ]
    );
    res.json({ success: true, message: 'Bill updated.' });
  } catch (err) {
    console.error('PUT /bills:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/bills/:id
app.delete('/api/bills/:id', requireAuth, writeLimiter, async (req, res) => {
  try {
    const [existing] = await pool.execute('SELECT created_by FROM bills WHERE id=?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ success: false, message: 'Bill not found.' });
    if (req.user.role !== 'admin' && existing[0].created_by !== req.user.id)
      return res.status(403).json({ success: false, message: 'You can only delete your own bills.' });
    await pool.execute('DELETE FROM bills WHERE id=?', [req.params.id]);
    res.json({ success: true, message: 'Bill deleted.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// ── Health check ────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', service: 'DailyBills API' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ── Error handler ───────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled:', err.message);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

process.on('uncaughtException',  err => console.error('Uncaught:', err.message));
process.on('unhandledRejection', err => console.error('Rejected:', err));

const PORT = process.env.PORT || 5002;
(async () => {
  try {
    await initDB();
    app.listen(PORT, '0.0.0.0', () => console.log(`✅ DailyBills API running on port ${PORT}`));
  } catch (err) {
    console.error('Startup failed:', err);
    process.exit(1);
  }
})();

// ════════════════════════════════════════════════════════════════
//  DROPDOWN OPTIONS — custom items per field
// ════════════════════════════════════════════════════════════════

// GET /api/dropdowns — get all custom options grouped by field
app.get('/api/dropdowns', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT field_name, value FROM dropdown_options ORDER BY field_name, value');
    const grouped = {};
    rows.forEach(r => {
      if (!grouped[r.field_name]) grouped[r.field_name] = [];
      grouped[r.field_name].push(r.value);
    });
    res.json({ success: true, data: grouped });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/dropdowns — add a new option
app.post('/api/dropdowns', requireAuth, async (req, res) => {
  const { field_name, value } = req.body;
  if (!field_name || !value || !value.trim())
    return res.status(400).json({ success: false, message: 'field_name and value required.' });
  try {
    await pool.execute(
      'INSERT IGNORE INTO dropdown_options (field_name, value) VALUES (?,?)',
      [field_name.trim(), value.trim()]
    );
    res.status(201).json({ success: true, message: `"${value.trim()}" added to ${field_name}.` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/dropdowns — remove an option (admin only)
app.delete('/api/dropdowns', requireAdmin, async (req, res) => {
  const { field_name, value } = req.body;
  try {
    await pool.execute('DELETE FROM dropdown_options WHERE field_name=? AND value=?', [field_name, value]);
    res.json({ success: true });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// ════════════════════════════════════════════════════════════════
//  COLLECTIONS ROUTES (Admin only) — payments received per project
// ════════════════════════════════════════════════════════════════

// GET /api/collections — list all collections (newest first)
app.get('/api/collections', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT c.*, u.display AS created_by_name
       FROM collections c
       LEFT JOIN users u ON u.id = c.created_by
       ORDER BY c.created_at DESC, c.id DESC`
    );

    // Compute amount used per project (summed from matching bills)
    for (const row of rows) {
      const proj = (row.project_name || '').trim();
      if (!proj) { row.used = 0; row.remaining = Number(row.total_booked || 0); continue; }
      const like = `%${proj}%`;
      const [aggRows] = await pool.execute(
        `SELECT COALESCE(SUM(amount),0) AS used
         FROM bills
         WHERE purpose_site LIKE ? OR description LIKE ?`,
        [like, like]
      );
      row.used = Number((aggRows[0] && aggRows[0].used) || 0);
      row.remaining = Number(row.total_booked || 0) - row.used;
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('GET /collections:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/collections — add a new collection entry
app.post('/api/collections', requireAdmin, writeLimiter, async (req, res) => {
  const c = req.body;
  if (!c.project_name || !c.project_name.trim())
    return res.status(400).json({ success: false, message: 'Project name is required.' });
  try {
    const [r] = await pool.execute(
      `INSERT INTO collections
       (project_name, total_booked, received_amount, payment_method, received_by, notes, created_by)
       VALUES (?,?,?,?,?,?,?)`,
      [
        c.project_name.trim(),
        parseFloat(c.total_booked)    || 0,
        parseFloat(c.received_amount) || 0,
        c.payment_method || 'Cash',
        c.received_by    || '',
        c.notes          || '',
        req.user.id,
      ]
    );
    res.status(201).json({ success: true, id: r.insertId, message: 'Collection saved.' });
  } catch (err) {
    console.error('POST /collections:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/collections/:id — remove a collection entry
app.delete('/api/collections/:id', requireAdmin, writeLimiter, async (req, res) => {
  try {
    const [existing] = await pool.execute('SELECT id FROM collections WHERE id=?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ success: false, message: 'Collection not found.' });
    await pool.execute('DELETE FROM collections WHERE id=?', [req.params.id]);
    res.json({ success: true, message: 'Collection deleted.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// GET /api/collections/:id/details — project spend pulled from bills
//   "used" = sum of bills whose purpose_site / description matches the project name
app.get('/api/collections/:id/details', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM collections WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Collection not found.' });
    const collection = rows[0];
    const proj = (collection.project_name || '').trim();
    const like = `%${proj}%`;

    // Bills linked to this project by matching purpose/site or description
    const [bills] = await pool.execute(
      `SELECT id, voucher_no, date, description, category, purpose_site, vendor, amount
       FROM bills
       WHERE purpose_site LIKE ? OR description LIKE ?
       ORDER BY date DESC, id DESC`,
      [like, like]
    );

    const used = bills.reduce((s, b) => s + Number(b.amount || 0), 0);
    const totalBooked = Number(collection.total_booked || 0);
    const remaining   = totalBooked - used;

    res.json({
      success: true,
      data: {
        collection,
        total_booked: totalBooked,
        received_amount: Number(collection.received_amount || 0),
        used,
        remaining,
        bills,
      }
    });
  } catch (err) {
    console.error('GET /collections/:id/details:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});