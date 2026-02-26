require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const path = require('path');
const { db, initDb } = require('./db');
const { startBackupScheduler } = require('./backup');

initDb();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.resolve(__dirname, '../public')));

function toNum(v) {
  return Number(v || 0);
}

function daysBetween(start, end) {
  const s = new Date(start);
  const e = new Date(end);
  const ms = e - s;
  const days = Math.floor(ms / (1000 * 60 * 60 * 24)) + 1;
  return days > 0 ? days : 1;
}

function nowIso() {
  return new Date().toISOString();
}

function addMinutesIso(minutes) {
  const d = new Date();
  d.setMinutes(d.getMinutes() + minutes);
  return d.toISOString();
}

function addDaysIso(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function hashOtp(code) {
  const secret = process.env.OTP_SECRET || 'change-me';
  return crypto.createHash('sha256').update(`${code}:${secret}`).digest('hex');
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isEmail(identifier) {
  return identifier.includes('@');
}

function sanitizeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    mobile: user.mobile,
    role: user.role,
    status: user.status,
  };
}

async function sendOtp(channel, target, code) {
  const webhook =
    channel === 'EMAIL'
      ? process.env.EMAIL_OTP_WEBHOOK_URL
      : process.env.MOBILE_OTP_WEBHOOK_URL;

  if (!webhook) return false;

  try {
    const response = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel,
        target,
        otp: code,
        message: `Your ERP OTP is ${code}. It is valid for ${process.env.OTP_EXPIRE_MINUTES || 10} minutes.`,
      }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const row = db
    .prepare(
      `
      SELECT s.id AS session_id, s.token, s.expires_at,
             u.id, u.name, u.email, u.mobile, u.role, u.status
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ?
    `
    )
    .get(token);

  if (!row || row.status !== 'ACTIVE' || row.expires_at <= nowIso()) {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }

  req.user = sanitizeUser(row);
  req.sessionToken = token;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.get('/api/auth/setup-status', (req, res) => {
  const totalUsers = db.prepare(`SELECT COUNT(*) AS total FROM users`).get().total;
  res.json({ needs_admin: totalUsers === 0 });
});

app.post('/api/auth/bootstrap-admin', (req, res) => {
  const totalUsers = db.prepare(`SELECT COUNT(*) AS total FROM users`).get().total;
  if (totalUsers > 0) {
    return res.status(400).json({ error: 'Admin already initialized' });
  }

  const { name, email, mobile } = req.body;
  if (!name || (!email && !mobile)) {
    return res.status(400).json({ error: 'name and either email or mobile are required' });
  }

  const result = db
    .prepare(`INSERT INTO users (name, email, mobile, role, status) VALUES (?, ?, ?, 'ADMIN', 'ACTIVE')`)
    .run(name, email || null, mobile || null);

  res.json({ id: result.lastInsertRowid, message: 'Admin created' });
});

app.post('/api/auth/request-otp', async (req, res) => {
  const { identifier } = req.body;
  if (!identifier) return res.status(400).json({ error: 'identifier is required' });

  const user = isEmail(identifier)
    ? db.prepare(`SELECT * FROM users WHERE email = ?`).get(identifier)
    : db.prepare(`SELECT * FROM users WHERE mobile = ?`).get(identifier);

  if (!user || user.status !== 'ACTIVE') {
    return res.status(404).json({ error: 'User not found or inactive' });
  }

  const channel = isEmail(identifier) ? 'EMAIL' : 'MOBILE';
  const code = generateOtp();
  const otpHash = hashOtp(code);
  const expiresAt = addMinutesIso(Number(process.env.OTP_EXPIRE_MINUTES || 10));

  db.prepare(
    `INSERT INTO otp_codes (user_id, channel, target, otp_hash, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)`
  ).run(user.id, channel, identifier, otpHash, expiresAt);

  const delivered = await sendOtp(channel, identifier, code);
  db.prepare(`INSERT INTO sync_log (event_type, status, message) VALUES (?, ?, ?)`)
    .run('OTP', delivered ? 'SUCCESS' : 'SKIPPED', `OTP generated for ${channel} ${identifier}`);

  const devBypass = String(process.env.DEV_OTP_BYPASS || 'true') === 'true';
  const payload = {
    message: delivered
      ? `OTP sent to your ${channel === 'EMAIL' ? 'email' : 'mobile'} number`
      : `OTP generated. Configure provider webhook to auto-deliver ${channel} OTP.`,
  };
  if (devBypass) {
    payload.dev_otp = code;
  }

  res.json(payload);
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { identifier, code } = req.body;
  if (!identifier || !code) {
    return res.status(400).json({ error: 'identifier and code are required' });
  }

  const user = isEmail(identifier)
    ? db.prepare(`SELECT * FROM users WHERE email = ?`).get(identifier)
    : db.prepare(`SELECT * FROM users WHERE mobile = ?`).get(identifier);

  if (!user || user.status !== 'ACTIVE') {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const otpHash = hashOtp(String(code));
  const otpRow = db
    .prepare(
      `
      SELECT *
      FROM otp_codes
      WHERE user_id = ? AND target = ? AND otp_hash = ? AND used = 0 AND expires_at > ?
      ORDER BY id DESC
      LIMIT 1
      `
    )
    .get(user.id, identifier, otpHash, nowIso());

  if (!otpRow) {
    return res.status(401).json({ error: 'Invalid or expired OTP' });
  }

  const token = generateToken();
  const expiresAt = addDaysIso(Number(process.env.SESSION_EXPIRE_DAYS || 7));

  const tx = db.transaction(() => {
    db.prepare(`UPDATE otp_codes SET used = 1 WHERE id = ?`).run(otpRow.id);
    db.prepare(`INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)`)
      .run(user.id, token, expiresAt);
  });

  tx();

  res.json({ token, user: sanitizeUser(user) });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  db.prepare(`DELETE FROM sessions WHERE token = ?`).run(req.sessionToken);
  res.json({ success: true });
});

app.get('/api/users', requireAuth, requireRole('ADMIN'), (req, res) => {
  const rows = db.prepare(`SELECT id, name, email, mobile, role, status, created_at FROM users ORDER BY id DESC`).all();
  res.json(rows);
});

app.post('/api/users', requireAuth, requireRole('ADMIN'), (req, res) => {
  const { name, email, mobile, role } = req.body;
  if (!name || (!email && !mobile)) {
    return res.status(400).json({ error: 'name and either email or mobile are required' });
  }

  const roleValue = role === 'ADMIN' ? 'ADMIN' : 'USER';
  const result = db
    .prepare(`INSERT INTO users (name, email, mobile, role, status) VALUES (?, ?, ?, ?, 'ACTIVE')`)
    .run(name, email || null, mobile || null, roleValue);

  res.json({ id: result.lastInsertRowid });
});

app.patch('/api/users/:id', requireAuth, requireRole('ADMIN'), (req, res) => {
  const userId = Number(req.params.id);
  const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { name, role, status } = req.body;
  const nextName = name || user.name;
  const nextRole = role && ['ADMIN', 'USER'].includes(role) ? role : user.role;
  const nextStatus = status && ['ACTIVE', 'INACTIVE'].includes(status) ? status : user.status;

  db.prepare(`UPDATE users SET name = ?, role = ?, status = ? WHERE id = ?`)
    .run(nextName, nextRole, nextStatus, userId);

  res.json({ success: true });
});

app.get('/api/dashboard', requireAuth, (req, res) => {
  const counts = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM vehicles) AS total_vehicles,
      (SELECT COUNT(*) FROM vehicles WHERE status = 'ON_RENT') AS on_rent,
      (SELECT COUNT(*) FROM clients) AS total_clients,
      (SELECT COUNT(*) FROM rentals WHERE contract_status = 'ACTIVE') AS active_rentals
  `).get();

  const clientOutstanding = db.prepare(`
    SELECT COALESCE(SUM(r.client_finalized_charge - r.client_advance - IFNULL(cp.total_paid, 0)), 0) AS amount
    FROM rentals r
    LEFT JOIN (
      SELECT rental_id, SUM(amount) AS total_paid
      FROM client_payments
      GROUP BY rental_id
    ) cp ON cp.rental_id = r.id
  `).get();

  const staffOutstanding = db.prepare(`
    SELECT COALESCE(SUM((driver_total_charge - driver_advance) + (operator_total_charge - operator_advance)), 0) AS amount
    FROM rentals
    WHERE contract_status = 'ACTIVE'
  `).get();

  res.json({
    ...counts,
    client_outstanding: Number(clientOutstanding.amount || 0),
    staff_outstanding: Number(staffOutstanding.amount || 0),
  });
});

app.get('/api/clients', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM clients ORDER BY id DESC`).all();
  res.json(rows);
});

app.post('/api/clients', requireAuth, (req, res) => {
  const { name, phone, email, address } = req.body;
  if (!name) return res.status(400).json({ error: 'Client name is required' });

  const result = db
    .prepare(`INSERT INTO clients (name, phone, email, address) VALUES (?, ?, ?, ?)`)
    .run(name, phone || null, email || null, address || null);

  res.json({ id: result.lastInsertRowid });
});

app.get('/api/vehicles', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM vehicles ORDER BY id DESC`).all();
  res.json(rows);
});

app.post('/api/vehicles', requireAuth, (req, res) => {
  const {
    vehicle_number,
    driver_name,
    driver_phone,
    operator_name,
    operator_phone,
    current_location,
    notes,
  } = req.body;

  if (!vehicle_number) return res.status(400).json({ error: 'Vehicle number is required' });

  const result = db
    .prepare(`
      INSERT INTO vehicles (
        vehicle_number, driver_name, driver_phone, operator_name, operator_phone, current_location, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      vehicle_number,
      driver_name || null,
      driver_phone || null,
      operator_name || null,
      operator_phone || null,
      current_location || null,
      notes || null
    );

  res.json({ id: result.lastInsertRowid });
});

app.get('/api/rentals', requireAuth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT
        r.*,
        c.name AS client_name,
        v.vehicle_number,
        v.driver_name,
        v.driver_phone,
        v.operator_name,
        v.operator_phone,
        IFNULL(cp.total_paid, 0) AS client_paid
      FROM rentals r
      JOIN clients c ON c.id = r.client_id
      JOIN vehicles v ON v.id = r.vehicle_id
      LEFT JOIN (
        SELECT rental_id, SUM(amount) AS total_paid
        FROM client_payments
        GROUP BY rental_id
      ) cp ON cp.rental_id = r.id
      ORDER BY r.id DESC
    `)
    .all()
    .map((r) => ({
      ...r,
      client_remaining: Number(r.client_finalized_charge) - Number(r.client_advance) - Number(r.client_paid),
      driver_remaining: Number(r.driver_total_charge) - Number(r.driver_advance),
      operator_remaining: Number(r.operator_total_charge) - Number(r.operator_advance),
    }));

  res.json(rows);
});

app.post('/api/rentals', requireAuth, (req, res) => {
  const {
    client_id,
    vehicle_id,
    start_date,
    end_date,
    client_finalized_charge,
    client_advance,
    driver_total_charge,
    operator_total_charge,
    driver_advance,
    operator_advance,
    notes,
  } = req.body;

  if (!client_id || !vehicle_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'client_id, vehicle_id, start_date, end_date are required' });
  }

  const totalDays = daysBetween(start_date, end_date);

  const tx = db.transaction(() => {
    const rental = db
      .prepare(`
        INSERT INTO rentals (
          client_id, vehicle_id, start_date, end_date, total_days,
          client_finalized_charge, client_advance,
          driver_total_charge, operator_total_charge,
          driver_advance, operator_advance,
          notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        client_id,
        vehicle_id,
        start_date,
        end_date,
        totalDays,
        toNum(client_finalized_charge),
        toNum(client_advance),
        toNum(driver_total_charge),
        toNum(operator_total_charge),
        toNum(driver_advance),
        toNum(operator_advance),
        notes || null
      );

    db.prepare(`UPDATE vehicles SET status = 'ON_RENT' WHERE id = ?`).run(vehicle_id);

    return rental.lastInsertRowid;
  });

  const id = tx();
  res.json({ id });
});

app.post('/api/rentals/:id/close', requireAuth, (req, res) => {
  const rentalId = Number(req.params.id);
  const rental = db.prepare(`SELECT * FROM rentals WHERE id = ?`).get(rentalId);
  if (!rental) return res.status(404).json({ error: 'Rental not found' });

  const tx = db.transaction(() => {
    db.prepare(`UPDATE rentals SET contract_status = 'CLOSED' WHERE id = ?`).run(rentalId);
    db.prepare(`UPDATE vehicles SET status = 'AVAILABLE' WHERE id = ?`).run(rental.vehicle_id);
  });

  tx();
  res.json({ success: true });
});

app.get('/api/payments', requireAuth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT cp.*, c.name AS client_name, v.vehicle_number
      FROM client_payments cp
      JOIN clients c ON c.id = cp.client_id
      LEFT JOIN rentals r ON r.id = cp.rental_id
      LEFT JOIN vehicles v ON v.id = r.vehicle_id
      ORDER BY cp.id DESC
    `)
    .all();

  res.json(rows);
});

app.post('/api/payments', requireAuth, (req, res) => {
  const { client_id, rental_id, amount, payment_type, reference_no, payment_date, notes } = req.body;

  if (!client_id || !amount || !payment_type || !payment_date) {
    return res.status(400).json({ error: 'client_id, amount, payment_type, payment_date are required' });
  }

  if (!['CASH', 'ONLINE', 'CHECK'].includes(payment_type)) {
    return res.status(400).json({ error: 'payment_type must be CASH, ONLINE, or CHECK' });
  }

  const result = db
    .prepare(`
      INSERT INTO client_payments (client_id, rental_id, amount, payment_type, reference_no, payment_date, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      client_id,
      rental_id || null,
      toNum(amount),
      payment_type,
      reference_no || null,
      payment_date,
      notes || null
    );

  res.json({ id: result.lastInsertRowid });
});

app.get('/api/sync-log', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM sync_log ORDER BY id DESC LIMIT 100`).all();
  res.json(rows);
});

app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../public/index.html'));
});

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  startBackupScheduler();
  console.log(`ERP server running at http://localhost:${port}`);
});
