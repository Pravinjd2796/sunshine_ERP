const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const dbPath = process.env.DB_PATH || './data/erp.sqlite';
const absoluteDbPath = path.resolve(dbPath);
fs.mkdirSync(path.dirname(absoluteDbPath), { recursive: true });

const db = new Database(absoluteDbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE,
      mobile TEXT UNIQUE,
      role TEXT NOT NULL CHECK (role IN ('ADMIN','USER')),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      channel TEXT NOT NULL CHECK (channel IN ('EMAIL','MOBILE')),
      target TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      address TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS vehicles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vehicle_number TEXT NOT NULL UNIQUE,
      driver_name TEXT,
      driver_phone TEXT,
      operator_name TEXT,
      operator_phone TEXT,
      current_location TEXT,
      status TEXT NOT NULL DEFAULT 'AVAILABLE',
      notes TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS rentals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      vehicle_id INTEGER NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      total_days INTEGER NOT NULL,
      client_finalized_charge REAL NOT NULL DEFAULT 0,
      client_advance REAL NOT NULL DEFAULT 0,
      driver_total_charge REAL NOT NULL DEFAULT 0,
      operator_total_charge REAL NOT NULL DEFAULT 0,
      driver_advance REAL NOT NULL DEFAULT 0,
      operator_advance REAL NOT NULL DEFAULT 0,
      contract_status TEXT NOT NULL DEFAULT 'ACTIVE',
      notes TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(client_id) REFERENCES clients(id),
      FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
    );

    CREATE TABLE IF NOT EXISTS client_payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      rental_id INTEGER,
      amount REAL NOT NULL,
      payment_type TEXT NOT NULL CHECK (payment_type IN ('CASH','ONLINE','CHECK')),
      reference_no TEXT,
      payment_date TEXT NOT NULL,
      notes TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(client_id) REFERENCES clients(id),
      FOREIGN KEY(rental_id) REFERENCES rentals(id)
    );

    CREATE TABLE IF NOT EXISTS sync_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      status TEXT NOT NULL,
      message TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

module.exports = { db, initDb, absoluteDbPath };
