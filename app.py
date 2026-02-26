import hashlib
import hmac
import json
import os
import shutil
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from secrets import token_hex
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

try:
    import boto3
except Exception:
    boto3 = None

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
IS_RAILWAY = bool(os.getenv("RAILWAY_PROJECT_ID") or os.getenv("RAILWAY_ENVIRONMENT"))
DEFAULT_DB_PATH = "/app/data/erp.sqlite" if IS_RAILWAY else "./data/erp.sqlite"
DEFAULT_BACKUP_DIR = "/app/backups" if IS_RAILWAY else "./backups"
DB_PATH = Path(os.getenv("DB_PATH", DEFAULT_DB_PATH)).resolve()
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", DEFAULT_BACKUP_DIR)).resolve()
BACKUP_INTERVAL_MIN = int(os.getenv("BACKUP_INTERVAL_MIN", "15"))
OTP_SECRET = os.getenv("OTP_SECRET", "change-me")
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
SESSION_EXPIRE_DAYS = int(os.getenv("SESSION_EXPIRE_DAYS", "30"))
DEV_OTP_BYPASS = os.getenv("DEV_OTP_BYPASS", "true").lower() == "true"
EMAIL_OTP_WEBHOOK_URL = os.getenv("EMAIL_OTP_WEBHOOK_URL", "").strip()
MOBILE_OTP_WEBHOOK_URL = os.getenv("MOBILE_OTP_WEBHOOK_URL", "").strip()

DB_PATH.parent.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder="public", static_url_path="")


@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def add_minutes_iso(minutes: int):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def add_days_iso(days: int):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def to_num(val):
    try:
        return float(val or 0)
    except Exception:
        return 0.0


def is_email(identifier: str):
    return "@" in identifier


def hash_otp(code: str):
    return hmac.new(OTP_SECRET.encode(), code.encode(), hashlib.sha256).hexdigest()


def hash_password(password: str):
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str):
    try:
        salt, expected = stored.split("$", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120000).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def sanitize_user(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "name": row["name"],
        "email": row["email"],
        "mobile": row["mobile"],
        "role": row["role"],
        "status": row["status"],
    }


def log_sync(event_type: str, status: str, message: str = ""):
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO sync_log (event_type, status, message) VALUES (?, ?, ?)",
            (event_type, status, message),
        )


def init_db():
    with db_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE,
              password_hash TEXT,
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
              vehicle_quantity INTEGER NOT NULL DEFAULT 0,
              rent_days INTEGER NOT NULL DEFAULT 0,
              finalized_amount REAL NOT NULL DEFAULT 0,
              advance_amount REAL NOT NULL DEFAULT 0,
              remaining_amount REAL NOT NULL DEFAULT 0,
              advance_mode TEXT NOT NULL DEFAULT 'CASH',
              remaining_mode TEXT NOT NULL DEFAULT 'PENDING',
              created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS client_contracts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              client_id INTEGER NOT NULL,
              vehicle_quantity INTEGER NOT NULL,
              rent_days INTEGER NOT NULL,
              finalized_amount REAL NOT NULL DEFAULT 0,
              advance_amount REAL NOT NULL DEFAULT 0,
              advance_mode TEXT NOT NULL CHECK (advance_mode IN ('CASH','ONLINE','CHECK')),
              remaining_amount REAL NOT NULL DEFAULT 0,
              remaining_mode TEXT NOT NULL DEFAULT 'PENDING' CHECK (remaining_mode IN ('PENDING','CASH','ONLINE','CHECK')),
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );

            CREATE TABLE IF NOT EXISTS vehicles (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              client_id INTEGER,
              vehicle_number TEXT NOT NULL UNIQUE,
              driver_name TEXT,
              driver_phone TEXT,
              operator_name TEXT,
              operator_phone TEXT,
              current_location TEXT,
              status TEXT NOT NULL DEFAULT 'AVAILABLE',
              rent_days INTEGER NOT NULL DEFAULT 0,
              driver_finalized_amount REAL NOT NULL DEFAULT 0,
              driver_advance_amount REAL NOT NULL DEFAULT 0,
              driver_remaining_amount REAL NOT NULL DEFAULT 0,
              driver_advance_mode TEXT NOT NULL DEFAULT 'CASH',
              driver_remaining_mode TEXT NOT NULL DEFAULT 'PENDING',
              operator_finalized_amount REAL NOT NULL DEFAULT 0,
              operator_advance_amount REAL NOT NULL DEFAULT 0,
              operator_remaining_amount REAL NOT NULL DEFAULT 0,
              operator_advance_mode TEXT NOT NULL DEFAULT 'CASH',
              operator_remaining_mode TEXT NOT NULL DEFAULT 'PENDING',
              notes TEXT,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );

            CREATE TABLE IF NOT EXISTS vehicle_finance (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              vehicle_id INTEGER NOT NULL,
              rent_days INTEGER NOT NULL,
              driver_finalized_amount REAL NOT NULL DEFAULT 0,
              driver_advance_amount REAL NOT NULL DEFAULT 0,
              driver_advance_mode TEXT NOT NULL CHECK (driver_advance_mode IN ('CASH','ONLINE','CHECK')),
              driver_remaining_amount REAL NOT NULL DEFAULT 0,
              driver_remaining_mode TEXT NOT NULL DEFAULT 'PENDING' CHECK (driver_remaining_mode IN ('PENDING','CASH','ONLINE','CHECK')),
              operator_finalized_amount REAL NOT NULL DEFAULT 0,
              operator_advance_amount REAL NOT NULL DEFAULT 0,
              operator_advance_mode TEXT NOT NULL CHECK (operator_advance_mode IN ('CASH','ONLINE','CHECK')),
              operator_remaining_amount REAL NOT NULL DEFAULT 0,
              operator_remaining_mode TEXT NOT NULL DEFAULT 'PENDING' CHECK (operator_remaining_mode IN ('PENDING','CASH','ONLINE','CHECK')),
              notes TEXT,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
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
            """
        )

        # Lightweight column migration for existing SQLite files.
        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "username" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN username TEXT")
        if "password_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")

        client_cols = {r["name"] for r in conn.execute("PRAGMA table_info(clients)").fetchall()}
        client_additions = [
            ("vehicle_quantity", "INTEGER NOT NULL DEFAULT 0"),
            ("rent_days", "INTEGER NOT NULL DEFAULT 0"),
            ("finalized_amount", "REAL NOT NULL DEFAULT 0"),
            ("advance_amount", "REAL NOT NULL DEFAULT 0"),
            ("remaining_amount", "REAL NOT NULL DEFAULT 0"),
            ("advance_mode", "TEXT NOT NULL DEFAULT 'CASH'"),
            ("remaining_mode", "TEXT NOT NULL DEFAULT 'PENDING'"),
        ]
        for col, ddl in client_additions:
            if col not in client_cols:
                conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {ddl}")

        vehicle_cols = {r["name"] for r in conn.execute("PRAGMA table_info(vehicles)").fetchall()}
        vehicle_additions = [
            ("client_id", "INTEGER"),
            ("rent_days", "INTEGER NOT NULL DEFAULT 0"),
            ("driver_finalized_amount", "REAL NOT NULL DEFAULT 0"),
            ("driver_advance_amount", "REAL NOT NULL DEFAULT 0"),
            ("driver_remaining_amount", "REAL NOT NULL DEFAULT 0"),
            ("driver_advance_mode", "TEXT NOT NULL DEFAULT 'CASH'"),
            ("driver_remaining_mode", "TEXT NOT NULL DEFAULT 'PENDING'"),
            ("operator_finalized_amount", "REAL NOT NULL DEFAULT 0"),
            ("operator_advance_amount", "REAL NOT NULL DEFAULT 0"),
            ("operator_remaining_amount", "REAL NOT NULL DEFAULT 0"),
            ("operator_advance_mode", "TEXT NOT NULL DEFAULT 'CASH'"),
            ("operator_remaining_mode", "TEXT NOT NULL DEFAULT 'PENDING'"),
        ]
        for col, ddl in vehicle_additions:
            if col not in vehicle_cols:
                conn.execute(f"ALTER TABLE vehicles ADD COLUMN {col} {ddl}")


def has_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False


def create_local_snapshot():
    with db_conn() as conn:
        conn.execute("PRAGMA wal_checkpoint(FULL)")

    ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    target = BACKUP_DIR / f"erp-backup-{ts}.sqlite"
    shutil.copy2(DB_PATH, target)
    log_sync("LOCAL_BACKUP", "SUCCESS", f"Created {target.name}")
    return target


def upload_to_s3(file_path: Path):
    region = os.getenv("AWS_REGION", "").strip()
    key_id = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
    secret = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
    bucket = os.getenv("S3_BUCKET", "").strip()
    prefix = os.getenv("S3_PREFIX", "erp-backups").strip().rstrip("/")

    if not all([region, key_id, secret, bucket]):
        log_sync("CLOUD_BACKUP", "SKIPPED", "S3 not configured")
        return
    if boto3 is None:
        log_sync("CLOUD_BACKUP", "FAILED", "boto3 not installed")
        return

    s3 = boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
    )
    key = f"{prefix}/{file_path.name}"
    s3.upload_file(str(file_path), bucket, key)
    log_sync("CLOUD_BACKUP", "SUCCESS", f"Uploaded {key}")


def backup_loop():
    while True:
        try:
            snapshot = create_local_snapshot()
            if has_internet():
                upload_to_s3(snapshot)
            else:
                log_sync("CLOUD_BACKUP", "SKIPPED", "No internet connection")
        except Exception as exc:
            log_sync("BACKUP", "FAILED", str(exc))
        time.sleep(BACKUP_INTERVAL_MIN * 60)


def start_backup_thread():
    t = threading.Thread(target=backup_loop, daemon=True)
    t.start()


def send_otp(channel: str, target: str, code: str):
    url = EMAIL_OTP_WEBHOOK_URL if channel == "EMAIL" else MOBILE_OTP_WEBHOOK_URL
    if not url:
        return False

    payload = json.dumps(
        {
            "channel": channel,
            "target": target,
            "otp": code,
            "message": f"Your ERP OTP is {code}. Valid for {OTP_EXPIRE_MINUTES} minutes.",
        }
    ).encode()

    req = urlrequest.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=8) as res:
            return 200 <= res.status < 300
    except (URLError, HTTPError):
        return False


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not token:
            return jsonify({"error": "Unauthorized"}), 401

        now_utc = datetime.now(timezone.utc)
        with db_conn() as conn:
            row = conn.execute(
                """
                SELECT s.token, s.expires_at,
                       u.id, u.username, u.name, u.email, u.mobile, u.role, u.status
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ?
                """,
                (token,),
            ).fetchone()

            if not row or row["status"] != "ACTIVE":
                return jsonify({"error": "Session expired or invalid"}), 401

            expires_at = parse_iso(row["expires_at"])
            if expires_at <= now_utc:
                return jsonify({"error": "Session expired or invalid"}), 401

            # Sliding session: active usage keeps user logged in.
            conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?", (add_days_iso(SESSION_EXPIRE_DAYS), token))

        if not row:
            return jsonify({"error": "Session expired or invalid"}), 401

        request.user = sanitize_user(row)
        request.session_token = token
        return fn(*args, **kwargs)

    return wrapper


def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(request, "user", None)
            if not user or user.get("role") not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def days_between(start_date: str, end_date: str):
    s = datetime.fromisoformat(start_date)
    e = datetime.fromisoformat(end_date)
    days = (e - s).days + 1
    return days if days > 0 else 1


@app.get("/api/auth/setup-status")
def auth_setup_status():
    with db_conn() as conn:
        credentialed = conn.execute(
            "SELECT COUNT(*) AS total FROM users WHERE username IS NOT NULL AND password_hash IS NOT NULL"
        ).fetchone()["total"]
    return jsonify({"needs_admin": credentialed == 0})


@app.post("/api/auth/bootstrap-admin")
def auth_bootstrap_admin():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip().lower()
    password = str(data.get("password") or "")
    email = (data.get("email") or "").strip() or None
    mobile = (data.get("mobile") or "").strip() or None

    if not name or not username or len(password) < 6:
        return jsonify({"error": "name, username and password (min 6 chars) are required"}), 400

    with db_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        credentialed = conn.execute(
            "SELECT COUNT(*) AS total FROM users WHERE username IS NOT NULL AND password_hash IS NOT NULL"
        ).fetchone()["total"]
        if credentialed > 0:
            return jsonify({"error": "Admin already initialized"}), 400

        existing_admin = conn.execute("SELECT id FROM users WHERE role='ADMIN' ORDER BY id ASC LIMIT 1").fetchone()
        if existing_admin:
            conn.execute(
                "UPDATE users SET username = ?, password_hash = ?, name = ?, email = ?, mobile = ?, status = 'ACTIVE' WHERE id = ?",
                (username, hash_password(password), name, email, mobile, existing_admin["id"]),
            )
            return jsonify({"id": existing_admin["id"], "message": "Admin credentials initialized"})

        if total > 0:
            return jsonify({"error": "Existing users found but no admin record available"}), 400

        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, name, email, mobile, role, status) VALUES (?, ?, ?, ?, ?, 'ADMIN', 'ACTIVE')",
                (username, hash_password(password), name, email, mobile),
            )
            return jsonify({"id": cur.lastrowid, "message": "Admin created"})
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username/email/mobile already exists"}), 400


@app.post("/api/auth/login")
def auth_login():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = str(data.get("password") or "")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    with db_conn() as conn:
        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(IFNULL(username, '')) = ?
               OR LOWER(IFNULL(email, '')) = ?
               OR IFNULL(mobile, '') = ?
            LIMIT 1
            """,
            (username, username, username),
        ).fetchone()
        if not user or user["status"] != "ACTIVE" or not user["password_hash"] or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Incorrect username/password"}), 401

        token = token_hex(32)
        conn.execute(
            "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, add_days_iso(SESSION_EXPIRE_DAYS)),
        )

    return jsonify({"token": token, "user": sanitize_user(user)})


@app.post("/api/auth/request-password-reset")
def auth_request_password_reset():
    data = request.get_json(force=True, silent=True) or {}
    mobile = (data.get("mobile") or "").strip()
    if not mobile:
        return jsonify({"error": "mobile is required"}), 400

    with db_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE mobile = ? AND status = 'ACTIVE'",
            (mobile,),
        ).fetchone()
        if not user:
            return jsonify({"error": "Mobile number not registered"}), 404

        code = str(int.from_bytes(os.urandom(3), "big") % 900000 + 100000)
        otp_hash = hash_otp(code)
        expires_at = add_minutes_iso(OTP_EXPIRE_MINUTES)

        conn.execute(
            "INSERT INTO otp_codes (user_id, channel, target, otp_hash, expires_at, used) VALUES (?, 'MOBILE', ?, ?, ?, 0)",
            (user["id"], mobile, otp_hash, expires_at),
        )

    delivered = send_otp("MOBILE", mobile, code)
    log_sync("PASSWORD_RESET_OTP", "SUCCESS" if delivered else "SKIPPED", f"OTP generated for mobile {mobile}")

    payload = {"message": "OTP sent to your mobile number"}
    if DEV_OTP_BYPASS:
        payload["dev_otp"] = code
    return jsonify(payload)


@app.post("/api/auth/reset-password")
def auth_reset_password():
    data = request.get_json(force=True, silent=True) or {}
    mobile = (data.get("mobile") or "").strip()
    code = str(data.get("code") or "").strip()
    new_password = str(data.get("new_password") or "")

    if not mobile or not code or len(new_password) < 6:
        return jsonify({"error": "mobile, otp code and new_password(min 6 chars) are required"}), 400

    with db_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE mobile = ? AND status = 'ACTIVE'",
            (mobile,),
        ).fetchone()
        if not user:
            return jsonify({"error": "Mobile number not registered"}), 404

        otp_row = conn.execute(
            """
            SELECT * FROM otp_codes
            WHERE user_id = ? AND channel = 'MOBILE' AND target = ? AND otp_hash = ? AND used = 0 AND expires_at > ?
            ORDER BY id DESC LIMIT 1
            """,
            (user["id"], mobile, hash_otp(code), now_iso()),
        ).fetchone()
        if not otp_row:
            return jsonify({"error": "Invalid or expired OTP"}), 401

        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_row["id"],))
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["id"]))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))

    return jsonify({"success": True, "message": "Password reset successful. Please login again."})


@app.post("/api/auth/request-otp")
def auth_request_otp():
    data = request.get_json(force=True, silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    if not identifier:
        return jsonify({"error": "identifier is required"}), 400

    with db_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?" if is_email(identifier) else "SELECT * FROM users WHERE mobile = ?",
            (identifier,),
        ).fetchone()

        if not user or user["status"] != "ACTIVE":
            return jsonify({"error": "User not found or inactive"}), 404

        code = str(int.from_bytes(os.urandom(3), "big") % 900000 + 100000)
        otp_hash = hash_otp(code)
        expires_at = add_minutes_iso(OTP_EXPIRE_MINUTES)
        channel = "EMAIL" if is_email(identifier) else "MOBILE"

        conn.execute(
            "INSERT INTO otp_codes (user_id, channel, target, otp_hash, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)",
            (user["id"], channel, identifier, otp_hash, expires_at),
        )

    delivered = send_otp(channel, identifier, code)
    log_sync("OTP", "SUCCESS" if delivered else "SKIPPED", f"OTP generated for {channel} {identifier}")

    payload = {
        "message": (
            f"OTP sent to your {'email' if channel == 'EMAIL' else 'mobile'}"
            if delivered
            else f"OTP generated. Configure provider webhook for {channel} delivery."
        )
    }
    if DEV_OTP_BYPASS:
        payload["dev_otp"] = code

    return jsonify(payload)


@app.post("/api/auth/verify-otp")
def auth_verify_otp():
    data = request.get_json(force=True, silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    code = str(data.get("code") or "").strip()
    if not identifier or not code:
        return jsonify({"error": "identifier and code are required"}), 400

    with db_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?" if is_email(identifier) else "SELECT * FROM users WHERE mobile = ?",
            (identifier,),
        ).fetchone()
        if not user or user["status"] != "ACTIVE":
            return jsonify({"error": "Invalid credentials"}), 401

        otp_row = conn.execute(
            """
            SELECT * FROM otp_codes
            WHERE user_id = ? AND target = ? AND otp_hash = ? AND used = 0 AND expires_at > ?
            ORDER BY id DESC LIMIT 1
            """,
            (user["id"], identifier, hash_otp(code), now_iso()),
        ).fetchone()

        if not otp_row:
            return jsonify({"error": "Invalid or expired OTP"}), 401

        token = token_hex(32)
        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_row["id"],))
        conn.execute(
            "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, add_days_iso(SESSION_EXPIRE_DAYS)),
        )

    return jsonify({"token": token, "user": sanitize_user(user)})


@app.get("/api/auth/me")
@require_auth
def auth_me():
    return jsonify({"user": request.user})


@app.post("/api/auth/logout")
@require_auth
def auth_logout():
    with db_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (request.session_token,))
    return jsonify({"success": True})


@app.get("/api/users")
@require_auth
@require_role("ADMIN")
def users_list():
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id, username, name, email, mobile, role, status, created_at, CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END AS has_password FROM users ORDER BY id DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/users")
@require_auth
@require_role("ADMIN")
def users_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip().lower()
    password = str(data.get("password") or "")
    email = (data.get("email") or "").strip() or None
    mobile = (data.get("mobile") or "").strip() or None
    role = "ADMIN" if (data.get("role") == "ADMIN") else "USER"

    if not name or not username or len(password) < 6:
        return jsonify({"error": "name, username and password (min 6 chars) are required"}), 400

    with db_conn() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, name, email, mobile, role, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
                (username, hash_password(password), name, email, mobile, role),
            )
            return jsonify({"id": cur.lastrowid})
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username/email/mobile already exists"}), 400


@app.patch("/api/users/<int:user_id>")
@require_auth
@require_role("ADMIN")
def users_update(user_id: int):
    data = request.get_json(force=True, silent=True) or {}
    status = (data.get("status") or "").strip().upper()
    if status not in ["ACTIVE", "INACTIVE"]:
        return jsonify({"error": "status must be ACTIVE or INACTIVE"}), 400

    with db_conn() as conn:
        user = conn.execute("SELECT id, role, status FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user["id"] == request.user["id"]:
            return jsonify({"error": "You cannot change your own status"}), 400

        if user["role"] == "ADMIN" and status == "INACTIVE":
            active_admins = conn.execute(
                "SELECT COUNT(*) AS total FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'"
            ).fetchone()["total"]
            if active_admins <= 1 and user["status"] == "ACTIVE":
                return jsonify({"error": "Cannot inactivate the last active admin"}), 400

        conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
    return jsonify({"success": True})


@app.patch("/api/users/<int:user_id>/credentials")
@require_auth
@require_role("ADMIN")
def users_update_credentials(user_id: int):
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = str(data.get("password") or "")
    if not username or len(password) < 6:
        return jsonify({"error": "username and password (min 6 chars) are required"}), 400

    with db_conn() as conn:
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        taken = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id)).fetchone()
        if taken:
            return jsonify({"error": "Username already in use"}), 400

        conn.execute(
            "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
            (username, hash_password(password), user_id),
        )
    return jsonify({"success": True})


@app.delete("/api/users/<int:user_id>")
@require_auth
@require_role("ADMIN")
def users_delete(user_id: int):
    with db_conn() as conn:
        user = conn.execute("SELECT id, role, status FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user["id"] == request.user["id"]:
            return jsonify({"error": "You cannot delete your own account"}), 400

        if user["role"] == "ADMIN":
            active_admins = conn.execute(
                "SELECT COUNT(*) AS total FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'"
            ).fetchone()["total"]
            if active_admins <= 1 and user["status"] == "ACTIVE":
                return jsonify({"error": "Cannot delete the last active admin"}), 400

        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"success": True})


@app.get("/api/dashboard")
@require_auth
def dashboard():
    with db_conn() as conn:
        counts = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM vehicles) AS total_vehicles,
              (SELECT COUNT(*) FROM vehicles WHERE status = 'ON_RENT') AS on_rent,
              (SELECT COUNT(*) FROM clients) AS total_clients,
              (SELECT COUNT(*) FROM rentals WHERE contract_status = 'ACTIVE') AS active_rentals
            """
        ).fetchone()

        client_outstanding = conn.execute(
            """
            SELECT COALESCE(SUM(r.client_finalized_charge - r.client_advance - IFNULL(cp.total_paid, 0)), 0) AS amount
            FROM rentals r
            LEFT JOIN (
              SELECT rental_id, SUM(amount) AS total_paid
              FROM client_payments
              GROUP BY rental_id
            ) cp ON cp.rental_id = r.id
            """
        ).fetchone()["amount"]

        staff_outstanding = conn.execute(
            """
            SELECT COALESCE(SUM((driver_total_charge - driver_advance) + (operator_total_charge - operator_advance)), 0) AS amount
            FROM rentals
            WHERE contract_status = 'ACTIVE'
            """
        ).fetchone()["amount"]

    payload = dict(counts)
    payload["client_outstanding"] = float(client_outstanding or 0)
    payload["staff_outstanding"] = float(staff_outstanding or 0)
    return jsonify(payload)


@app.get("/api/clients")
@require_auth
def clients_list():
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM clients ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/clients")
@require_auth
def clients_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Client name is required"}), 400

    advance_mode = data.get("advance_mode") or "CASH"
    remaining_mode = data.get("remaining_mode") or "PENDING"
    if advance_mode not in ["CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "advance_mode must be CASH, ONLINE, or CHECK"}), 400
    if remaining_mode not in ["PENDING", "CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "remaining_mode must be PENDING, CASH, ONLINE, or CHECK"}), 400

    finalized = to_num(data.get("finalized_amount"))
    advance = to_num(data.get("advance_amount"))
    remaining = to_num(data.get("remaining_amount"))
    if remaining == 0 and finalized >= advance:
        remaining = finalized - advance

    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO clients (
              name, phone, email, address,
              vehicle_quantity, rent_days, finalized_amount, advance_amount, remaining_amount, advance_mode, remaining_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                data.get("phone") or None,
                data.get("email") or None,
                data.get("address") or None,
                int(data.get("vehicle_quantity") or 0),
                int(data.get("rent_days") or 0),
                finalized,
                advance,
                remaining,
                advance_mode,
                remaining_mode,
            ),
        )
    return jsonify({"id": cur.lastrowid})


@app.get("/api/client-contracts")
@require_auth
def client_contracts_list():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT cc.*, c.name AS client_name
            FROM client_contracts cc
            JOIN clients c ON c.id = cc.client_id
            ORDER BY cc.id DESC
            """
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/client-contracts")
@require_auth
def client_contracts_create():
    data = request.get_json(force=True, silent=True) or {}
    required = [
        "client_id",
        "vehicle_quantity",
        "rent_days",
        "finalized_amount",
        "advance_amount",
        "advance_mode",
    ]
    if any(data.get(k) in [None, ""] for k in required):
        return jsonify(
            {
                "error": "client_id, vehicle_quantity, rent_days, finalized_amount, advance_amount, advance_mode are required"
            }
        ), 400

    if data["advance_mode"] not in ["CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "advance_mode must be CASH, ONLINE, or CHECK"}), 400

    remaining_mode = data.get("remaining_mode") or "PENDING"
    if remaining_mode not in ["PENDING", "CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "remaining_mode must be PENDING, CASH, ONLINE, or CHECK"}), 400

    finalized = to_num(data.get("finalized_amount"))
    advance = to_num(data.get("advance_amount"))
    remaining = max(finalized - advance, 0)

    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO client_contracts (
              client_id, vehicle_quantity, rent_days,
              finalized_amount, advance_amount, advance_mode,
              remaining_amount, remaining_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["client_id"],
                int(data["vehicle_quantity"]),
                int(data["rent_days"]),
                finalized,
                advance,
                data["advance_mode"],
                remaining,
                remaining_mode,
            ),
        )
    return jsonify({"id": cur.lastrowid})


@app.get("/api/vehicles")
@require_auth
def vehicles_list():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT v.*, c.name AS client_name
            FROM vehicles v
            LEFT JOIN clients c ON c.id = v.client_id
            ORDER BY v.id DESC
            """
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/vehicles")
@require_auth
def vehicles_create():
    data = request.get_json(force=True, silent=True) or {}
    vehicle_number = (data.get("vehicle_number") or "").strip()
    if not vehicle_number:
        return jsonify({"error": "Vehicle number is required"}), 400
    if not data.get("client_id"):
        return jsonify({"error": "client_id is required"}), 400

    driver_advance_mode = data.get("driver_advance_mode") or "CASH"
    driver_remaining_mode = data.get("driver_remaining_mode") or "PENDING"
    operator_advance_mode = data.get("operator_advance_mode") or "CASH"
    operator_remaining_mode = data.get("operator_remaining_mode") or "PENDING"

    valid_modes = ["CASH", "ONLINE", "CHECK"]
    valid_remaining_modes = ["PENDING", "CASH", "ONLINE", "CHECK"]
    if driver_advance_mode not in valid_modes or operator_advance_mode not in valid_modes:
        return jsonify({"error": "driver/operator advance mode must be CASH, ONLINE, or CHECK"}), 400
    if driver_remaining_mode not in valid_remaining_modes or operator_remaining_mode not in valid_remaining_modes:
        return jsonify({"error": "driver/operator remaining mode must be PENDING, CASH, ONLINE, or CHECK"}), 400

    driver_finalized = to_num(data.get("driver_finalized_amount"))
    driver_advance = to_num(data.get("driver_advance_amount"))
    driver_remaining = to_num(data.get("driver_remaining_amount"))
    if driver_remaining == 0 and driver_finalized >= driver_advance:
        driver_remaining = driver_finalized - driver_advance

    operator_finalized = to_num(data.get("operator_finalized_amount"))
    operator_advance = to_num(data.get("operator_advance_amount"))
    operator_remaining = to_num(data.get("operator_remaining_amount"))
    if operator_remaining == 0 and operator_finalized >= operator_advance:
        operator_remaining = operator_finalized - operator_advance

    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO vehicles (
              client_id, vehicle_number, driver_name, driver_phone, operator_name, operator_phone, current_location, status,
              rent_days,
              driver_finalized_amount, driver_advance_amount, driver_remaining_amount, driver_advance_mode, driver_remaining_mode,
              operator_finalized_amount, operator_advance_amount, operator_remaining_amount, operator_advance_mode, operator_remaining_mode,
              notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("client_id"),
                vehicle_number,
                data.get("driver_name") or None,
                data.get("driver_phone") or None,
                data.get("operator_name") or None,
                data.get("operator_phone") or None,
                data.get("current_location") or None,
                data.get("status") or "AVAILABLE",
                int(data.get("rent_days") or 0),
                driver_finalized,
                driver_advance,
                driver_remaining,
                driver_advance_mode,
                driver_remaining_mode,
                operator_finalized,
                operator_advance,
                operator_remaining,
                operator_advance_mode,
                operator_remaining_mode,
                data.get("notes") or None,
            ),
        )
    return jsonify({"id": cur.lastrowid})


@app.get("/api/vehicle-finance")
@require_auth
def vehicle_finance_list():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT vf.*, v.vehicle_number, v.driver_name, v.operator_name
            FROM vehicle_finance vf
            JOIN vehicles v ON v.id = vf.vehicle_id
            ORDER BY vf.id DESC
            """
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/vehicle-finance")
@require_auth
def vehicle_finance_create():
    data = request.get_json(force=True, silent=True) or {}
    required = [
        "vehicle_id",
        "rent_days",
        "driver_finalized_amount",
        "driver_advance_amount",
        "driver_advance_mode",
        "operator_finalized_amount",
        "operator_advance_amount",
        "operator_advance_mode",
    ]
    if any(data.get(k) in [None, ""] for k in required):
        return jsonify({"error": "vehicle_id, rent_days, driver/operator finalized+advance+mode are required"}), 400

    if data["driver_advance_mode"] not in ["CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "driver_advance_mode must be CASH, ONLINE, or CHECK"}), 400
    if data["operator_advance_mode"] not in ["CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "operator_advance_mode must be CASH, ONLINE, or CHECK"}), 400

    driver_remaining_mode = data.get("driver_remaining_mode") or "PENDING"
    operator_remaining_mode = data.get("operator_remaining_mode") or "PENDING"
    valid_remaining_modes = ["PENDING", "CASH", "ONLINE", "CHECK"]
    if driver_remaining_mode not in valid_remaining_modes or operator_remaining_mode not in valid_remaining_modes:
        return jsonify({"error": "remaining mode must be PENDING, CASH, ONLINE, or CHECK"}), 400

    driver_finalized = to_num(data.get("driver_finalized_amount"))
    driver_advance = to_num(data.get("driver_advance_amount"))
    operator_finalized = to_num(data.get("operator_finalized_amount"))
    operator_advance = to_num(data.get("operator_advance_amount"))

    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO vehicle_finance (
              vehicle_id, rent_days,
              driver_finalized_amount, driver_advance_amount, driver_advance_mode, driver_remaining_amount, driver_remaining_mode,
              operator_finalized_amount, operator_advance_amount, operator_advance_mode, operator_remaining_amount, operator_remaining_mode,
              notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["vehicle_id"],
                int(data["rent_days"]),
                driver_finalized,
                driver_advance,
                data["driver_advance_mode"],
                max(driver_finalized - driver_advance, 0),
                driver_remaining_mode,
                operator_finalized,
                operator_advance,
                data["operator_advance_mode"],
                max(operator_finalized - operator_advance, 0),
                operator_remaining_mode,
                data.get("notes") or None,
            ),
        )
    return jsonify({"id": cur.lastrowid})


@app.get("/api/rentals")
@require_auth
def rentals_list():
    with db_conn() as conn:
        rows = conn.execute(
            """
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
            """
        ).fetchall()

    result = []
    for r in rows:
        row = dict(r)
        row["client_remaining"] = float(row["client_finalized_charge"] or 0) - float(row["client_advance"] or 0) - float(row["client_paid"] or 0)
        row["driver_remaining"] = float(row["driver_total_charge"] or 0) - float(row["driver_advance"] or 0)
        row["operator_remaining"] = float(row["operator_total_charge"] or 0) - float(row["operator_advance"] or 0)
        result.append(row)

    return jsonify(result)


@app.post("/api/rentals")
@require_auth
def rentals_create():
    data = request.get_json(force=True, silent=True) or {}
    required = ["client_id", "vehicle_id", "start_date", "end_date"]
    if any(not data.get(k) for k in required):
        return jsonify({"error": "client_id, vehicle_id, start_date, end_date are required"}), 400

    total_days = days_between(data["start_date"], data["end_date"])

    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO rentals (
              client_id, vehicle_id, start_date, end_date, total_days,
              client_finalized_charge, client_advance,
              driver_total_charge, operator_total_charge,
              driver_advance, operator_advance,
              notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["client_id"],
                data["vehicle_id"],
                data["start_date"],
                data["end_date"],
                total_days,
                to_num(data.get("client_finalized_charge")),
                to_num(data.get("client_advance")),
                to_num(data.get("driver_total_charge")),
                to_num(data.get("operator_total_charge")),
                to_num(data.get("driver_advance")),
                to_num(data.get("operator_advance")),
                data.get("notes") or None,
            ),
        )
        conn.execute("UPDATE vehicles SET status = 'ON_RENT' WHERE id = ?", (data["vehicle_id"],))
    return jsonify({"id": cur.lastrowid})


@app.post("/api/rentals/<int:rental_id>/close")
@require_auth
def rentals_close(rental_id: int):
    with db_conn() as conn:
        rental = conn.execute("SELECT * FROM rentals WHERE id = ?", (rental_id,)).fetchone()
        if not rental:
            return jsonify({"error": "Rental not found"}), 404

        conn.execute("UPDATE rentals SET contract_status = 'CLOSED' WHERE id = ?", (rental_id,))
        conn.execute("UPDATE vehicles SET status = 'AVAILABLE' WHERE id = ?", (rental["vehicle_id"],))
    return jsonify({"success": True})


@app.get("/api/payments")
@require_auth
def payments_list():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT cp.*, c.name AS client_name, v.vehicle_number
            FROM client_payments cp
            JOIN clients c ON c.id = cp.client_id
            LEFT JOIN rentals r ON r.id = cp.rental_id
            LEFT JOIN vehicles v ON v.id = r.vehicle_id
            ORDER BY cp.id DESC
            """
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/payments")
@require_auth
def payments_create():
    data = request.get_json(force=True, silent=True) or {}
    required = ["client_id", "amount", "payment_type", "payment_date"]
    if any(not data.get(k) for k in required):
        return jsonify({"error": "client_id, amount, payment_type, payment_date are required"}), 400

    if data["payment_type"] not in ["CASH", "ONLINE", "CHECK"]:
        return jsonify({"error": "payment_type must be CASH, ONLINE, or CHECK"}), 400

    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO client_payments (client_id, rental_id, amount, payment_type, reference_no, payment_date, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["client_id"],
                data.get("rental_id") or None,
                to_num(data["amount"]),
                data["payment_type"],
                data.get("reference_no") or None,
                data["payment_date"],
                data.get("notes") or None,
            ),
        )
    return jsonify({"id": cur.lastrowid})


@app.get("/api/sync-log")
@require_auth
def sync_log():
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM sync_log ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    full = BASE_DIR / "public" / path
    if path and full.exists():
        return send_from_directory(BASE_DIR / "public", path)
    return send_from_directory(BASE_DIR / "public", "index.html")


def main():
    init_db()
    start_backup_thread()
    app.run(host=os.getenv("APP_HOST", "0.0.0.0"), port=int(os.getenv("PORT", "4000")), debug=False)


if __name__ == "__main__":
    main()
