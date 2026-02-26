# LED Truck ERP (Python Backend + JS Frontend)

Offline-first ERP for your LED truck rental business across India.

## Stack
- Backend: Python (Flask)
- Frontend: HTML/CSS/JavaScript
- Database: SQLite
- Backup: Local snapshots + optional AWS S3 upload

## Features
- Username/password authentication for admin and users
- Offline-first data entry for clients and vehicles with automatic sync when internet returns
- Role-based access: `ADMIN` and `USER`
- Client management
- Vehicle + driver/operator management
- Rental contract tracking (days, amounts, advances, pending)
- Client payment tracking with mode (`CASH`, `ONLINE`, `CHECK`)
- Dashboard with outstanding totals
- Backup/sync logs
- Fancy India LED campaign UI theme

## Run Step-by-Step
1. Go to project folder
```bash
cd /Users/pravinjadhav/Desktop/Pravin/PM/ERP
```

2. Create virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Create environment config
```bash
cp .env.example .env
```

5. Start server
```bash
python3 app.py
```

6. Open in browser
- [http://localhost:4000](http://localhost:4000)

## First Login
1. Create admin on first screen.
2. Login using admin username and password.
4. After login, app opens a simple home page with two choices:
   - Client Information
   - Vehicle Information

## New Data Captured
- Client page (single Add Client form) now tracks:
  - name, phone, email, address
  - number of vehicles
  - rent days
  - finalized amount
  - advance payment + mode
  - remaining payment + mode
- Vehicle page (single Add Vehicle form) now tracks:
  - vehicle, driver, operator details
  - rent days
  - driver finalized, advance + mode, remaining + mode
  - operator finalized, advance + mode, remaining + mode

## Login Notes
- Users are created by admin from the **User Management** page.
- Each user gets a `username` and `password`.
- Session is persisted in browser local storage and extended on active usage.
- Forgot password flow uses registered mobile number + OTP before password reset.

## Offline + Online Behavior
- If internet is down, client/vehicle entries are saved locally in browser outbox.
- When internet is back, pending entries sync automatically to server.
- App pages are cached via service worker for offline access after first load.

## Cloud Backup (Optional)
Configure AWS keys and bucket in `.env`.
- App stores data in local SQLite always.
- Every `BACKUP_INTERVAL_MIN` minutes:
  - save local backup in `./backups`
  - if internet + S3 configured, upload snapshot to S3

## Notes
- Old Node.js files may still exist, but active backend is `app.py`.
- Keep app running while entering data.
- UI is now multi-page for simplicity:
  - `/index.html` (login)
  - `/home.html` (menu)
  - `/clients.html`
  - `/vehicles.html`
