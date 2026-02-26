# LED Truck ERP (Python Backend + JS Frontend)

Offline-first ERP for your LED truck rental business across India.

## Stack
- Backend: Python (Flask)
- Frontend: HTML/CSS/JavaScript
- Database: SQLite
- Backup: Local snapshots + optional AWS S3 upload

## Features
- OTP authentication (email or mobile)
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
2. Request OTP with admin email/mobile.
3. Verify OTP and login.
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

## OTP Delivery
- Development: `DEV_OTP_BYPASS=true` shows OTP on UI.
- Production:
  - set `DEV_OTP_BYPASS=false`
  - configure:
    - `EMAIL_OTP_WEBHOOK_URL`
    - `MOBILE_OTP_WEBHOOK_URL`

Your webhook should accept JSON:
```json
{
  "channel": "EMAIL or MOBILE",
  "target": "destination",
  "otp": "123456",
  "message": "Your ERP OTP is ..."
}
```

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
