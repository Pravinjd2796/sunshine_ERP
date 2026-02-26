# Deploy ERP to Railway (Public URL)

## 1. Push project to GitHub
From project root:
```bash
git init
git add .
git commit -m "ERP ready for cloud deploy"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

## 2. Create Railway project
1. Open [Railway](https://railway.com) and login.
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Select your ERP repository.

## 3. Configure service start
Railway will use `Procfile`:
- `web: python3 app.py`

## 4. Add environment variables
In Railway service -> **Variables**, add:
- `PORT` = `4000`
- `APP_HOST` = `0.0.0.0`
- `DB_PATH` = `/app/data/erp.sqlite`
- `BACKUP_DIR` = `/app/backups`
- `BACKUP_INTERVAL_MIN` = `15`
- `OTP_SECRET` = `<long-random-secret>`
- `OTP_EXPIRE_MINUTES` = `10`
- `SESSION_EXPIRE_DAYS` = `30`
- `DEV_OTP_BYPASS` = `true` (for testing)
- `EMAIL_OTP_WEBHOOK_URL` = ``
- `MOBILE_OTP_WEBHOOK_URL` = ``

## 5. Attach persistent volume (very important)
In Railway service -> **Volumes**:
1. Create volume
2. Mount path: `/app/data`

This keeps SQLite data persistent across deploys.
Without this volume, data is lost on redeploy/restart.

## 6. (Optional) backup folder volume
If you want backups persisted too, mount another volume at:
- `/app/backups`

## 7. Get public URL
1. Open service settings -> **Networking**
2. Generate domain
3. Railway gives URL like:
   - `https://your-app-name.up.railway.app`

Share this URL with your client.

## 8. First-time app use
1. Open URL
2. Create admin
3. Login via OTP
4. Admin creates test users

## 9. For stricter testing
After initial setup, set:
- `DEV_OTP_BYPASS=false`
And configure SMS/email webhook URLs.
