const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { db, absoluteDbPath } = require('./db');

const backupDir = path.resolve(process.env.BACKUP_DIR || './backups');
const backupIntervalMin = Number(process.env.BACKUP_INTERVAL_MIN || '15');

const s3ConfigReady =
  process.env.AWS_REGION &&
  process.env.AWS_ACCESS_KEY_ID &&
  process.env.AWS_SECRET_ACCESS_KEY &&
  process.env.S3_BUCKET;

const s3Client = s3ConfigReady
  ? new S3Client({
      region: process.env.AWS_REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    })
  : null;

async function hasInternet() {
  try {
    await dns.lookup('google.com');
    return true;
  } catch {
    return false;
  }
}

function logSync(eventType, status, message) {
  db.prepare(
    `INSERT INTO sync_log (event_type, status, message) VALUES (?, ?, ?)`
  ).run(eventType, status, message || null);
}

function timestamp() {
  const d = new Date();
  return d.toISOString().replace(/[:.]/g, '-');
}

function createLocalSnapshot() {
  fs.mkdirSync(backupDir, { recursive: true });

  db.pragma('wal_checkpoint(FULL)');

  const fileName = `erp-backup-${timestamp()}.sqlite`;
  const target = path.join(backupDir, fileName);
  fs.copyFileSync(absoluteDbPath, target);

  logSync('LOCAL_BACKUP', 'SUCCESS', `Created ${fileName}`);
  return target;
}

async function uploadToS3(filePath) {
  if (!s3Client) return;

  const keyPrefix = (process.env.S3_PREFIX || 'erp-backups').replace(/\/+$/, '');
  const key = `${keyPrefix}/${path.basename(filePath)}`;
  const body = fs.readFileSync(filePath);

  await s3Client.send(
    new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: key,
      Body: body,
      ContentType: 'application/octet-stream',
    })
  );

  logSync('CLOUD_BACKUP', 'SUCCESS', `Uploaded ${key}`);
}

async function runBackupCycle() {
  try {
    const snapshotPath = createLocalSnapshot();
    const online = await hasInternet();

    if (online && s3Client) {
      await uploadToS3(snapshotPath);
    } else if (!online) {
      logSync('CLOUD_BACKUP', 'SKIPPED', 'No internet connection');
    } else {
      logSync('CLOUD_BACKUP', 'SKIPPED', 'S3 not configured');
    }
  } catch (error) {
    logSync('BACKUP', 'FAILED', error.message);
  }
}

function startBackupScheduler() {
  runBackupCycle();
  setInterval(runBackupCycle, backupIntervalMin * 60 * 1000);
}

module.exports = { startBackupScheduler };
