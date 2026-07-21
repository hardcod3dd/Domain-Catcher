const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');

const dataDir = path.resolve(process.env.DATA_DIR || 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'domain-catcher.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
  CREATE TABLE IF NOT EXISTS keywords (
    id INTEGER PRIMARY KEY, value TEXT NOT NULL COLLATE NOCASE UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY, domain TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS catches (
    id INTEGER PRIMARY KEY, domain TEXT NOT NULL COLLATE NOCASE UNIQUE,
    matched_keyword TEXT NOT NULL, match_type TEXT NOT NULL,
    caught_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'queued', screenshot_path TEXT,
    screenshot_error TEXT, whois_json TEXT, ip_json TEXT, error TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_catches_caught ON catches(caught_at DESC);
`);
const keywordColumns = db.prepare('PRAGMA table_info(keywords)').all().map(column => column.name);
if (!keywordColumns.includes('match_scope')) db.exec("ALTER TABLE keywords ADD COLUMN match_scope TEXT NOT NULL DEFAULT 'all'");
const catchColumns = db.prepare('PRAGMA table_info(catches)').all().map(column => column.name);
if (!catchColumns.includes('favorite')) db.exec('ALTER TABLE catches ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0');
// A process can exit while an asynchronous enrichment task owns a row. There is
// no useful in-memory work to resume, so return those rows to the durable queue.
db.prepare("UPDATE catches SET status='queued',updated_at=CURRENT_TIMESTAMP WHERE status='processing'").run();

const defaults = {
  certstream_url: process.env.CERTSTREAM_URL || 'ws://localhost:4000/full-stream', ipinfo_token: '',
  screenshot_proxy: '', screenshot_enabled: '1', worker_enabled: '0'
};
const putSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
for (const [key, value] of Object.entries(defaults)) db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)').run(key, value);
// Migrate the legacy Compose endpoint without replacing a URL the user chose.
if (process.env.CERTSTREAM_URL) {
  db.prepare("UPDATE settings SET value=? WHERE key='certstream_url' AND value IN ('ws://localhost:8080/full-stream','ws://localhost:4000/full-stream','ws://certstream:4000/full-stream')")
    .run(process.env.CERTSTREAM_URL);
}

function settings() {
  return Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x => [x.key, x.value]));
}
function setSettings(values) {
  const tx = db.transaction(() => Object.entries(values).forEach(([k, v]) => putSetting.run(k, String(v ?? ''))));
  tx();
}

module.exports = { db, settings, setSettings, dataDir };
