-- Cloudflare D1 schema: notification devices only. Existing Firestore data is untouched.
CREATE TABLE IF NOT EXISTS push_devices (
  token_hash TEXT PRIMARY KEY,
  subscription_json TEXT NOT NULL,
  settings_json TEXT NOT NULL,
  events_json TEXT NOT NULL DEFAULT '[]',
  last_sent_date TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_push_devices_updated_at ON push_devices(updated_at);
