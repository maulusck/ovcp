PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS certs (
  serial     TEXT PRIMARY KEY,          -- hex, no leading zeros
  cn         TEXT NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN ('server','client')),
  cert_pem   BLOB NOT NULL,
  issued_at  INTEGER NOT NULL,          -- unix
  not_after  INTEGER NOT NULL,
  revoked_at INTEGER                    -- NULL = valid
);
CREATE INDEX IF NOT EXISTS idx_certs_cn ON certs(cn);

CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY,
  username   TEXT NOT NULL UNIQUE,
  pass_hash  TEXT NOT NULL,             -- argon2id encoded
  role       TEXT NOT NULL CHECK (role IN ('admin','operator','readonly')),
  totp_secret TEXT,                     -- NULL until 2FA enrolled
  created_at INTEGER NOT NULL,
  disabled   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,          -- sha256(token)
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id      INTEGER PRIMARY KEY,
  ts      INTEGER NOT NULL,
  actor   TEXT NOT NULL,                -- username or 'system'
  action  TEXT NOT NULL,                -- login, issue, revoke, kill, config_change, ...
  detail  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
