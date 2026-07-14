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

DROP TABLE IF EXISTS vpn_samples; -- superseded by client_samples below

-- periodic per-client snapshot (Stats tab charts); one row per connected
-- client per sample tick. The global view (Connected clients/Rate/Volume)
-- is a GROUP BY ts over this table; the per-client view is a WHERE cn = ?.
CREATE TABLE IF NOT EXISTS client_samples (
  ts         INTEGER NOT NULL,             -- unix
  cn         TEXT NOT NULL,
  bytes_recv INTEGER NOT NULL,             -- that client's own cumulative counter at ts (OpenVPN's, resets on reconnect)
  bytes_sent INTEGER NOT NULL,
  PRIMARY KEY (ts, cn)
);
CREATE INDEX IF NOT EXISTS idx_client_samples_cn ON client_samples(cn, ts);

-- one row per finished client session; a session missing from one sample to
-- the next is logged here, so this table doubles as the disconnect log.
CREATE TABLE IF NOT EXISTS client_sessions (
  id              INTEGER PRIMARY KEY,
  cn              TEXT NOT NULL,
  real_address    TEXT NOT NULL,
  connected_at    INTEGER NOT NULL,
  disconnected_at INTEGER NOT NULL,
  bytes_recv      INTEGER NOT NULL,
  bytes_sent      INTEGER NOT NULL
);
-- prune-by-age is the only lookup pattern on this table; keeps the periodic
-- DELETE an index scan instead of a full table scan as sessions accumulate.
CREATE INDEX IF NOT EXISTS idx_client_sessions_disconnected ON client_sessions(disconnected_at);
