// Package store: SQLite persistence. Cert metadata only — never private keys.
package store

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/ovcp/ovcp/internal/pki"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db *sql.DB
	// totpKey encrypts totp_secret at rest (AES-256-GCM), stored in a plain
	// machine-local file — no operator passphrase exists at automatic login.
	totpKey []byte
	// fires after Audit() — the one choke point every audited action routes
	// through, instead of hooking each call site.
	auditHook AuditHook
}

type AuditHook func(actor, action, detail string)

// OnAudit sets fn to run after every Audit(). Set once at startup.
func (s *Store) OnAudit(fn AuditHook) { s.auditHook = fn }

// ExpiryWarnDays mirrors web/ui/src/Certs.svelte's EXPIRY_WARN_DAYS — JS
// can't share this constant, keep both in sync if it ever changes.
const ExpiryWarnDays = 30

type Cert struct {
	Serial     string
	CN         string
	Kind       string // "server" | "client"
	CertPEM    []byte
	IssuedAt   time.Time
	NotAfter   time.Time
	RevokedAt  *time.Time
	IncludeDNS bool // whether this CN gets a certs.hosts line while connected (Records tab); default true
}

// CertFrom is the store row for a freshly issued cert — every issue path
// (CLI and API) writes this same shape.
func CertFrom(ic *pki.IssuedCert, kind string) Cert {
	return Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: kind,
		CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter, IncludeDNS: true}
}

type AuditEntry struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	Detail string
}

// Open assumes path's directory already exists with the right permissions —
// ensureSkeleton (cmd/ovcp) is the one place that owns creating it.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_fk=1")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(f, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			return nil, err
		}
	}
	key, err := loadOrCreateTOTPKey(filepath.Join(filepath.Dir(path), "totp.key"))
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, totpKey: key}, nil
}

func loadOrCreateTOTPKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("store: bad totp key length in %s", path)
		}
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, key, 0o600)
}

func (s *Store) Close() error { return s.db.Close() }

// Ping verifies the database connection is alive (health checks).
func (s *Store) Ping() error { return s.db.Ping() }

// BackupTo copies the database to path (must not already exist) via SQLite's
// VACUUM INTO, so a backup taken mid-write is never torn.
func (s *Store) BackupTo(path string) error {
	_, err := s.db.Exec("VACUUM INTO ?", path)
	return err
}

// --- certs ---

// ErrDuplicateCN: one active (non-revoked) cert per CN+kind — client or
// server. Revoke the old one first (renewal does this automatically).
var ErrDuplicateCN = errors.New("an active cert already exists for this CN — revoke it first")

// activeCertSerial returns the non-revoked cert's serial for cn+kind, or ""
// if there isn't one.
func (s *Store) activeCertSerial(cn, kind string) (string, error) {
	var serial string
	err := s.db.QueryRow(
		`SELECT serial FROM certs WHERE cn = ? AND kind = ? AND revoked_at IS NULL LIMIT 1`, cn, kind).Scan(&serial)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return serial, err
}

// boolInt converts a Go bool to the 0/1 SQLite stores it as.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// AddCert is the one funnel every issue path uses, so the active-CN check lives here, once.
// ponytail: check-then-insert race needs two concurrent issues of the same new CN — not this tool's load.
func (s *Store) AddCert(c Cert) error {
	if prev, err := s.activeCertSerial(c.CN, c.Kind); err != nil {
		return err
	} else if prev != "" {
		return fmt.Errorf("store: %s: %w", c.CN, ErrDuplicateCN)
	}
	_, err := s.db.Exec(
		`INSERT INTO certs(serial, cn, kind, cert_pem, issued_at, not_after, include_dns) VALUES (?,?,?,?,?,?,?)`,
		c.Serial, c.CN, c.Kind, c.CertPEM, c.IssuedAt.Unix(), c.NotAfter.Unix(), boolInt(c.IncludeDNS))
	return err
}

// SetCertDNS toggles whether serial's CN gets a certs.hosts line, mirroring
// SetUserDisabled's shape.
func (s *Store) SetCertDNS(serial string, include bool) error {
	res, err := s.db.Exec(`UPDATE certs SET include_dns=? WHERE serial=?`, boolInt(include), serial)
	return s.mustAffect(res, err, "store: no such cert")
}

// ReplaceCert retires c's outgoing active cert (same CN+kind), if any, then
// adds c — server-cert renewal in one call, shared by the CLI and the API.
func (s *Store) ReplaceCert(c Cert) error {
	prev, err := s.activeCertSerial(c.CN, c.Kind)
	if err != nil {
		return err
	}
	if prev != "" {
		if err := s.Revoke(prev, time.Now()); err != nil {
			return err
		}
	}
	return s.AddCert(c)
}

func (s *Store) GetCert(serial string) (*Cert, error) {
	row := s.db.QueryRow(
		`SELECT serial, cn, kind, cert_pem, issued_at, not_after, revoked_at, include_dns FROM certs WHERE serial = ?`, serial)
	return scanCert(row)
}

func (s *Store) ListCerts() ([]Cert, error) {
	rows, err := s.db.Query(
		`SELECT serial, cn, kind, cert_pem, issued_at, not_after, revoked_at, include_dns FROM certs ORDER BY issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// Revoke marks a cert revoked. Returns sql.ErrNoRows if unknown,
// and an error if already revoked (idempotence is the caller's policy call).
func (s *Store) Revoke(serial string, at time.Time) error {
	res, err := s.db.Exec(
		`UPDATE certs SET revoked_at = ? WHERE serial = ? AND revoked_at IS NULL`, at.Unix(), serial)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("store: cert %s not found or already revoked", serial)
	}
	return nil
}

// RevokedCerts returns the full revoked set (feeds CRL regeneration).
func (s *Store) RevokedCerts() ([]Cert, error) {
	rows, err := s.db.Query(
		`SELECT serial, cn, kind, cert_pem, issued_at, not_after, revoked_at, include_dns FROM certs WHERE revoked_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanCert(r scanner) (*Cert, error) {
	var c Cert
	var issued, notAfter int64
	var revoked sql.NullInt64
	var includeDNS int
	if err := r.Scan(&c.Serial, &c.CN, &c.Kind, &c.CertPEM, &issued, &notAfter, &revoked, &includeDNS); err != nil {
		return nil, err
	}
	c.IssuedAt = time.Unix(issued, 0)
	c.NotAfter = time.Unix(notAfter, 0)
	if revoked.Valid {
		t := time.Unix(revoked.Int64, 0)
		c.RevokedAt = &t
	}
	c.IncludeDNS = includeDNS != 0
	return &c, nil
}

// --- audit ---

func (s *Store) Audit(actor, action, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log(ts, actor, action, detail) VALUES (?,?,?,?)`,
		time.Now().Unix(), actor, action, detail)
	if err == nil && s.auditHook != nil {
		s.auditHook(actor, action, detail)
	}
	return err
}

func (s *Store) AuditTail(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- settings ---

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings(key, value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// LoadJSON reads key as JSON, falling back to def — missing key or corrupt
// value, same treatment: every persisted config in ovcp treats "unset" as
// "use the default", not an error. The one settings-as-JSON round-trip,
// shared by every admin-tunable config (log rotation, stats sampling, ...).
func LoadJSON[T any](s *Store, key string, def T) T {
	raw, _ := s.GetSetting(key)
	if raw == "" {
		return def
	}
	cfg := def
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return def
	}
	return cfg
}

// SaveJSON is LoadJSON's write side.
func SaveJSON[T any](s *Store, key string, v T) error {
	enc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.SetSetting(key, string(enc))
}
