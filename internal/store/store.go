// Package store: SQLite persistence. Cert metadata only — never private keys.
package store

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db *sql.DB
	// totpKey encrypts totp_secret at rest (AES-256-GCM). Unlike the CA key,
	// there's no operator passphrase available at automatic login time, so
	// this lives in a plain machine-local file next to the database.
	totpKey []byte
}

type Cert struct {
	Serial    string
	CN        string
	Kind      string // "server" | "client"
	CertPEM   []byte
	IssuedAt  time.Time
	NotAfter  time.Time
	RevokedAt *time.Time
}

type AuditEntry struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	Detail string
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_fk=1")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
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

// BackupTo writes a consistent point-in-time copy of the database to path,
// which must not already exist. Uses SQLite's own VACUUM INTO rather than a
// raw file copy, so a backup taken while writes are in flight is never torn.
func (s *Store) BackupTo(path string) error {
	_, err := s.db.Exec("VACUUM INTO ?", path)
	return err
}

// --- certs ---

func (s *Store) AddCert(c Cert) error {
	_, err := s.db.Exec(
		`INSERT INTO certs(serial, cn, kind, cert_pem, issued_at, not_after) VALUES (?,?,?,?,?,?)`,
		c.Serial, c.CN, c.Kind, c.CertPEM, c.IssuedAt.Unix(), c.NotAfter.Unix())
	return err
}

func (s *Store) GetCert(serial string) (*Cert, error) {
	row := s.db.QueryRow(
		`SELECT serial, cn, kind, cert_pem, issued_at, not_after, revoked_at FROM certs WHERE serial = ?`, serial)
	return scanCert(row)
}

func (s *Store) ListCerts() ([]Cert, error) {
	rows, err := s.db.Query(
		`SELECT serial, cn, kind, cert_pem, issued_at, not_after, revoked_at FROM certs ORDER BY issued_at DESC`)
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
		`SELECT serial, cn, kind, cert_pem, issued_at, not_after, revoked_at FROM certs WHERE revoked_at IS NOT NULL`)
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
	if err := r.Scan(&c.Serial, &c.CN, &c.Kind, &c.CertPEM, &issued, &notAfter, &revoked); err != nil {
		return nil, err
	}
	c.IssuedAt = time.Unix(issued, 0)
	c.NotAfter = time.Unix(notAfter, 0)
	if revoked.Valid {
		t := time.Unix(revoked.Int64, 0)
		c.RevokedAt = &t
	}
	return &c, nil
}

// --- audit ---

func (s *Store) Audit(actor, action, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log(ts, actor, action, detail) VALUES (?,?,?,?)`,
		time.Now().Unix(), actor, action, detail)
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
