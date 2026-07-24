package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

type User struct {
	ID         int64
	Username   string
	PassHash   string
	Role       string // admin|operator|readonly
	TOTPSecret string // "" = not enrolled
	Disabled   bool
	CreatedAt  time.Time
}

func (s *Store) AddUser(username, passHash, role string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO users(username, pass_hash, role, created_at) VALUES (?,?,?,?)`,
		username, passHash, role, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// scanUser reads a users row and decrypts totp_secret — every query touching
// that column routes through here so none can forget to.
func (s *Store) scanUser(r scanner) (*User, error) {
	var u User
	var dis int
	var created int64
	if err := r.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.TOTPSecret, &dis, &created); err != nil {
		return nil, err
	}
	u.Disabled = dis != 0
	u.CreatedAt = time.Unix(created, 0)
	dec, err := s.decryptTOTP(u.TOTPSecret)
	if err != nil {
		return nil, err
	}
	u.TOTPSecret = dec
	return &u, nil
}

func (s *Store) GetUser(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, pass_hash, role, COALESCE(totp_secret,''), disabled, created_at
		 FROM users WHERE username = ?`, username)
	return s.scanUser(row)
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, username, pass_hash, role, COALESCE(totp_secret,''), disabled, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserDisabled(username string, disabled bool) error {
	res, err := s.db.Exec(`UPDATE users SET disabled=? WHERE username=?`, boolInt(disabled), username)
	return s.mustAffect(res, err, "store: no such user")
}

func (s *Store) SetUserPassword(username, passHash string) error {
	res, err := s.db.Exec(`UPDATE users SET pass_hash=? WHERE username=?`, passHash, username)
	return s.mustAffect(res, err, "store: no such user")
}

func (s *Store) SetUserTOTP(username, secret string) error {
	enc, err := s.encryptTOTP(secret)
	if err != nil {
		return err
	}
	res, execErr := s.db.Exec(`UPDATE users SET totp_secret=? WHERE username=?`, enc, username)
	return s.mustAffect(res, execErr, "store: no such user")
}

// encryptTOTP/decryptTOTP keep totp_secret encrypted at rest (AES-256-GCM,
// store.totpKey). "" is the not-enrolled sentinel, passed through unencrypted
// so callers can compare against it directly.
func (s *Store) encryptTOTP(secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	gcm, err := s.totpGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (s *Store) decryptTOTP(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("store: corrupt totp secret: %w", err)
	}
	gcm, err := s.totpGCM()
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("store: corrupt totp secret")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("store: corrupt totp secret: %w", err)
	}
	return string(pt), nil
}

func (s *Store) totpGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.totpKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) mustAffect(res sql.Result, err error, notFoundMsg string) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New(notFoundMsg)
	}
	return nil
}

// --- sessions ---

func (s *Store) AddSession(tokenHash string, userID int64, ttl time.Duration) error {
	now := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)`,
		tokenHash, userID, now.Unix(), now.Add(ttl).Unix())
	return err
}

// SessionUser resolves a token hash to its (non-disabled) user; nil if invalid/expired.
func (s *Store) SessionUser(tokenHash string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT u.id, u.username, u.pass_hash, u.role, COALESCE(u.totp_secret,''), u.disabled, u.created_at
		 FROM sessions se JOIN users u ON u.id = se.user_id
		 WHERE se.token_hash = ? AND se.expires_at > ? AND u.disabled = 0`,
		tokenHash, time.Now().Unix())
	u, err := s.scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteUser(username string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE username=?`, username)
	return s.mustAffect(res, err, "store: no such user")
}
