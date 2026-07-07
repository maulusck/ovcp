package store

import (
	"database/sql"
	"errors"
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

func (s *Store) GetUser(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, pass_hash, role, COALESCE(totp_secret,''), disabled, created_at
		 FROM users WHERE username = ?`, username)
	var u User
	var dis int
	var created int64
	if err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.TOTPSecret, &dis, &created); err != nil {
		return nil, err
	}
	u.Disabled = dis != 0
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
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
		var u User
		var dis int
		var created int64
		if err := rows.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.TOTPSecret, &dis, &created); err != nil {
			return nil, err
		}
		u.Disabled = dis != 0
		u.CreatedAt = time.Unix(created, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserDisabled(username string, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	return s.mustAffect(s.db.Exec(`UPDATE users SET disabled=? WHERE username=?`, d, username))
}

func (s *Store) SetUserPassword(username, passHash string) error {
	return s.mustAffect(s.db.Exec(`UPDATE users SET pass_hash=? WHERE username=?`, passHash, username))
}

func (s *Store) SetUserTOTP(username, secret string) error {
	return s.mustAffect(s.db.Exec(`UPDATE users SET totp_secret=? WHERE username=?`, secret, username))
}

func (s *Store) mustAffect(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("store: no such user")
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
	var u User
	var dis int
	var created int64
	if err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.TOTPSecret, &dis, &created); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) PurgeExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

func (s *Store) DeleteUser(username string) error {
	return s.mustAffect(s.db.Exec(`DELETE FROM users WHERE username=?`, username))
}
