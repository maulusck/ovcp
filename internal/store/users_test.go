package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSessionExpiry: an expired session must resolve to nil user — without
// this, sessions that never expire would pass the whole suite.
func TestSessionExpiry(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.AddUser("alice", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	s.AddSession("expired", id, -time.Second)
	if u, err := s.SessionUser("expired"); err != nil || u != nil {
		t.Fatalf("expired session must be nil user, got %+v err=%v", u, err)
	}
	s.AddSession("live", id, time.Hour)
	if u, err := s.SessionUser("live"); err != nil || u == nil || u.Username != "alice" {
		t.Fatalf("live session must resolve, got %+v err=%v", u, err)
	}
}

func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.AddUser("alice", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	if err := s.SetUserTOTP("alice", secret); err != nil {
		t.Fatal(err)
	}

	// Round-trips back to plaintext through the store API.
	u, err := s.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.TOTPSecret != secret {
		t.Fatalf("GetUser: got %q, want %q", u.TOTPSecret, secret)
	}

	// The value actually stored in the DB must not be the plaintext secret.
	var raw string
	if err := s.db.QueryRow(`SELECT totp_secret FROM users WHERE username=?`, "alice").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, secret) {
		t.Fatalf("totp_secret stored in plaintext: %q", raw)
	}

	// Disabling (empty secret) stays the empty sentinel, not ciphertext.
	if err := s.SetUserTOTP("alice", ""); err != nil {
		t.Fatal(err)
	}
	if u, err = s.GetUser("alice"); err != nil {
		t.Fatal(err)
	} else if u.TOTPSecret != "" {
		t.Fatalf("want empty (disabled), got %q", u.TOTPSecret)
	}
}
