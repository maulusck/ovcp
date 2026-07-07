package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCertLifecycle(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	c := Cert{Serial: "abc123", CN: "alice", Kind: "client",
		CertPEM: []byte("PEM"), IssuedAt: now, NotAfter: now.AddDate(1, 0, 0)}
	if err := s.AddCert(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCert("abc123")
	if err != nil || got.CN != "alice" || got.RevokedAt != nil {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	if err := s.Revoke("abc123", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke("abc123", now); err == nil {
		t.Fatal("double revoke should error")
	}
	rev, err := s.RevokedCerts()
	if err != nil || len(rev) != 1 {
		t.Fatalf("revoked: %v %v", rev, err)
	}
	all, _ := s.ListCerts()
	if len(all) != 1 {
		t.Fatalf("list = %d", len(all))
	}
}

func TestAudit(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()
	s.Audit("admin", "issue", "cn=alice")
	s.Audit("admin", "revoke", "serial=abc")
	tail, err := s.AuditTail(10)
	if err != nil || len(tail) != 2 || tail[0].Action != "revoke" {
		t.Fatalf("tail: %+v err=%v", tail, err)
	}
}
