package store

import (
	"errors"
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

func TestAddCertDuplicateCN(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	client := func(serial string) Cert {
		return Cert{Serial: serial, CN: "bob", Kind: "client",
			CertPEM: []byte("PEM"), IssuedAt: now, NotAfter: now.AddDate(1, 0, 0)}
	}
	if err := s.AddCert(client("s1")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCert(client("s2")); !errors.Is(err, ErrDuplicateCN) {
		t.Fatalf("want ErrDuplicateCN, got %v", err)
	}
	if err := s.Revoke("s1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCert(client("s3")); err != nil {
		t.Fatalf("reissue after revoke should succeed: %v", err)
	}
}

func TestReplaceCert(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	srv := func(serial string) Cert {
		return Cert{Serial: serial, CN: "vpn.example", Kind: "server",
			CertPEM: []byte("PEM"), IssuedAt: now, NotAfter: now.AddDate(1, 0, 0)}
	}
	if err := s.ReplaceCert(srv("srv1")); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceCert(srv("srv2")); err != nil {
		t.Fatalf("renewal should retire the outgoing cert, not collide: %v", err)
	}
	old, err := s.GetCert("srv1")
	if err != nil || old.RevokedAt == nil {
		t.Fatalf("outgoing cert should be revoked: %+v err=%v", old, err)
	}
	cur, err := s.GetCert("srv2")
	if err != nil || cur.RevokedAt != nil {
		t.Fatalf("new cert should be active: %+v err=%v", cur, err)
	}
}

func TestClientSamples(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Now().Add(-time.Minute).Truncate(time.Second)
	t1 := t0.Add(time.Minute)
	die := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	die(s.AddClientSample(t0, "alice", 100, 200))
	die(s.AddClientSample(t0, "bob", 10, 20))
	die(s.AddClientSample(t1, "alice", 150, 250)) // bob dropped off between t0 and t1

	global, err := s.Samples(t0.Add(-time.Second))
	if err != nil || len(global) != 2 {
		t.Fatalf("global samples: %+v err=%v", global, err)
	}
	if global[0].Clients != 2 || global[0].BytesRecv != 110 || global[0].BytesSent != 220 {
		t.Fatalf("t0 aggregate wrong: %+v", global[0])
	}
	if global[1].Clients != 1 || global[1].BytesRecv != 150 {
		t.Fatalf("t1 aggregate wrong: %+v", global[1])
	}

	alice, err := s.ClientSamples("alice", t0.Add(-time.Second))
	if err != nil || len(alice) != 2 || alice[1].BytesRecv != 150 {
		t.Fatalf("alice samples: %+v err=%v", alice, err)
	}
	bob, err := s.ClientSamples("bob", t0.Add(-time.Second))
	if err != nil || len(bob) != 1 {
		t.Fatalf("bob samples: %+v err=%v", bob, err)
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
