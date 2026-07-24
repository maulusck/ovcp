package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/pki"
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

// TestCertIncludeDNS: CertFrom defaults IncludeDNS true, and SetCertDNS
// round-trips both directions.
func TestCertIncludeDNS(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ic := &pki.IssuedCert{SerialHex: "dns1", CN: "carol", CertPEM: []byte("PEM"), NotAfter: time.Now().AddDate(1, 0, 0)}
	c := CertFrom(ic, "client")
	if !c.IncludeDNS {
		t.Fatal("CertFrom must default IncludeDNS true")
	}
	if err := s.AddCert(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCert("dns1")
	if err != nil || !got.IncludeDNS {
		t.Fatalf("get after add: %+v err=%v, want IncludeDNS=true", got, err)
	}

	if err := s.SetCertDNS("dns1", false); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetCert("dns1")
	if err != nil || got.IncludeDNS {
		t.Fatalf("get after exclude: %+v err=%v, want IncludeDNS=false", got, err)
	}

	if err := s.SetCertDNS("dns1", true); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetCert("dns1")
	if err != nil || !got.IncludeDNS {
		t.Fatalf("get after re-include: %+v err=%v, want IncludeDNS=true", got, err)
	}

	if err := s.SetCertDNS("nonexistent", true); err == nil {
		t.Fatal("SetCertDNS on an unknown serial must error")
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

// TestClientSamples: bob disconnects between t0 and t1; the global rate must
// reflect only alice's delta, not dip because bob dropped out.
func TestClientSamples(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Now().Add(-time.Minute).Truncate(time.Second)
	t1 := t0.Add(time.Minute) // exactly 60s later, so /60 divides cleanly below
	die := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	die(s.AddClientSample(t0, "alice", 1000, 2000))
	die(s.AddClientSample(t0, "bob", 500, 1000))
	die(s.AddClientSample(t1, "alice", 7000, 5000)) // +6000/+3000; bob gone

	global, err := s.Samples(t0.Add(-time.Second))
	if err != nil || len(global) != 2 {
		t.Fatalf("global samples: %+v err=%v", global, err)
	}
	if global[0].Clients != 2 || global[0].BytesRecv != 1500 || global[0].BytesSent != 3000 ||
		global[0].BytesRecvRate != 0 || global[0].BytesSentRate != 0 {
		t.Fatalf("t0 aggregate wrong (first sample must have rate 0): %+v", global[0])
	}
	if global[1].Clients != 1 || global[1].BytesRecv != 7000 || global[1].BytesSent != 5000 {
		t.Fatalf("t1 aggregate volume wrong: %+v", global[1])
	}
	if global[1].BytesRecvRate != 100 || global[1].BytesSentRate != 50 {
		t.Fatalf("t1 rate should be alice's delta only (6000/60=100, 3000/60=50), not a dip from bob leaving: %+v", global[1])
	}

	alice, err := s.ClientSamples("alice", t0.Add(-time.Second))
	if err != nil || len(alice) != 2 || alice[1].BytesRecv != 7000 || alice[1].BytesRecvRate != 100 {
		t.Fatalf("alice samples: %+v err=%v", alice, err)
	}
	bob, err := s.ClientSamples("bob", t0.Add(-time.Second))
	if err != nil || len(bob) != 1 || bob[0].BytesRecvRate != 0 {
		t.Fatalf("bob samples (single sample, no baseline yet): %+v err=%v", bob, err)
	}
}

func TestRate(t *testing.T) {
	cases := []struct {
		prev, cur uint64
		dt        time.Duration
		want      uint64
	}{
		{100, 700, time.Minute, 10}, // +600 over 60s
		{700, 100, time.Minute, 0},  // counter reset (reconnect) — clamp, not negative
		{100, 100, time.Minute, 0},  // no change
		{100, 700, 0, 0},            // no elapsed time — can't divide
	}
	for _, c := range cases {
		if got := Rate(c.prev, c.cur, c.dt); got != c.want {
			t.Errorf("Rate(%d, %d, %v) = %d, want %d", c.prev, c.cur, c.dt, got, c.want)
		}
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

func TestAuditHook(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()
	var got []string
	s.OnAudit(func(actor, action, detail string) { got = append(got, actor+" "+action+" "+detail) })
	s.Audit("admin", "revoke", "serial=abc")
	if len(got) != 1 || got[0] != "admin revoke serial=abc" {
		t.Fatalf("hook not fired correctly: %v", got)
	}
}
