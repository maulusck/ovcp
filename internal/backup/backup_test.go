package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

const pass = "correct horse battery staple"

// newInstall builds a minimal but realistic ovcp data directory: a real CA,
// a fake tls-crypt key/server.conf (backup only cares about their bytes),
// and a store with one row so the VACUUM INTO snapshot has something in it.
func newInstall(t *testing.T) (dir string, s *store.Store) {
	t.Helper()
	dir = t.TempDir()
	p := pki.New(filepath.Join(dir, "pki"))
	if err := p.InitCA("Test CA", 1, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pki", "tls-crypt.key"), []byte("fake-tls-crypt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.conf"), []byte("fake-server-conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Audit("test", "setup", "marker"); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

func TestRoundTrip(t *testing.T) {
	srcDir, s := newInstall(t)

	var archive bytes.Buffer
	if err := Create(srcDir, s, &archive, []byte(pass)); err != nil {
		t.Fatal(err)
	}

	dstDir := t.TempDir()
	if err := Restore(dstDir, bytes.NewReader(archive.Bytes()), []byte(pass), false); err != nil {
		t.Fatal(err)
	}

	for _, f := range []string{"pki/ca.crt", "pki/ca.key.enc", "pki/crl.pem", "pki/tls-crypt.key", "server.conf", "totp.key", "ovcp.db"} {
		want, err := os.ReadFile(filepath.Join(srcDir, filepath.FromSlash(f)))
		if err != nil && f != "ovcp.db" {
			t.Fatalf("read source %s: %v", f, err)
		}
		got, err := os.ReadFile(filepath.Join(dstDir, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("restored file missing: %s: %v", f, err)
		}
		if f != "ovcp.db" && !bytes.Equal(want, got) {
			t.Fatalf("%s: content mismatch after restore", f)
		}
	}

	// the whole point: no server cert/key ever leaves the machine
	for _, f := range []string{"pki/server.crt", "pki/server.key"} {
		if _, err := os.Stat(filepath.Join(dstDir, filepath.FromSlash(f))); err == nil {
			t.Fatalf("%s should not exist after restore", f)
		}
	}

	// restored db is a real, independent, queryable copy
	rs, err := store.Open(filepath.Join(dstDir, "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	tail, err := rs.AuditTail(10)
	if err != nil || len(tail) == 0 || tail[0].Action != "setup" {
		t.Fatalf("restored db missing expected audit row: tail=%+v err=%v", tail, err)
	}
}

func TestRestoreWrongPassphrase(t *testing.T) {
	srcDir, s := newInstall(t)
	var archive bytes.Buffer
	if err := Create(srcDir, s, &archive, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	err := Restore(t.TempDir(), bytes.NewReader(archive.Bytes()), []byte("wrong"), false)
	if err != pki.ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
}

func TestRestoreRefusesExistingInstall(t *testing.T) {
	srcDir, s := newInstall(t)
	var archive bytes.Buffer
	if err := Create(srcDir, s, &archive, []byte(pass)); err != nil {
		t.Fatal(err)
	}

	dstDir, _ := newInstall(t) // already "initialized"
	if err := Restore(dstDir, bytes.NewReader(archive.Bytes()), []byte(pass), false); err != ErrAlreadyInitialized {
		t.Fatalf("want ErrAlreadyInitialized, got %v", err)
	}
	if err := Restore(dstDir, bytes.NewReader(archive.Bytes()), []byte(pass), true); err != nil {
		t.Fatalf("force restore should succeed, got %v", err)
	}
}

func TestCreateMissingFile(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// no pki/ dir at all -> not a real install
	if err := Create(dir, s, &bytes.Buffer{}, []byte(pass)); err == nil {
		t.Fatal("expected an error backing up an uninitialized data dir")
	}
}
