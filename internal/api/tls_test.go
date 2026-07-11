package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeExpiredAdminCert plants a pre-expired self-signed cert at the paths
// EnsureAdminTLS reads, so we can exercise the "past NotAfter" regeneration
// branch without waiting five years.
func writeExpiredAdminCert(t *testing.T, dir, cn string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().Add(-time.Hour), // already expired
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(filepath.Join(dir, "admin.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "admin.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAdminTLSRegeneratesExpired(t *testing.T) {
	dir := t.TempDir()
	writeExpiredAdminCert(t, dir, "vpn.example.com")

	cp, _, err := EnsureAdminTLS(dir, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cp)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !time.Now().Before(c.NotAfter) {
		t.Fatalf("cert still expired after EnsureAdminTLS: NotAfter=%v", c.NotAfter)
	}
}
