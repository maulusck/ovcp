package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/telegram"
)

// writeSoonExpiringCA plants a self-signed cert at the path PKI.CACert reads,
// inside store.ExpiryWarnDays — the CA is never a certs-table row, so this is
// the only way to exercise "the CA itself is about to expire" without waiting years.
func writeSoonExpiringCA(t *testing.T, dir, cn string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().AddDate(0, 0, -1),
		NotAfter:     time.Now().AddDate(0, 0, store.ExpiryWarnDays-1),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSweepExpiringIncludesCA: the CA is never a certs-table row, so
// sweepExpiring must fold it in as a synthetic entry — regression for that
// blind spot, and for the sweep living in cmd/ovcp (polling), not the
// telegram package (just the notification sink).
func TestSweepExpiringIncludesCA(t *testing.T) {
	var notified []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendMessage") {
			var body struct{ Text string }
			json.NewDecoder(r.Body).Decode(&body)
			notified = append(notified, body.Text)
		}
		w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true}}`))
	}))
	defer srv.Close()
	defer telegram.SetAPIBaseForTesting(srv.URL + "/bot")()

	dir := t.TempDir()
	s, _ := store.Open(filepath.Join(dir, "ovcp.db"))
	defer s.Close()
	telegram.SetToken(s, "t")
	telegram.SetAdmin(s, "555")
	tg := telegram.New(s, nil, nil, nil)

	p := pki.New(filepath.Join(dir, "pki"))
	writeSoonExpiringCA(t, filepath.Join(dir, "pki"), "OVCP CA")

	sweepExpiring(s, p, tg)

	found := false
	for _, n := range notified {
		if strings.Contains(n, "OVCP") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a notification mentioning the CA, got %v", notified)
	}
}
