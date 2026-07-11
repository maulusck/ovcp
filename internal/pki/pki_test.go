package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

var pass = []byte("correct horse battery staple")

func newCA(t *testing.T) *PKI {
	t.Helper()
	p := New(t.TempDir())
	if err := p.InitCA("OVCP Test CA", 10, pass); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInitCA(t *testing.T) {
	p := newCA(t)
	if err := p.InitCA("again", 1, pass); err != ErrCAExists {
		t.Fatalf("want ErrCAExists, got %v", err)
	}
	if err := p.CheckPassphrase(pass); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckPassphrase([]byte("wrong")); err != ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
}

func TestRotate(t *testing.T) {
	p := newCA(t)
	newPass := []byte("a different passphrase entirely")

	if err := p.Rotate([]byte("wrong"), newPass); err != ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
	if err := p.Rotate(pass, newPass); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckPassphrase(pass); err != ErrBadPassphrase {
		t.Fatalf("old passphrase should no longer work, got %v", err)
	}
	if err := p.CheckPassphrase(newPass); err != nil {
		t.Fatal(err)
	}
	// CA identity survives rotation: issuing still works under the new key.
	if _, err := p.Issue(KindClient, "alice", 365, newPass); err != nil {
		t.Fatal(err)
	}
}

func TestIssueAndVerify(t *testing.T) {
	p := newCA(t)
	ic, err := p.Issue(KindClient, "alice", 365, pass)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := p.CACertPEM()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA pem")
	}
	block, _ := pem.Decode(ic.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if cert.Subject.CommonName != "alice" {
		t.Fatalf("cn = %q", cert.Subject.CommonName)
	}
	if _, err := p.Issue(KindClient, "mallory", 1, []byte("wrong")); err != ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
}

func TestServerCertEKU(t *testing.T) {
	p := newCA(t)
	ic, err := p.Issue(KindServer, "vpn.example.com", 825, pass)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(ic.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	found := false
	for _, e := range cert.ExtKeyUsage {
		if e == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Fatal("server cert missing serverAuth EKU")
	}
}

func TestCRL(t *testing.T) {
	p := newCA(t)
	ic, _ := p.Issue(KindClient, "bob", 30, pass)
	err := p.RegenCRL([]RevokedEntry{{SerialHex: ic.SerialHex, RevokedAt: time.Now()}}, pass)
	if err != nil {
		t.Fatal(err)
	}
	data, err := p.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := parseCertPEM(data)
	crlPEM, err := os.ReadFile(p.CRLPath())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("crl signature: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("revoked entries = %d", len(crl.RevokedCertificateEntries))
	}
}

func TestTLSCryptKeyFormat(t *testing.T) {
	k, err := GenTLSCryptKey()
	if err != nil {
		t.Fatal(err)
	}
	s := string(k)
	if !strings.Contains(s, "BEGIN OpenVPN Static key V1") {
		t.Fatal("missing header")
	}
	lines := 0
	for _, l := range strings.Split(s, "\n") {
		if len(l) == 32 && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "-") {
			lines++
		}
	}
	if lines != 16 {
		t.Fatalf("hex lines = %d, want 16", lines)
	}
}

func TestRenderOVPN(t *testing.T) {
	p := newCA(t)
	ic, _ := p.Issue(KindClient, "carol", 365, pass)
	caPEM, _ := p.CACertPEM()
	tc, _ := GenTLSCryptKey()
	out, err := RenderOVPN(BundleParams{
		Remote: "vpn.example.com", Port: 1194, Proto: "udp",
		CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
		TLSCrypt: tc, Cipher: "AES-256-GCM", ServerCN: "vpn.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote vpn.example.com 1194",
		"proto udp",
		"<ca>", "</ca>", "<cert>", "<key>", "<tls-crypt>",
		"verify-x509-name vpn.example.com name",
		"remote-cert-tls server", "auth-nocache", "data-ciphers-fallback AES-256-GCM",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("missing %q in bundle", want)
		}
	}
}

func TestRenderOVPNRejectsInjection(t *testing.T) {
	if _, err := RenderOVPN(BundleParams{Remote: "vpn.example.com\nauth-user-pass steal.txt", Port: 1194, Proto: "udp"}); err == nil {
		t.Fatal("want error for remote containing newline")
	}
	if _, err := RenderOVPN(BundleParams{Remote: "vpn.example.com", Port: 1194, Proto: "udp", ServerCN: "evil\nup /bin/sh"}); err == nil {
		t.Fatal("want error for server-cn containing newline")
	}
}

func TestEncryptKeyPEM(t *testing.T) {
	p := newCA(t)
	ic, _ := p.Issue(KindClient, "enc", 30, pass)
	enc, err := EncryptKeyPEM(ic.KeyPEM, "profile-pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(enc), "DEK-Info: AES-256-CBC") {
		t.Fatal("not encrypted")
	}
	block, _ := pem.Decode(enc)
	der, err := x509.DecryptPEMBlock(block, []byte("profile-pw")) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseECPrivateKey(der); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.DecryptPEMBlock(block, []byte("wrong")); err == nil {
		t.Fatal("wrong pw must fail")
	}
}
