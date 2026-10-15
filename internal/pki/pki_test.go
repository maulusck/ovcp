package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

// TestWriteFileAtomic covers the happy path (content actually lands, no
// leftover .tmp) and that a stale .tmp from an earlier crashed write never
// blocks a fresh one — WriteFileAtomic removes it before O_EXCL, not the
// other way around.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")

	if err := WriteFileAtomic(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "v1" {
		t.Fatalf("got %q, want v1", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file must not survive a successful write")
	}

	if err := os.WriteFile(path+".tmp", []byte("stale, from a crashed prior write"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("v2"), 0o644); err != nil {
		t.Fatalf("a stale .tmp must not block a fresh write: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "v2" {
		t.Fatalf("got %q, want v2", got)
	}
}

// TestWriteFileAtomicLeavesOriginalOnFailure: if WriteFileAtomic can't even
// create the temp file (here: a read-only directory, standing in for any
// failure before the rename), the original file must be completely
// untouched — the whole point of writing to a temp name first.
func TestWriteFileAtomicLeavesOriginalOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")
	if err := WriteFileAtomic(path, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if err := WriteFileAtomic(path, []byte("new"), 0o644); err == nil {
		t.Fatal("expected an error writing into a read-only directory")
	}
	os.Chmod(dir, 0o700)

	if got, _ := os.ReadFile(path); string(got) != "original" {
		t.Fatalf("original must survive a failed write, got %q", got)
	}
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

// TestRenewCA: the CA cert gets a new serial and extended validity, but the
// key doesn't change — a cert issued before renewal must still verify
// against the renewed CA cert.
func TestRenewCA(t *testing.T) {
	p := newCA(t)
	before, err := p.CACert()
	if err != nil {
		t.Fatal(err)
	}
	ic, err := p.Issue(KindClient, "alice", 365, pass)
	if err != nil {
		t.Fatal(err)
	}
	preCert, err := parseCertPEM(ic.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	renewed, err := p.RenewCA(20, pass)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("RenewCA must issue a fresh serial")
	}
	if !renewed.NotAfter.After(before.NotAfter) {
		t.Fatalf("RenewCA must extend validity: before=%v after=%v", before.NotAfter, renewed.NotAfter)
	}
	if renewed.Subject.CommonName != before.Subject.CommonName {
		t.Fatalf("RenewCA must keep the CA's CN, got %q want %q", renewed.Subject.CommonName, before.Subject.CommonName)
	}

	after, err := p.CACert()
	if err != nil {
		t.Fatal(err)
	}
	if err := preCert.CheckSignatureFrom(after); err != nil {
		t.Fatalf("a cert issued before RenewCA must still verify against the renewed CA (same key): %v", err)
	}

	// same key: issuing still works under the unchanged passphrase.
	if _, err := p.Issue(KindClient, "bob", 365, pass); err != nil {
		t.Fatal(err)
	}

	if _, err := p.RenewCA(20, []byte("wrong")); err != ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
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

// TestIssueCN: the one CN rule (length + charset) is enforced at issuance.
func TestIssueCN(t *testing.T) {
	p := newCA(t)
	for _, cn := range []string{strings.Repeat("a", MaxCNLen), "alice", "bob.laptop", "carol_2@corp.example", "10.0.0.1", "x-y"} {
		if _, err := p.Issue(KindClient, cn, 365, pass); err != nil {
			t.Errorf("%q should be accepted: %v", cn, err)
		}
	}
	for _, cn := range []string{"", strings.Repeat("a", MaxCNLen+1), "a b", "a\nkill b", "a\tb", "ünï", "a,b", `a"b`, "a/b"} {
		if _, err := p.Issue(KindClient, cn, 365, pass); err == nil {
			t.Errorf("%q should be rejected", cn)
		}
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
		"explicit-exit-notify 1",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("missing %q in bundle", want)
		}
	}
	if bytes.Contains(out, []byte("persist-key")) { // inline keys: a no-op, and 2.7 warns
		t.Fatal("persist-key must not be in a profile")
	}
	if bytes.Contains(out, []byte("pull-filter")) {
		t.Fatal("pull-filter must be omitted when SplitTunnel is false")
	}
	tcpOut, err := RenderOVPN(BundleParams{Remote: "vpn.example.com", Port: 1194, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(tcpOut, []byte("explicit-exit-notify")) {
		t.Fatal("explicit-exit-notify is UDP-only — TCP already detects a dropped peer via the OS")
	}
	out, err = RenderOVPN(BundleParams{Remote: "vpn.example.com", Port: 1194, Proto: "udp", SplitTunnel: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`pull-filter ignore "redirect-gateway"`)) {
		t.Fatal("SplitTunnel must add a pull-filter ignoring redirect-gateway")
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
