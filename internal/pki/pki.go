package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// PKI owns dir/{ca.crt, ca.key.enc, crl.pem}; every signing op takes the operator passphrase and never persists it (tier-2 model).
type PKI struct {
	Dir string
}

type IssuedCert struct {
	SerialHex string
	CN        string
	NotAfter  time.Time
	CertPEM   []byte
	KeyPEM    []byte // returned once to caller; never persisted for clients
}

type RevokedEntry struct {
	SerialHex string
	RevokedAt time.Time
}

// MaxCNLen mirrors RFC 5280's CommonName limit (ub-common-name = 64 bytes).
const MaxCNLen = 64

var nameRe = regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9._@-]{1,%d}$`, MaxCNLen))

// CheckName is the one rule for every name ovcp stores (CNs, usernames, upstream ids):
// no space, control or non-ASCII byte, so a name is safe verbatim in commands, files, logs and tables.
func CheckName(what, s string) error {
	if !nameRe.MatchString(s) {
		return fmt.Errorf("%s %q must be 1-%d of A-Z a-z 0-9 . _ @ -", what, s, MaxCNLen)
	}
	return nil
}

func New(dir string) *PKI { return &PKI{Dir: dir} }

// WriteFileAtomic writes data to path the durable way — fsync, rename,
// fsync-the-dir — the one write path for every load-bearing PKI file (CA
// cert/key, server cert/key), so a crash or power loss never leaves one truncated.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	os.Remove(tmp) // clear a stale tmp (crashed prior write, or a symlink) before O_EXCL below
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// best-effort: the rename above already succeeded either way, this only
	// hardens the last mile against power loss, not a correctness requirement.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

func (p *PKI) caCertPath() string { return filepath.Join(p.Dir, "ca.crt") }
func (p *PKI) caKeyPath() string  { return filepath.Join(p.Dir, "ca.key.enc") }

// CRLPath returns the path openvpn should be pointed at via crl-verify.
func (p *PKI) CRLPath() string { return filepath.Join(p.Dir, "crl.pem") }

var ErrCAExists = errors.New("pki: CA already initialized")

// caTemplate is the self-signed CA cert shape shared by InitCA and RenewCA —
// same fields either way, only the key/subject/serial/validity differ.
func caTemplate(subject pkix.Name, serial *big.Int, years int) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// InitCA creates a new ECDSA P-256 CA. Refuses to overwrite.
func (p *PKI) InitCA(cn string, years int, passphrase []byte) error {
	if _, err := os.Stat(p.caCertPath()); err == nil {
		return ErrCAExists
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	tpl := caTemplate(pkix.Name{CommonName: cn}, serial, years)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := sealToFile(p.caKeyPath(), keyDER, passphrase); err != nil {
		return err
	}
	if err := WriteFileAtomic(p.caCertPath(), pemEncode("CERTIFICATE", der), 0o644); err != nil {
		return err
	}
	// empty CRL so crl-verify can be configured from day one
	return p.RegenCRL(nil, passphrase)
}

// RenewCA reissues the CA cert in place with a new serial and extended
// validity, same key — already-issued certs stay valid since only the
// (unchanged) signing key matters for verification. Distinct from Rotate (re-encrypts the key only).
func (p *PKI) RenewCA(years int, passphrase []byte) (*x509.Certificate, error) {
	cur, key, err := p.loadCA(passphrase)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tpl := caTemplate(cur.Subject, serial, years)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(p.caCertPath(), pemEncode("CERTIFICATE", der), 0o644); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CACertPEM returns the CA certificate (public; no passphrase needed).
func (p *PKI) CACertPEM() ([]byte, error) { return os.ReadFile(p.caCertPath()) }

// CACert parses it — public, no passphrase needed, unlike loadCA.
func (p *PKI) CACert() (*x509.Certificate, error) {
	certPEM, err := p.CACertPEM()
	if err != nil {
		return nil, err
	}
	return parseCertPEM(certPEM)
}

func (p *PKI) loadCA(passphrase []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := p.CACertPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: CA not initialized: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := openFromFile(p.caKeyPath(), passphrase)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, ErrBadPassphrase
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("pki: unexpected CA key type")
	}
	return cert, key, nil
}

// CheckPassphrase verifies the operator passphrase without signing anything.
func (p *PKI) CheckPassphrase(passphrase []byte) error {
	_, _, err := p.loadCA(passphrase)
	return err
}

// Rotate re-encrypts the CA key under a new passphrase (CA cert/keypair untouched, no reissuing needed) via temp+rename, so a crash can't corrupt the key file.
func (p *PKI) Rotate(oldPassphrase, newPassphrase []byte) error {
	keyDER, err := openFromFile(p.caKeyPath(), oldPassphrase)
	if err != nil {
		return err
	}
	data, err := Seal(keyDER, newPassphrase)
	if err != nil {
		return err
	}
	return WriteFileAtomic(p.caKeyPath(), data, 0o600)
}

type CertKind int

const (
	KindServer CertKind = iota
	KindClient
)

// Issue creates a keypair + certificate signed by the CA; the private key is returned, not persisted.
func (p *PKI) Issue(kind CertKind, cn string, days int, passphrase []byte) (*IssuedCert, error) {
	if err := CheckName("pki: cn", cn); err != nil {
		return nil, err
	}
	if days <= 0 {
		return nil, errors.New("pki: validity must be at least one day")
	}
	caCert, caKey, err := p.loadCA(passphrase)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	switch kind {
	case KindServer:
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.KeyUsage |= x509.KeyUsageKeyEncipherment
		tpl.DNSNames = []string{cn}
	case KindClient:
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &IssuedCert{
		SerialHex: fmt.Sprintf("%x", serial),
		CN:        cn,
		NotAfter:  tpl.NotAfter,
		CertPEM:   pemEncode("CERTIFICATE", der),
		KeyPEM:    pemEncode("PRIVATE KEY", keyDER),
	}, nil
}

// RegenCRL signs a fresh CRL from the full revoked set (store is source of truth).
func (p *PKI) RegenCRL(revoked []RevokedEntry, passphrase []byte) error {
	caCert, caKey, err := p.loadCA(passphrase)
	if err != nil {
		return err
	}
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		n := new(big.Int)
		if _, ok := n.SetString(r.SerialHex, 16); !ok {
			return fmt.Errorf("pki: bad serial %q", r.SerialHex)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   n,
			RevocationTime: r.RevokedAt,
		})
	}
	now := time.Now()
	tpl := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(10, 0, 0), // long-lived; regenerated on every revoke
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, caCert, caKey)
	if err != nil {
		return err
	}
	return WriteFileAtomic(p.CRLPath(), pemEncode("X509 CRL", der), 0o644)
}

func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func pemEncode(t string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: t, Bytes: der})
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("pki: no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// EncryptKeyPEM wraps a PKCS#8 EC key as a password-protected EC PRIVATE KEY PEM (AES-256-CBC) for OpenVPN's connect-time prompt.
func EncryptKeyPEM(keyPEM []byte, password string) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("pki: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: unexpected key type")
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		return nil, err
	}
	enc, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", sec1,
		[]byte(password), x509.PEMCipherAES256) //nolint:staticcheck // required for OpenVPN-compatible key PEMs
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(enc), nil
}
