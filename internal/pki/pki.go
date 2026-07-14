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

// MaxCNLen bounds every CN this package issues a cert for: RFC 5280's own
// upper limit on an X.509 CommonName (ub-common-name = 64 bytes), the type
// a cn here actually is. Enforced once, here, at issuance — the one place
// a CN longer than this could ever come to exist — so every other bound
// downstream (internal/api's stats endpoint, which rejects a ?cn= query
// past this same length) can never see a legitimately-issued CN it treats
// as invalid.
const MaxCNLen = 64

func New(dir string) *PKI { return &PKI{Dir: dir} }

func (p *PKI) caCertPath() string { return filepath.Join(p.Dir, "ca.crt") }
func (p *PKI) caKeyPath() string  { return filepath.Join(p.Dir, "ca.key.enc") }

// CRLPath returns the path openvpn should be pointed at via crl-verify.
func (p *PKI) CRLPath() string { return filepath.Join(p.Dir, "crl.pem") }

var ErrCAExists = errors.New("pki: CA already initialized")

// InitCA creates a new ECDSA P-256 CA. Refuses to overwrite.
func (p *PKI) InitCA(cn string, years int, passphrase []byte) error {
	if _, err := os.Stat(p.caCertPath()); err == nil {
		return ErrCAExists
	}
	// 0701, not 0700: openvpn re-stats crl.pem on every handshake after
	// dropping to an unprivileged user (ovpnconf's user/group directives),
	// so this dir needs traversal for "other" — the private keys inside
	// stay protected by their own 0600, regardless of the dir's bits.
	if err := os.MkdirAll(p.Dir, 0o701); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
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
	if err := os.WriteFile(p.caCertPath(), pemEncode("CERTIFICATE", der), 0o644); err != nil {
		return err
	}
	// Start with an empty CRL so openvpn can be configured with crl-verify
	// from day one.
	return p.RegenCRL(nil, passphrase)
}

// CACertPEM returns the CA certificate (public; no passphrase needed).
func (p *PKI) CACertPEM() ([]byte, error) { return os.ReadFile(p.caCertPath()) }

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
	tmp := p.caKeyPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.caKeyPath())
}

type CertKind int

const (
	KindServer CertKind = iota
	KindClient
)

// Issue creates a keypair + certificate signed by the CA.
// The private key is generated here and returned; it is the caller's job to
// hand it to the operator (client bundle) or write it for openvpn (server).
func (p *PKI) Issue(kind CertKind, cn string, days int, passphrase []byte) (*IssuedCert, error) {
	if n := len(cn); n == 0 || n > MaxCNLen {
		return nil, fmt.Errorf("pki: cn must be 1-%d bytes, got %d", MaxCNLen, n)
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

// RegenCRL signs a fresh CRL covering all given revocations.
// Callers pass the full revoked set from the store (source of truth).
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
	return os.WriteFile(p.CRLPath(), pemEncode("X509 CRL", der), 0o644)
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

// EncryptKeyPEM converts an unencrypted PKCS#8 EC key PEM into a
// password-protected "EC PRIVATE KEY" PEM (AES-256-CBC, OpenVPN/OpenSSL
// compatible). OpenVPN prompts for the password on connect.
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
