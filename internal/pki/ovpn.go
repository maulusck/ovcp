package pki

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// GenTLSCryptKey produces a 2048-bit OpenVPN static key (V1 format),
// byte-compatible with `openvpn --genkey secret`.
func GenTLSCryptKey() ([]byte, error) {
	raw := make([]byte, 256)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key (OVCP)\n#\n")
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	h := hex.EncodeToString(raw)
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return []byte(b.String()), nil
}

// BundleParams describes everything needed for an inline client profile.
type BundleParams struct {
	Remote     string // host or IP clients connect to
	Port       int
	Proto      string // "udp" | "tcp"
	CACertPEM  []byte
	ClientCert []byte
	ClientKey  []byte
	TLSCrypt   []byte // static key, V1 format
	Cipher     string // e.g. "AES-256-GCM"
	ServerCN   string // optional: verify-x509-name

	// SplitTunnel: keep this client's own default route, ignore only the
	// pushed redirect-gateway. Meaningful only if the server pushes one.
	SplitTunnel bool
	Extra       string // raw client directives, appended verbatim; unvalidated by design
}

// RenderOVPN emits a single-file .ovpn; Remote/ServerCN are unescaped, so newlines there would inject config lines.
func RenderOVPN(p BundleParams) ([]byte, error) {
	if strings.ContainsAny(p.Remote, "\r\n") || strings.ContainsAny(p.ServerCN, "\r\n") {
		return nil, errors.New("pki: invalid character in remote/server-cn")
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("client")
	w("dev tun")
	w("proto %s", p.Proto)
	w("remote %s %d", p.Remote, p.Port)
	w("resolv-retry infinite")
	w("nobind")
	w("persist-tun")
	w("remote-cert-tls server")
	if p.Proto == "udp" {
		w("explicit-exit-notify 1") // tells the server we're gone instead of waiting out ping-restart
	}
	if p.ServerCN != "" {
		w("verify-x509-name %s name", p.ServerCN)
	}
	w("data-ciphers %s", p.Cipher)
	w("data-ciphers-fallback %s", p.Cipher) // silences the BF-CBC note
	w("auth-nocache")
	w("verb 3")
	if p.SplitTunnel {
		w(`pull-filter ignore "redirect-gateway"`)
	}
	if extra := strings.TrimSpace(p.Extra); extra != "" {
		w("# --- custom options ---")
		w("%s", extra)
	}
	inline := func(tag string, body []byte) {
		w("<%s>", tag)
		b.Write(body)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			b.WriteByte('\n')
		}
		w("</%s>", tag)
	}
	inline("ca", p.CACertPEM)
	inline("cert", p.ClientCert)
	inline("key", p.ClientKey)
	if len(p.TLSCrypt) > 0 {
		inline("tls-crypt", p.TLSCrypt)
	}
	return []byte(b.String()), nil
}
