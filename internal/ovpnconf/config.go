// Package ovpnconf renders and validates the openvpn server config.
package ovpnconf

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNoRedirect: split-tunnel has nothing to opt out of unless the server
// redirects all traffic. One check, shared by the CLI and the API.
var ErrNoRedirect = errors.New("server doesn't redirect all traffic; nothing to split")

// CanSplitTunnel reports whether a client may opt out of the server's redirect.
func (c Config) CanSplitTunnel() bool { return c.RedirectGW }

type Config struct {
	Proto           string   // udp|tcp
	Port            int      // 1-65535
	Subnet          string   // CIDR, e.g. 10.8.0.0/24
	Cipher          string   // from allowedCiphers
	DNS             []string // pushed resolvers (admin's own, additive)
	PushInternalDNS bool     // also push the server's own tun IP, first — see ServerTunIP
	Routes          []string // pushed routes, CIDR
	RedirectGW      bool     // push redirect-gateway
	Extra           string   // raw directives, appended verbatim; unvalidated by design

	// paths (filled by the app from its data dir)
	CACert, ServerCert, ServerKey, CRL, TLSCrypt, MgmtSocket, StatusLog string
	ServerCN                                                            string // admin cert CN; drives DOMAIN-SEARCH push (Records tab)

	// StatusInterval: seconds between openvpn rewriting StatusLog. Server-owned
	// like the paths above (from OVCP_STATUS_INTERVAL, see fillPaths), never
	// user-editable — see EffectiveStatusInterval for the <=0 fallback.
	StatusInterval int

	// ManagementClientAuth: server-owned, set true only when the upstream
	// feature has a per-CN assignment — never a user-editable field.
	ManagementClientAuth bool
}

// defaultStatusInterval is EffectiveStatusInterval's fallback when
// StatusInterval isn't set — keeps a rendered config always valid even from
// a Default()/stale-JSON Config that never went through fillPaths.
const defaultStatusInterval = 3

// EffectiveStatusInterval is StatusInterval with defaultStatusInterval
// applied — the one source of truth Render and the /api/me poll-cadence
// field both use, so they can't disagree about what "unset" means.
func (c Config) EffectiveStatusInterval() int {
	if c.StatusInterval <= 0 {
		return defaultStatusInterval
	}
	return c.StatusInterval
}

// ServerTunIP returns the server's own address within Subnet — OpenVPN's own
// "server takes network+1" convention, same one Render's "server %s %s" line
// relies on. Used for certs.hosts' server line (Records tab).
func (c Config) ServerTunIP() (net.IP, error) {
	_, ipnet, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return nil, fmt.Errorf("ovpnconf: subnet: %w", err)
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("ovpnconf: subnet must be IPv4")
	}
	server := make(net.IP, len(ip))
	copy(server, ip)
	server[len(server)-1]++
	return server, nil
}

// Default seeds every server setting from its OVCP_OPENVPN_* env var
// (container/unattended init), falling back to the hardcoded default. Only
// consulted before anything's persisted — after the first save, `config set` is the override path.
func Default() Config {
	return Config{
		Proto:      cmp.Or(os.Getenv("OVCP_OPENVPN_PROTO"), "udp"),
		Port:       EnvInt("OVCP_OPENVPN_PORT", 1194),
		Subnet:     cmp.Or(os.Getenv("OVCP_OPENVPN_SUBNET"), "10.8.0.0/24"),
		Cipher:     cmp.Or(os.Getenv("OVCP_OPENVPN_CIPHER"), "AES-256-GCM"),
		DNS:        SplitCSV(os.Getenv("OVCP_OPENVPN_DNS")),
		Routes:     SplitCSV(os.Getenv("OVCP_OPENVPN_ROUTES")),
		RedirectGW: os.Getenv("OVCP_OPENVPN_REDIRECT_GW") != "false",
		Extra:      os.Getenv("OVCP_OPENVPN_EXTRA"),
	}
}

// EnvInt reads key as an int, falling back to def if unset or unparseable —
// shared by every package that seeds a Default() from OVCP_* env vars.
func EnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// SplitCSV splits a comma-separated list, trimming whitespace and dropping
// empty entries — shared by env-var and CLI flag parsing (DNS, Routes).
func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Load parses a persisted config JSON blob, falling back to defaults for
// anything empty or missing; raw == "" returns plain Default().
func Load(raw string) Config {
	cfg := Default()
	if raw != "" {
		json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

var allowedCiphers = map[string]bool{
	"AES-256-GCM": true, "AES-128-GCM": true, "CHACHA20-POLY1305": true,
}

func (c *Config) Validate() error {
	if c.Proto != "udp" && c.Proto != "tcp" {
		return fmt.Errorf("ovpnconf: proto must be udp or tcp")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("ovpnconf: port out of range")
	}
	if !allowedCiphers[c.Cipher] {
		return fmt.Errorf("ovpnconf: cipher %q not allowed", c.Cipher)
	}
	if _, _, err := net.ParseCIDR(c.Subnet); err != nil {
		return fmt.Errorf("ovpnconf: subnet: %w", err)
	}
	for _, d := range c.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("ovpnconf: bad DNS ip %q", d)
		}
	}
	for _, r := range c.Routes {
		if _, _, err := net.ParseCIDR(r); err != nil {
			return fmt.Errorf("ovpnconf: route %q: %w", r, err)
		}
	}
	return nil
}

// Render emits server.conf. Assumes Validate passed.
func (c *Config) Render() []byte {
	ip, ipnet, _ := net.ParseCIDR(c.Subnet)
	mask := net.IP(ipnet.Mask).String()
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("# generated by ovcp — do not edit; changes are overwritten")
	w("proto %s", c.Proto)
	w("port %d", c.Port)
	w("dev %s", TunDev)
	w("dev-type tun")
	w("topology subnet")
	w("server %s %s", ip.Mask(ipnet.Mask), mask)
	w("ca %s", c.CACert)
	w("cert %s", c.ServerCert)
	w("key %s", c.ServerKey)
	w("crl-verify %s", c.CRL)
	w("tls-crypt %s", c.TLSCrypt)
	w("dh none") // EC only
	// DCO breaks mgmt status polling after privilege drop (dco_get_peer
	// netlink → EPERM → forced session restarts). Requires OpenVPN 2.6+.
	w("disable-dco")
	w("data-ciphers %s", c.Cipher)
	w("data-ciphers-fallback %s", c.Cipher)
	w("auth SHA256")
	w("keepalive 10 60")
	// persist-key/-tun: keep the tun device and key across SIGUSR1.
	w("persist-key")
	w("persist-tun")
	w("management %s unix", c.MgmtSocket)
	if c.ManagementClientAuth {
		w("management-client-auth")
		// hibernates admission until connect() sends "hold release" —
		// closes the race where a client could get admitted before ovcp
		// reattaches after a restart.
		w("management-hold")
		// clients are cert-only and never send credentials — without this,
		// deferred auth's shared user/pass code path rejects every client
		// with "Auth Username/Password was not provided by peer".
		w("auth-user-pass-optional")
	}
	w("status %s %d", c.StatusLog, c.EffectiveStatusInterval())
	w("status-version 3")
	w("verb 3")
	w("suppress-timestamps") // Supervisor's own logLines stamps every line instead
	if c.RedirectGW {
		w(`push "redirect-gateway def1 bypass-dhcp"`)
	}
	// internal resolver first: queries for our own hostnames must reach it
	// before any other pushed resolver gets a chance to NXDOMAIN them.
	if c.PushInternalDNS {
		if ip, err := c.ServerTunIP(); err == nil {
			w(`push "dhcp-option DNS %s"`, ip)
		}
	}
	for _, d := range c.DNS {
		w(`push "dhcp-option DNS %s"`, d)
	}
	// Gated on PushInternalDNS: without it a client's search suffix would still
	// gain our domain, leaking internal hostnames to its own resolver. Both
	// DOMAIN+DOMAIN-SEARCH pushed: no single option covers every client.
	if domain := Domain(c.ServerCN); c.PushInternalDNS && domain != "" {
		w(`push "dhcp-option DOMAIN %s"`, domain)
		w(`push "dhcp-option DOMAIN-SEARCH %s"`, domain)
	}
	for _, r := range c.Routes {
		rip, rnet, _ := net.ParseCIDR(r)
		w(`push "route %s %s"`, rip.Mask(rnet.Mask), net.IP(rnet.Mask))
	}
	if c.Proto == "udp" {
		w("explicit-exit-notify 1")
	}
	if extra := strings.TrimSpace(c.Extra); extra != "" {
		w("# --- custom options ---")
		w("%s", extra)
	}
	return []byte(b.String())
}

// TunDev is the tunnel interface openvpn creates: a fixed, ovcp-owned name,
// so VPN traffic can be identified by the interface it arrives on.
const TunDev = "ovcp0"

// Domain returns a hostname CN's parent domain ("vpn.example.com" →
// "example.com"); a single label or an IP address has none.
func Domain(cn string) string {
	if net.ParseIP(cn) != nil {
		return ""
	}
	_, domain, _ := strings.Cut(cn, ".")
	return domain
}

// Diff is an ordered line diff (longest common subsequence): "-" lines only
// in old, "+" only in new; empty exactly when the line sequences match.
func Diff(old, new []byte) []string {
	a := strings.Split(strings.TrimRight(string(old), "\n"), "\n")
	b := strings.Split(strings.TrimRight(string(new), "\n"), "\n")
	lcs := make([][]int, len(a)+1) // lcs[i][j]: LCS length of a[i:] and b[j:]
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	for i, j := 0, 0; i < len(a) || j < len(b); {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			out, i = append(out, "-"+a[i]), i+1
		default:
			out, j = append(out, "+"+b[j]), j+1
		}
	}
	return out
}

// WriteAtomic renders and installs the config via tmp+rename.
func (c *Config) WriteAtomic(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), ".server.conf.tmp")
	if err := os.WriteFile(tmp, c.Render(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
