package ovpnconf

import (
	"strings"
	"testing"
)

func valid() Config {
	c := Default()
	c.DNS = []string{"1.1.1.1"}
	c.Routes = []string{"192.168.10.0/24"}
	c.CACert, c.ServerCert, c.ServerKey = "/d/ca.crt", "/d/s.crt", "/d/s.key"
	c.CRL, c.TLSCrypt = "/d/crl.pem", "/d/tc.key"
	c.MgmtSocket, c.StatusLog = "/run/ovcp/mgmt.sock", "/run/ovcp/status.log"
	return c
}

func TestValidate(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*Config){
		func(c *Config) { c.Proto = "sctp" },
		func(c *Config) { c.Port = 0 },
		func(c *Config) { c.Cipher = "DES" },
		func(c *Config) { c.Subnet = "10.8.0.0" },
		func(c *Config) { c.DNS = []string{"nope"} },
		func(c *Config) { c.Routes = []string{"bad/99"} },
	} {
		bad := valid()
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("mutation should fail: %+v", bad)
		}
	}
}

func TestRender(t *testing.T) {
	c := valid()
	out := string(c.Render())
	for _, want := range []string{
		"proto udp", "port 1194", "server 10.8.0.0 255.255.255.0",
		"dev tun", "topology subnet", "dh none", "disable-dco", "data-ciphers AES-256-GCM", "data-ciphers-fallback AES-256-GCM",
		"crl-verify /d/crl.pem", "tls-crypt /d/tc.key",
		"management /run/ovcp/mgmt.sock unix", "status-version 3",
		`push "redirect-gateway def1 bypass-dhcp"`,
		`push "dhcp-option DNS 1.1.1.1"`,
		`push "route 192.168.10.0 255.255.255.0"`,
		"explicit-exit-notify 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q\n%s", want, out)
		}
	}
	c.Proto = "tcp"
	if strings.Contains(string(c.Render()), "explicit-exit-notify") {
		t.Fatal("exit-notify must be udp-only")
	}
	c.RunAsUser = ""
	if strings.Contains(string(c.Render()), "\nuser ") {
		t.Fatal("empty RunAsUser must omit the user/group lines")
	}
}

// TestPushInternalDNSFirst: the internal resolver must be pushed before any
// manual entry, so internal-name queries never reach a resolver that'll
// NXDOMAIN them before dnsmasq gets a chance — see Render's DNS block.
func TestPushInternalDNSFirst(t *testing.T) {
	c := valid()
	c.PushInternalDNS = true
	out := string(c.Render())
	internal := strings.Index(out, `push "dhcp-option DNS 10.8.0.1"`)
	manual := strings.Index(out, `push "dhcp-option DNS 1.1.1.1"`)
	if internal < 0 || manual < 0 || internal > manual {
		t.Fatalf("want internal DNS pushed before manual entries, got:\n%s", out)
	}
	c.PushInternalDNS = false
	if strings.Contains(string(c.Render()), `dhcp-option DNS 10.8.0.1`) {
		t.Fatal("PushInternalDNS off must not push the tun IP")
	}
}

func TestRenderExtra(t *testing.T) {
	c := valid()
	if strings.Contains(string(c.Render()), "custom options") {
		t.Fatal("empty Extra must not add the custom-options marker")
	}
	c.Extra = "client-to-client"
	out := string(c.Render())
	if !strings.Contains(out, "custom options") || !strings.Contains(out, "client-to-client") {
		t.Fatalf("Extra must be appended verbatim\n%s", out)
	}
}

func TestServerTunIP(t *testing.T) {
	c := valid()
	ip, err := c.ServerTunIP()
	if err != nil || ip.String() != "10.8.0.1" {
		t.Fatalf("ServerTunIP() = %v, %v; want 10.8.0.1", ip, err)
	}
	c.Subnet = "not-a-cidr"
	if _, err := c.ServerTunIP(); err == nil {
		t.Fatal("bad subnet must error")
	}
}

func TestDomainSearchPush(t *testing.T) {
	c := valid()
	c.ServerCN = "ovcp.example.com"
	c.PushInternalDNS = true
	out := string(c.Render())
	if !strings.Contains(out, `push "dhcp-option DOMAIN example.com"`) {
		t.Fatalf("expected DOMAIN push for a dotted CN\n%s", out)
	}
	if !strings.Contains(out, `push "dhcp-option DOMAIN-SEARCH example.com"`) {
		t.Fatalf("expected DOMAIN-SEARCH push for a dotted CN\n%s", out)
	}

	c.ServerCN = "ovcp"
	out = string(c.Render())
	if strings.Contains(out, "DOMAIN") {
		t.Fatalf("bare shortname CN must not push DOMAIN/DOMAIN-SEARCH\n%s", out)
	}

	// PushInternalDNS off: pushing the domain would leak internal hostnames
	// to a resolver clients were never told to use for DNS.
	c.ServerCN = "ovcp.example.com"
	c.PushInternalDNS = false
	out = string(c.Render())
	if strings.Contains(out, "DOMAIN") {
		t.Fatalf("PushInternalDNS off must not push DOMAIN/DOMAIN-SEARCH\n%s", out)
	}
}

func TestCanSplitTunnel(t *testing.T) {
	c := valid()
	c.RedirectGW = false
	if c.CanSplitTunnel() {
		t.Fatal("no split-tunnel without a server redirect to opt out of")
	}
	c.RedirectGW = true
	if !c.CanSplitTunnel() {
		t.Fatal("split-tunnel should be allowed once the server redirects")
	}
}

func TestDiff(t *testing.T) {
	c := valid()
	same := Diff(c.Render(), c.Render())
	if len(same) != 0 {
		t.Fatalf("identical renders should diff empty, got %v", same)
	}

	changed := valid()
	changed.Port = 443
	d := Diff(c.Render(), changed.Render())
	want := []string{"-port 1194", "+port 443"}
	if len(d) != len(want) || d[0] != want[0] || d[1] != want[1] {
		t.Fatalf("port change diff = %v, want %v", d, want)
	}

	added := valid()
	added.DNS = append(added.DNS, "8.8.8.8")
	d = Diff(c.Render(), added.Render())
	want = []string{`+push "dhcp-option DNS 8.8.8.8"`}
	if len(d) != 1 || d[0] != want[0] {
		t.Fatalf("added DNS diff = %v, want %v", d, want)
	}
}

func TestLoadCorrupt(t *testing.T) {
	if c := Load("{corrupt"); c.Port != Default().Port || c.Proto != Default().Proto {
		t.Fatalf("corrupt JSON must fall back to defaults, got %+v", c)
	}
}

// TestDefaultEnvOverrides: OVCP_OPENVPN_* seeds every setting Default()
// returns — the one-shot container/non-attended init path.
func TestDefaultEnvOverrides(t *testing.T) {
	for k, v := range map[string]string{
		"OVCP_OPENVPN_PROTO":       "tcp",
		"OVCP_OPENVPN_PORT":        "51820",
		"OVCP_OPENVPN_SUBNET":      "10.9.0.0/24",
		"OVCP_OPENVPN_CIPHER":      "CHACHA20-POLY1305",
		"OVCP_OPENVPN_DNS":         "1.1.1.1, 9.9.9.9",
		"OVCP_OPENVPN_ROUTES":      "192.168.1.0/24",
		"OVCP_OPENVPN_REDIRECT_GW": "false",
		"OVCP_OPENVPN_EXTRA":       "client-to-client",
	} {
		t.Setenv(k, v)
	}
	c := Default()
	if c.Proto != "tcp" || c.Port != 51820 || c.Subnet != "10.9.0.0/24" || c.Cipher != "CHACHA20-POLY1305" {
		t.Fatalf("scalar env overrides not applied: %+v", c)
	}
	if len(c.DNS) != 2 || c.DNS[0] != "1.1.1.1" || c.DNS[1] != "9.9.9.9" {
		t.Fatalf("DNS env override not applied: %+v", c.DNS)
	}
	if len(c.Routes) != 1 || c.Routes[0] != "192.168.1.0/24" {
		t.Fatalf("Routes env override not applied: %+v", c.Routes)
	}
	if c.RedirectGW {
		t.Fatal("OVCP_OPENVPN_REDIRECT_GW=false must disable RedirectGW")
	}
	if c.Extra != "client-to-client" {
		t.Fatalf("Extra env override not applied: %q", c.Extra)
	}
}

// TestDefaultPortEnvInvalid: an unparseable port must fall back to the
// hardcoded default, not zero it out or crash.
func TestDefaultPortEnvInvalid(t *testing.T) {
	t.Setenv("OVCP_OPENVPN_PORT", "not-a-number")
	if c := Default(); c.Port != 1194 {
		t.Fatalf("invalid OVCP_OPENVPN_PORT should fall back to 1194, got %d", c.Port)
	}
}

func TestSplitCSV(t *testing.T) {
	if got := SplitCSV(""); got != nil {
		t.Fatalf("empty string should split to nil, got %v", got)
	}
	if got := SplitCSV("1.1.1.1, 9.9.9.9 ,  "); len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "9.9.9.9" {
		t.Fatalf("want [1.1.1.1 9.9.9.9] with whitespace/empties trimmed, got %v", got)
	}
}
