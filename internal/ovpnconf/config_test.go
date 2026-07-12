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
		"topology subnet", "dh none", "disable-dco", "data-ciphers AES-256-GCM", "data-ciphers-fallback AES-256-GCM",
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

func TestLoadCorrupt(t *testing.T) {
	if c := Load("{corrupt"); c.Port != Default().Port || c.Proto != Default().Proto {
		t.Fatalf("corrupt JSON must fall back to defaults, got %+v", c)
	}
}
