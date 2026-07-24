package api

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
)

func TestCertsHostsContent(t *testing.T) {
	now := time.Now()
	revokedAt := now
	certs := []store.Cert{
		{CN: "ovcp.example.com", Kind: "server", IncludeDNS: true},
		{CN: "alice", Kind: "client", IncludeDNS: true},                        // connected, included -> line
		{CN: "bob", Kind: "client", IncludeDNS: false},                         // connected, excluded -> no line
		{CN: "carol", Kind: "client", IncludeDNS: true, RevokedAt: &revokedAt}, // connected, revoked -> no line
		{CN: "dave", Kind: "client", IncludeDNS: true},                         // included but disconnected -> no line
	}
	live := []controller.VPNClient{
		{CN: "alice", VirtualAddress: "10.8.0.2"},
		{CN: "bob", VirtualAddress: "10.8.0.3"},
		{CN: "carol", VirtualAddress: "10.8.0.4"},
	}
	serverIP := net.ParseIP("10.8.0.1")

	out := string(CertsHostsContent(certs, live, "ovcp.example.com", serverIP))

	// alice's CN has no dot, but the server CN's domain (example.com) is
	// known, so alice still gets a resolvable FQDN, not just the shortname.
	mustContain := []string{"10.8.0.1 ovcp.example.com ovcp", "10.8.0.2 alice.example.com alice"}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q\n%s", want, out)
		}
	}
	mustNotContain := []string{"bob", "carol", "dave"}
	for _, unwanted := range mustNotContain {
		if strings.Contains(out, unwanted) {
			t.Fatalf("unexpected %q in output\n%s", unwanted, out)
		}
	}
}

func TestHostAliases(t *testing.T) {
	cases := []struct{ cn, domain, want string }{
		{"alice.example.com", "", "alice.example.com alice"},          // already FQDN: add its shortname
		{"alice.example.com", "other.com", "alice.example.com alice"}, // own domain wins over the server's
		{"alice", "example.com", "alice.example.com alice"},           // bare + known server domain: synthesize FQDN
		{"alice", "", "alice"},                                        // bare, no domain anywhere: nothing to add
	}
	for _, c := range cases {
		if got := hostAliases(c.cn, c.domain); got != c.want {
			t.Fatalf("hostAliases(%q, %q) = %q, want %q", c.cn, c.domain, got, c.want)
		}
	}
}

// TestCertsHostsContentDualResolution: an FQDN CN gets both forms on one
// line (dual resolution), never a second, duplicate line for the shortname.
func TestCertsHostsContentDualResolution(t *testing.T) {
	certs := []store.Cert{{CN: "alice.example.com", Kind: "client", IncludeDNS: true}}
	live := []controller.VPNClient{{CN: "alice.example.com", VirtualAddress: "10.8.0.2"}}

	out := string(CertsHostsContent(certs, live, "", nil))
	want := "10.8.0.2 alice.example.com alice\n"
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q\n%s", want, out)
	}
	if strings.Count(out, "10.8.0.2") != 1 {
		t.Fatalf("expected exactly one line for alice, got\n%s", out)
	}
}

func TestCertsHostsContentBareShortname(t *testing.T) {
	certs := []store.Cert{{CN: "ovcp", Kind: "server", IncludeDNS: true}}
	out := string(CertsHostsContent(certs, nil, "ovcp", net.ParseIP("10.8.0.1")))
	if !strings.Contains(out, "10.8.0.1 ovcp\n") {
		t.Fatalf("bare shortname CN must still get its one line\n%s", out)
	}
}

func TestCertsHostsContentNoServer(t *testing.T) {
	out := string(CertsHostsContent(nil, nil, "", nil))
	if strings.Contains(out, "\n10.8.0.1") || strings.Count(out, "\n") != 1 {
		t.Fatalf("empty server CN/IP must produce only the header comment\n%q", out)
	}
}

func TestWriteAtomicHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "certs.hosts")

	if err := WriteAtomicHosts(path, []byte("10.8.0.1 ovcp\n"), -1); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "10.8.0.1 ovcp\n" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
	}

	// second write replaces the file wholesale (rename-over), not append.
	if err := WriteAtomicHosts(path, []byte("10.8.0.1 ovcp\n10.8.0.2 alice\n"), -1); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "10.8.0.1 ovcp\n10.8.0.2 alice\n" {
		t.Fatalf("got %q after second write", got)
	}

	// no leftover temp file
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly the final file, got %v", entries)
	}
}
