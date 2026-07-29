package api

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
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

// TestWriteAtomicHostsSkipsUnchangedWrite: a rename() is what fires dnsmasq's
// inotify watch, so an identical rewrite must never reach it — proven via
// mtime, since a real rename always replaces the file (and its mtime) even
// when the bytes are the same.
func TestWriteAtomicHostsSkipsUnchangedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "certs.hosts")
	data := []byte("10.8.0.1 ovcp\n")

	if err := WriteAtomicHosts(path, data, -1); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	if err := WriteAtomicHosts(path, data, -1); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Fatalf("identical content must skip the rename, mtime changed to %v", fi.ModTime())
	}

	if err := WriteAtomicHosts(path, []byte("10.8.0.1 ovcp\n10.8.0.2 alice\n"), -1); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.ModTime().Equal(old) {
		t.Fatal("changed content must still write")
	}
}

// TestRefreshCertsHostsLiveDefaultRemote: DefaultRemote must be read fresh on
// every call, not cached at Server construction — a `certificate renew -cn`
// rename takes effect on the very next tick, no `ovcp serve` restart needed.
func TestRefreshCertsHostsLiveDefaultRemote(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	remote := "old.example.com"
	srv := &Server{
		Store:          s,
		CertsHostsPath: filepath.Join(t.TempDir(), "certs.hosts"),
		DefaultRemote:  func() string { return remote },
		DNSGroupGID:    -1,
	}

	die := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	die(srv.RefreshCertsHosts(nil))
	got, _ := os.ReadFile(srv.CertsHostsPath)
	if !strings.Contains(string(got), "old.example.com") {
		t.Fatalf("want old CN, got %q", got)
	}

	remote = "new.example.com" // same Server, no restart — mutating what the closure reads
	die(srv.RefreshCertsHosts(nil))
	got, _ = os.ReadFile(srv.CertsHostsPath)
	if !strings.Contains(string(got), "new.example.com") || strings.Contains(string(got), "old.example.com") {
		t.Fatalf("DefaultRemote must be live, not cached: %q", got)
	}
}

// TestDNSLeakWarning covers the advisory-only cross-domain check — never an
// error, just a heads-up when block-internet and pushed DNS contradict.
func TestDNSLeakWarning(t *testing.T) {
	blockOn := DNSConfig{BlockInternet: true}
	if w := DNSLeakWarning(ovpnconf.Config{PushInternalDNS: true}, blockOn); w != "" {
		t.Fatalf("internal-only push under block-internet should be clean, got %q", w)
	}
	if w := DNSLeakWarning(ovpnconf.Config{PushInternalDNS: true, DNS: []string{"1.1.1.1"}}, blockOn); w == "" {
		t.Fatal("manual DNS alongside block-internet should warn")
	}
	if w := DNSLeakWarning(ovpnconf.Config{PushInternalDNS: false}, blockOn); w == "" {
		t.Fatal("block-internet without pushing the internal resolver should warn")
	}
	if w := DNSLeakWarning(ovpnconf.Config{DNS: []string{"1.1.1.1"}}, DNSConfig{BlockInternet: false}); w != "" {
		t.Fatalf("block-internet off should never warn, got %q", w)
	}
}
