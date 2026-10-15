package telegram

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

type fakeLife struct{}

func (fakeLife) Start() error         { return nil }
func (fakeLife) Stop() error          { return nil }
func (fakeLife) Restart() error       { return nil }
func (fakeLife) Reconnect() error     { return nil }
func (fakeLife) Pid() int             { return 0 }
func (fakeLife) StartedAt() time.Time { return time.Time{} }

func TestMatches(t *testing.T) {
	cases := []struct {
		admin string
		u     user
		want  bool
	}{
		{"12345", user{ID: 12345, Username: "alice"}, true},
		{"12345", user{ID: 99999, Username: "alice"}, false},
		{"@alice", user{ID: 999, Username: "alice"}, true},
		{"@alice", user{ID: 999, Username: "Alice"}, true}, // case-insensitive
		{"alice", user{ID: 999, Username: "alice"}, true},  // leading @ optional
		{"@alice", user{ID: 999, Username: "bob"}, false},
		{"@alice", user{ID: 999, Username: ""}, false}, // no username set, never matches
	}
	for _, c := range cases {
		if got := matches(c.admin, c.u); got != c.want {
			t.Errorf("matches(%q, %+v) = %v, want %v", c.admin, c.u, got, c.want)
		}
	}
}

// TestBusy: an op already holding mu must reject a concurrent one instead
// of queuing behind it — same guard as controller.Supervisor's opMu.
func TestBusy(t *testing.T) {
	p := &Poller{}
	p.mu.Lock()
	if err := p.Stop(); !errors.Is(err, controller.ErrBusy) {
		t.Fatalf("Stop while busy: got %v, want ErrBusy", err)
	}
	p.mu.Unlock()
	if err := p.Stop(); err != nil {
		t.Fatalf("stop after release: %v", err)
	}
}

// TestStrangerGetsNoReply: an unauthorized sender is ignored, not answered.
func TestStrangerGetsNoReply(t *testing.T) {
	var sent int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(SetAPIBaseForTesting(srv.URL + "/bot"))
	eve := user{ID: 111, Username: "eve"}
	(&Poller{}).handle(context.Background(), newBot("t"), testAdmin, update{Message: &message{Chat: chat{ID: 111}, From: eve, Text: "/status"}})
	if sent != 0 {
		t.Fatalf("stranger got %d API calls, want none", sent)
	}
}

// TestHandleCommandCoversRegisteredSurface guards against the menu listing
// an op handleCommand's switch doesn't dispatch — every identifier must reply.
func TestHandleCommandCoversRegisteredSurface(t *testing.T) {
	var sent int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendMessage") {
			sent++
		}
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()
	defer SetAPIBaseForTesting(srv.URL + "/bot")()

	s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()
	p := &Poller{s: s, p: pki.New(t.TempDir()), vpn: fakeLife{}, dns: fakeLife{}}
	b := newBot("t")
	ctx := context.Background()

	var identifiers []string
	for _, c := range botCommands {
		identifiers = append(identifiers, "/"+c.Command, c.Command)
	}
	for _, row := range opsKeyboard.Keyboard {
		identifiers = append(identifiers, row...)
	}

	for _, id := range identifiers {
		before := sent
		p.handleCommand(ctx, b, 1, id)
		if sent == before {
			t.Errorf("handleCommand(%q) produced no reply — menu lists an op the switch doesn't handle", id)
		}
	}
}

// TestCertsText covers /certs' grouping: expiring/expired/revoked/valid
// sections, the CA folded in via AllCerts, and that revoked wins the
// classification even for a cert that's also past NotAfter.
func TestCertsText(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	caPKI := pki.New(filepath.Join(dir, "pki"))
	if err := caPKI.InitCA("Test CA", 1, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	s, _ := store.Open(filepath.Join(dir, "ovcp.db"))
	defer s.Close()
	now := time.Now()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.AddCert(store.Cert{Serial: "s1", CN: "alice", Kind: "client", CertPEM: []byte("x"), IssuedAt: now, NotAfter: now.Add(5 * 24 * time.Hour)}))
	must(s.AddCert(store.Cert{Serial: "s2", CN: "bob", Kind: "client", CertPEM: []byte("x"), IssuedAt: now, NotAfter: now.Add(-3 * 24 * time.Hour)}))
	must(s.AddCert(store.Cert{Serial: "s3", CN: "carol", Kind: "client", CertPEM: []byte("x"), IssuedAt: now, NotAfter: now.AddDate(1, 0, 0)}))
	_, err := s.Revoke("s3", now)
	must(err)

	po := &Poller{s: s, p: caPKI}
	got := po.certsText()

	for _, want := range []string{
		"Certificates (4 total)",
		"⏳ Expiring (1)", "alice (client) — 4d left",
		"❌ Expired (1)", "bob (client) — expired 3d ago",
		"🚫 Revoked (1)", "carol (client) — revoked",
		"✅ Valid (1)", "Test CA (ca) — until",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("certsText() missing %q, got:\n%s", want, got)
		}
	}

	// sections must appear most-urgent-first, not just all be present.
	var positions []int
	for _, heading := range []string{"⏳ Expiring", "❌ Expired", "🚫 Revoked", "✅ Valid"} {
		i := strings.Index(got, heading)
		if i < 0 {
			t.Fatalf("heading %q not found in:\n%s", heading, got)
		}
		positions = append(positions, i)
	}
	if !slices.IsSorted(positions) {
		t.Fatalf("sections out of order (want expiring, expired, revoked, valid), got:\n%s", got)
	}
}

// TestDNSArgForm covers "/dns start|stop|restart" folding onto the same
// tokens the inline keyboard's callback_data uses — not listed in
// botCommands (no menu clutter), so the surface-coverage test above can't see it.
func TestDNSArgForm(t *testing.T) {
	var sent int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendMessage") {
			sent++
		}
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()
	defer SetAPIBaseForTesting(srv.URL + "/bot")()

	s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()
	p := &Poller{s: s, p: pki.New(t.TempDir()), vpn: fakeLife{}, dns: fakeLife{}}
	b := newBot("t")
	ctx := context.Background()

	for _, cmd := range []string{"/dns start", "/dns stop", "/dns restart"} {
		before := sent
		p.handleCommand(ctx, b, 1, cmd)
		if sent == before {
			t.Errorf("handleCommand(%q) produced no reply", cmd)
		}
	}
}
