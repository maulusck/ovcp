package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

const pass = "test-passphrase-123"
const testUserPW = "hunter22hunter22"

type env struct {
	ts   *httptest.Server
	sess *http.Cookie
	csrf *http.Cookie
	t    *testing.T
	dir  string
}

func setup(t *testing.T) *env {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p := pki.New(filepath.Join(dir, "pki"))
	if err := p.InitCA("T", 1, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	// backup.Create needs these to exist at their real relative layout.
	os.WriteFile(filepath.Join(dir, "pki", "tls-crypt.key"), []byte("fake-tls-crypt"), 0o600)
	os.WriteFile(filepath.Join(dir, "server.conf"), []byte("fake-server-conf"), 0o644)
	a := auth.NewService(s)
	h, _ := auth.HashPassword(testUserPW)
	s.AddUser("admin", h, "admin")
	h2, _ := auth.HashPassword(testUserPW)
	s.AddUser("viewer", h2, "readonly")
	srv := &Server{Store: s, Auth: a, PKI: p,
		Mgmt:          controller.NewClient(filepath.Join(dir, "no.sock")),
		VPN:           &fakeVPN{},
		DataDir:       dir,
		ConfigPath:    filepath.Join(dir, "server.conf"),
		TLSCrypt:      filepath.Join(dir, "pki", "tls-crypt.key"),
		ServerCert:    filepath.Join(dir, "server.crt"),
		ServerKey:     filepath.Join(dir, "server.key"),
		DefaultRemote: "vpn.example.com",
		DebugLevel:    new(slog.LevelVar),
	}
	return &env{ts: httptest.NewServer(srv.Handler()), t: t, dir: dir}
}

type fakeVPN struct{ n int }

func (f *fakeVPN) Start() error     { f.n++; return nil }
func (f *fakeVPN) Stop() error      { f.n++; return nil }
func (f *fakeVPN) Restart() error   { f.n++; return nil }
func (f *fakeVPN) Reconnect() error { f.n++; return nil }
func (f *fakeVPN) Pid() int         { return 4242 }

func (e *env) login(user string) {
	body, _ := json.Marshal(map[string]string{"Username": user, "Password": testUserPW})
	res, err := http.Post(e.ts.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil || res.StatusCode != 200 {
		e.t.Fatalf("login: %v %v", res.Status, err)
	}
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			e.sess = c
		}
		if c.Name == csrfCookie {
			e.csrf = c
		}
	}
}

func (e *env) req(method, path, body string, withCSRF bool) *http.Response {
	req, _ := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if e.sess != nil {
		req.AddCookie(e.sess)
		req.AddCookie(e.csrf)
	}
	if withCSRF && e.csrf != nil {
		req.Header.Set(csrfHeader, e.csrf.Value)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func TestHealthz(t *testing.T) {
	e := setup(t)
	r := e.req("GET", "/healthz", "", false)
	if r.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", r.StatusCode)
	}
}

func TestAuthFlow(t *testing.T) {
	e := setup(t)
	if r := e.req("GET", "/api/me", "", false); r.StatusCode != 401 {
		t.Fatal("unauthenticated must 401, got", r.Status)
	}
	e.login("admin")
	if r := e.req("GET", "/api/me", "", false); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
}

func TestCSRF(t *testing.T) {
	e := setup(t)
	e.login("admin")
	body := `{"CN":"x","Passphrase":"` + pass + `"}`
	if r := e.req("POST", "/api/certs", body, false); r.StatusCode != 403 {
		t.Fatal("missing csrf must 403, got", r.Status)
	}
	if r := e.req("POST", "/api/certs", body, true); r.StatusCode != 200 {
		t.Fatal("with csrf:", r.Status)
	}
}

// TestRBAC guards the role each route is registered with in Handler(), not
// just wrap() itself: every privileged route must reject a readonly session.
func TestRBAC(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	if r := e.req("GET", "/api/certs", "", false); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	for _, ep := range []struct{ method, path string }{
		{"POST", "/api/clients/kill"},
		{"POST", "/api/certs"},
		{"POST", "/api/certs/revoke"},
		{"POST", "/api/certs/renew-server"},
		{"POST", "/api/backup"},
		{"POST", "/api/certs/export"},
		{"PUT", "/api/config"},
		{"POST", "/api/vpn/restart"},
		{"POST", "/api/debug"},
		{"GET", "/api/users"},
		{"POST", "/api/users"},
		{"DELETE", "/api/users/x"},
		{"PATCH", "/api/users/x"},
		{"POST", "/api/users/x/password"},
		{"POST", "/api/users/x/totp"},
		{"DELETE", "/api/users/x/totp"},
	} {
		if r := e.req(ep.method, ep.path, "{}", true); r.StatusCode != 403 {
			t.Fatalf("%s %s as readonly = %d, want 403", ep.method, ep.path, r.StatusCode)
		}
	}
}

func TestIssueRevokeWrongPass(t *testing.T) {
	e := setup(t)
	e.login("admin")
	r := e.req("POST", "/api/certs", `{"CN":"alice","Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var out struct{ Serial string }
	json.NewDecoder(r.Body).Decode(&out)
	if r := e.req("POST", "/api/certs/revoke",
		`{"Serial":"`+out.Serial+`","Passphrase":"wrong"}`, true); r.StatusCode != 403 {
		t.Fatal("wrong passphrase must 403, got", r.Status)
	}
}

func TestRenewServer(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("POST", "/api/certs/renew-server", `{"Passphrase":"wrong"}`, true); r.StatusCode != 403 {
		t.Fatal("wrong passphrase must 403, got", r.Status)
	}
	r := e.req("POST", "/api/certs/renew-server", `{"Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var out struct{ Serial, NotAfter string }
	json.NewDecoder(r.Body).Decode(&out)
	if out.Serial == "" {
		t.Fatal("expected a serial in the response")
	}
}

func TestBackup(t *testing.T) {
	e := setup(t)
	e.login("admin")
	r := e.req("POST", "/api/backup", `{"Passphrase":"a-backup-passphrase"}`, true)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 {
		t.Fatal("empty archive")
	}
}

func TestStatusVPNDown(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	r := e.req("GET", "/api/status", "", false)
	var out struct {
		VPNUp bool `json:"vpn_up"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || out.VPNUp {
		t.Fatal("vpn down must be 200 vpn_up=false")
	}
}

func TestConfigPutValidation(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("PUT", "/api/config", `{"Proto":"sctp"}`, true); r.StatusCode != 400 {
		t.Fatal("bad proto must 400, got", r.Status)
	}
	if r := e.req("PUT", "/api/config", `{"Proto":"tcp","Port":443}`, true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	if r := e.req("POST", "/api/vpn/restart", "", true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
}

// TestUserEndpoints covers the user-management routes, above all the two
// self-lockout guards ("cannot delete/disable your own account") that exist
// only in this layer — the CLI has no such guard and auth never sees them.
func TestUserEndpoints(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("POST", "/api/users", `{"Username":"bob","Password":"`+testUserPW+`","Role":"operator"}`, true); r.StatusCode != 200 {
		t.Fatal("add:", r.Status)
	}
	if r := e.req("POST", "/api/users", `{"Username":"eve","Password":"short","Role":"operator"}`, true); r.StatusCode != 400 {
		t.Fatal("short password must 400, got", r.Status)
	}
	if r := e.req("DELETE", "/api/users/admin", "", true); r.StatusCode != 400 {
		t.Fatal("self-delete must 400, got", r.Status)
	}
	if r := e.req("PATCH", "/api/users/admin", `{"Disabled":true}`, true); r.StatusCode != 400 {
		t.Fatal("self-disable must 400, got", r.Status)
	}
	if r := e.req("PATCH", "/api/users/bob", `{"Disabled":true}`, true); r.StatusCode != 200 {
		t.Fatal("disable bob:", r.Status)
	}

	r := e.req("POST", "/api/users/bob/totp", "", true)
	var totp struct{ Secret, URL, QR string }
	json.NewDecoder(r.Body).Decode(&totp)
	if r.StatusCode != 200 || totp.Secret == "" || !strings.HasPrefix(totp.QR, "data:image/svg+xml;base64,") {
		t.Fatalf("totp enroll: status=%d %+v", r.StatusCode, totp)
	}
	if r := e.req("DELETE", "/api/users/bob/totp", "", true); r.StatusCode != 200 {
		t.Fatal("totp off:", r.Status)
	}

	if r := e.req("DELETE", "/api/users/bob", "", true); r.StatusCode != 200 {
		t.Fatal("delete bob:", r.Status)
	}
	if r := e.req("DELETE", "/api/users/bob", "", true); r.StatusCode != 400 {
		t.Fatal("deleting a missing user must 400, got", r.Status)
	}
}

// TestExportBundle: the API twin of the CLI's TestExportFollowsConfig — the
// rendered profile must reflect the persisted server config, not defaults.
func TestExportBundle(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("PUT", "/api/config", `{"Proto":"tcp","Port":443,"Cipher":"CHACHA20-POLY1305"}`, true); r.StatusCode != 200 {
		t.Fatal("config put:", r.Status)
	}
	r := e.req("POST", "/api/certs/export", `{"CN":"alice","Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal("export:", r.Status)
	}
	if cd := r.Header.Get("Content-Disposition"); !strings.Contains(cd, "alice.ovpn") {
		t.Fatalf("Content-Disposition = %q, want the CN in it", cd)
	}
	body, _ := io.ReadAll(r.Body)
	for _, want := range []string{
		"remote vpn.example.com 443", "proto tcp", "data-ciphers CHACHA20-POLY1305",
		"verify-x509-name vpn.example.com name", "<cert>", "<key>", "<tls-crypt>",
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("bundle missing %q:\n%s", want, body)
		}
	}
}

func TestExportSplitTunnel(t *testing.T) {
	e := setup(t)
	e.login("admin")
	// RedirectGW defaults to true (ovpnconf.Default) — split-tunnel should apply.
	r := e.req("POST", "/api/certs/export", `{"CN":"alice","Passphrase":"`+pass+`","SplitTunnel":true}`, true)
	if r.StatusCode != 200 {
		t.Fatal("export:", r.Status)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), `pull-filter ignore "redirect-gateway"`) {
		t.Fatalf("bundle missing pull-filter:\n%s", body)
	}
}

func TestExportSplitTunnelRejected(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("PUT", "/api/config", `{"RedirectGW":false}`, true); r.StatusCode != 200 {
		t.Fatal("config put:", r.Status)
	}
	r := e.req("POST", "/api/certs/export", `{"CN":"bob","Passphrase":"`+pass+`","SplitTunnel":true}`, true)
	if r.StatusCode != 400 {
		t.Fatalf("split-tunnel without server redirect should 400, got %s", r.Status)
	}
}

// TestStatsEndpoint covers the ?cn= branch handleStats gained when
// vpn_samples (global-only) became client_samples (per-CN): global must
// aggregate across clients, ?cn= must return only that one's own series.
func TestStatsEndpoint(t *testing.T) {
	e := setup(t)
	e.login("viewer")

	t0 := time.Now().Add(-time.Minute)
	t1 := t0.Add(time.Minute)
	die := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.Open(filepath.Join(e.dir, "t.db"))
	die(err)
	defer s.Close()
	die(s.AddClientSample(t0, "alice", 100, 200))
	die(s.AddClientSample(t0, "bob", 10, 20))
	die(s.AddClientSample(t1, "alice", 150, 250))

	var out struct {
		Samples []struct {
			Clients              int
			BytesRecv, BytesSent uint64
		}
	}

	r := e.req("GET", "/api/stats", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || len(out.Samples) != 2 || out.Samples[0].Clients != 2 || out.Samples[0].BytesRecv != 110 {
		t.Fatalf("global samples: status=%d %+v", r.StatusCode, out.Samples)
	}

	r = e.req("GET", "/api/stats?cn=alice", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || len(out.Samples) != 2 || out.Samples[1].BytesRecv != 150 {
		t.Fatalf("alice-scoped samples: status=%d %+v", r.StatusCode, out.Samples)
	}

	r = e.req("GET", "/api/stats?cn=nobody", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || len(out.Samples) != 0 {
		t.Fatalf("unknown cn should be an empty series, not an error: status=%d %+v", r.StatusCode, out.Samples)
	}

	// same bound pki.Issue enforces at creation (TestIssueCNLength) — a cn
	// that long could never have been issued, so rejecting it here can
	// never reject one that's actually in use.
	r = e.req("GET", "/api/stats?cn="+strings.Repeat("a", pki.MaxCNLen+1), "", false)
	if r.StatusCode != 400 {
		t.Fatalf("cn over MaxCNLen should 400, got %d", r.StatusCode)
	}
}

func TestDebugToggle(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	var out struct{ Debug bool }
	r := e.req("GET", "/api/debug", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || out.Debug {
		t.Fatalf("want debug=false initially, got status=%d debug=%v", r.StatusCode, out.Debug)
	}
	if r := e.req("POST", "/api/debug", `{"Debug":true}`, true); r.StatusCode != 403 {
		t.Fatal("readonly must not toggle debug, got", r.Status)
	}

	e.login("admin")
	r = e.req("POST", "/api/debug", `{"Debug":true}`, true)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || !out.Debug {
		t.Fatalf("want debug=true after enabling, got status=%d debug=%v", r.StatusCode, out.Debug)
	}
	r = e.req("GET", "/api/debug", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if !out.Debug {
		t.Fatal("GET after enable should report debug=true")
	}

	r = e.req("POST", "/api/debug", `{"Debug":false}`, true)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || out.Debug {
		t.Fatal("want debug=false after disabling")
	}
}
