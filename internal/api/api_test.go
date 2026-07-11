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

func TestRBAC(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	if r := e.req("GET", "/api/certs", "", false); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	if r := e.req("POST", "/api/certs", `{"CN":"x","Passphrase":"p"}`, true); r.StatusCode != 403 {
		t.Fatal("readonly issue must 403, got", r.Status)
	}
	if r := e.req("POST", "/api/vpn/restart", "", true); r.StatusCode != 403 {
		t.Fatal("readonly vpn op must 403, got", r.Status)
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

func TestRenewServerRBAC(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	if r := e.req("POST", "/api/certs/renew-server", `{"Passphrase":"`+pass+`"}`, true); r.StatusCode != 403 {
		t.Fatal("readonly renew-server must 403, got", r.Status)
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

func TestBackupRBAC(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	if r := e.req("POST", "/api/backup", `{"Passphrase":"a-backup-passphrase"}`, true); r.StatusCode != 403 {
		t.Fatal("readonly backup must 403, got", r.Status)
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
