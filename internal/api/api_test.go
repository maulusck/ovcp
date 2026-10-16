package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"github.com/ovcp/ovcp/internal/telegram"
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
	os.MkdirAll(filepath.Join(dir, "pki"), 0o701) // InitCA trusts the caller for this, same as ensureSkeleton in production
	p := pki.New(filepath.Join(dir, "pki"))
	if err := p.InitCA("T", 1, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	// a real `init` always issues+records the server cert alongside the CA
	// (cmd/ovcp's cmdInit); handleRenew now requires an active row to renew,
	// so this fixture needs one too, not just the CA.
	serverIC, err := p.Issue(pki.KindServer, "vpn.example.com", 825, []byte(pass))
	if err != nil {
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
	os.MkdirAll(filepath.Join(dir, "dns"), 0o750)
	srv := &Server{Store: s, Auth: a, PKI: p,
		Mgmt:            controller.NewClient(filepath.Join(dir, "no.sock"), filepath.Join(dir, "no-status.log")),
		VPN:             &fakeVPN{},
		DNS:             &fakeVPN{},
		Telegram:        telegram.New(s, p, &fakeVPN{}, &fakeVPN{}, controller.NewClient(filepath.Join(dir, "no.sock"), filepath.Join(dir, "no-status.log"))),
		DataDir:         dir,
		ConfigPath:      filepath.Join(dir, "server.conf"),
		TLSCrypt:        filepath.Join(dir, "pki", "tls-crypt.key"),
		ServerCert:      filepath.Join(dir, "server.crt"),
		ServerKey:       filepath.Join(dir, "server.key"),
		DefaultRemote:   func() string { return "vpn.example.com" },
		DebugLevel:      new(slog.LevelVar),
		CertsHostsPath:  filepath.Join(dir, "dns", "certs.hosts"),
		CustomHostsPath: filepath.Join(dir, "dns", "custom.hosts"),
	}
	if err := WriteServerCert(srv.Store, srv.ServerCert, srv.ServerKey, serverIC); err != nil {
		t.Fatal(err)
	}
	return &env{ts: httptest.NewServer(srv.Handler()), t: t, dir: dir}
}

type fakeVPN struct{ n int }

func (f *fakeVPN) Start() error         { f.n++; return nil }
func (f *fakeVPN) Stop() error          { f.n++; return nil }
func (f *fakeVPN) Restart() error       { f.n++; return nil }
func (f *fakeVPN) Reconnect() error     { f.n++; return nil }
func (f *fakeVPN) Pid() int             { return 4242 }
func (f *fakeVPN) StartedAt() time.Time { return time.Now() }

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
		{"POST", "/api/certs/renew"},
		{"POST", "/api/backup"},
		{"POST", "/api/certs/export"},
		{"PUT", "/api/vpn/config"},
		{"POST", "/api/vpn/restart"},
		{"POST", "/api/dns/restart"},
		{"PATCH", "/api/certs/x/dns"},
		{"PUT", "/api/records/custom"},
		{"POST", "/api/records/custom/preview"},
		{"PUT", "/api/dns/config"},
		{"PUT", "/api/logs/config"},
		{"POST", "/api/logs/rotate"},
		{"PUT", "/api/stats/config"},
		{"PUT", "/api/telegram/config"},
		{"POST", "/api/telegram/start"},
		{"POST", "/api/debug"},
		{"POST", "/api/upstreams"},
		{"DELETE", "/api/upstreams/x"},
		{"PUT", "/api/upstreams/default"},
		{"PUT", "/api/upstreams/assign"},
		{"POST", "/api/upstreams/reconcile"},
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

// TestRevokeRestartsSessions: both API revoke paths (revoke, export renew)
// send RESTART to the CN's live session, via a fake on the env's mgmt socket.
func TestRevokeRestartsSessions(t *testing.T) {
	e := setup(t)
	status, _ := os.ReadFile(writeStatus(t, "alice")) // alice, CID 0
	l, err := net.Listen("unix", filepath.Join(e.dir, "no.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	kills := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch cmd := strings.TrimSpace(line); {
					case cmd == "status 3":
						c.Write(status)
						continue
					case strings.HasPrefix(cmd, "client-kill "):
						kills <- cmd
					}
					c.Write([]byte("SUCCESS: ok\r\n"))
				}
			}()
		}
	}()
	wantKill := func(step string) {
		select {
		case got := <-kills:
			if got != "client-kill 0 RESTART" {
				t.Fatalf("%s: got %q", step, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no client-kill sent", step)
		}
	}

	e.login("admin")
	r := e.req("POST", "/api/certs", `{"CN":"alice","Passphrase":"`+pass+`"}`, true)
	var out struct{ Serial string }
	json.NewDecoder(r.Body).Decode(&out)
	if r := e.req("POST", "/api/certs/revoke", `{"Serial":"`+out.Serial+`","Passphrase":"`+pass+`"}`, true); r.StatusCode != 200 {
		t.Fatal("revoke:", r.Status)
	}
	wantKill("revoke")
	e.req("POST", "/api/certs", `{"CN":"alice","Passphrase":"`+pass+`"}`, true)
	if r := e.req("POST", "/api/certs/export", `{"CN":"alice","Passphrase":"`+pass+`","Renew":true}`, true); r.StatusCode != 200 {
		t.Fatal("renew:", r.Status)
	}
	wantKill("renew")
}

func TestRenewServer(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("POST", "/api/certs/renew", `{"Passphrase":"wrong"}`, true); r.StatusCode != 403 {
		t.Fatal("wrong passphrase must 403, got", r.Status)
	}
	r := e.req("POST", "/api/certs/renew", `{"Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var out struct{ Serial, NotAfter string }
	json.NewDecoder(r.Body).Decode(&out)
	if out.Serial == "" {
		t.Fatal("expected a serial in the response")
	}
}

// TestCAInfoIsReadOnly: /api/me still reports CA cn/expiry/status (Settings'
// status line needs it), but there is no HTTP path to renew or rotate the
// CA — that's CLI-only, on purpose (see docs/ovcp.8's `ca renew`).
func TestCAInfoIsReadOnly(t *testing.T) {
	e := setup(t)
	e.login("admin")
	r := e.req("GET", "/api/me", "", false)
	var out struct{ CaCN, CaNotAfter, CaStatus string }
	json.NewDecoder(r.Body).Decode(&out)
	if out.CaCN != "T" || out.CaStatus != "valid" || out.CaNotAfter == "" {
		t.Fatalf("/api/me CA fields = %+v, want cn=T status=valid notAfter set", out)
	}

	if r := e.req("POST", "/api/certs/renew-ca", `{"Passphrase":"`+pass+`"}`, true); r.StatusCode != 404 {
		t.Fatalf("renew-ca must not exist as an HTTP route, got %d", r.StatusCode)
	}
}

// TestExportRenew: client renewal is export with Renew:true — one atomic
// call (issue the replacement, only then revoke the outgoing cert and
// regen the CRL), not two separate requests a caller could abandon
// half-done. Plain export without Renew must still 400 on an active CN
// (ErrDuplicateCN) — that's the signal a caller meant to issue, not renew.
func TestExportRenew(t *testing.T) {
	e := setup(t)
	e.login("admin")
	r := e.req("POST", "/api/certs", `{"CN":"alice","Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var issued struct{ Serial string }
	json.NewDecoder(r.Body).Decode(&issued)

	if r := e.req("POST", "/api/certs/export", `{"CN":"alice","Passphrase":"`+pass+`"}`, true); r.StatusCode != 400 {
		t.Fatalf("plain export over an active CN should 400 (ErrDuplicateCN), got %d", r.StatusCode)
	}

	if r := e.req("POST", "/api/certs/export", `{"CN":"alice","Passphrase":"`+pass+`","Renew":true}`, true); r.StatusCode != 200 {
		t.Fatalf("export with Renew:true should succeed atomically, got %d: %s", r.StatusCode, r.Status)
	}

	rows := e.req("GET", "/api/certs", "", false)
	var certs []struct{ CN, Serial, Status string }
	json.NewDecoder(rows.Body).Decode(&certs)
	var outgoingRevoked, replacementActive bool
	for _, c := range certs {
		if c.CN != "alice" {
			continue
		}
		if c.Serial == issued.Serial {
			outgoingRevoked = c.Status == "revoked"
		} else {
			replacementActive = c.Status != "revoked"
		}
	}
	if !outgoingRevoked {
		t.Fatal("renewal must revoke the outgoing cert")
	}
	if !replacementActive {
		t.Fatal("renewal must leave an active replacement")
	}

	// Renew:true on a CN with nothing active must error, not silently issue
	// — same RequireActiveCert guard certificate renew (CLI) and the
	// server-cert renew endpoint already use.
	if r := e.req("POST", "/api/certs/export", `{"CN":"ghost","Passphrase":"`+pass+`","Renew":true}`, true); r.StatusCode != 400 {
		t.Fatalf("Renew:true on a never-issued CN should 400, got %d", r.StatusCode)
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
	var out Status
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || (out.Running && out.Error == "") {
		t.Fatalf("no readable client list must not read as up: %+v", out)
	}
	if out.Telegram == nil || out.Telegram.TokenSet {
		t.Fatalf("telegram should read not-configured by default: %+v", out.Telegram)
	}
	if out.RoutingWarning != controller.RoutingPrereqsWarning(false) {
		t.Fatalf("routing_warning = %v, want the host's RoutingPrereqsWarning", out.RoutingWarning)
	}
}

func TestConfigPutValidation(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("PUT", "/api/vpn/config", `{"Proto":"sctp"}`, true); r.StatusCode != 400 {
		t.Fatal("bad proto must 400, got", r.Status)
	}
	if r := e.req("PUT", "/api/vpn/config", `{"Proto":"tcp","Port":443}`, true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	// the same values again change nothing: no write, no audit line
	if r := e.req("PUT", "/api/vpn/config", `{"Proto":"tcp","Port":443}`, true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var audit []struct{ Action string }
	json.NewDecoder(e.req("GET", "/api/audit", "", false).Body).Decode(&audit)
	n := 0
	for _, a := range audit {
		if a.Action == "config_change" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("config_change audited %d times, want 1 (the no-op PUT must not audit)", n)
	}
	if r := e.req("POST", "/api/vpn/restart", "", true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
}

// TestConfigPreview: preview must report the same delta PUT would apply,
// without applying it — GET /api/config stays untouched either way.
func TestConfigPreview(t *testing.T) {
	e := setup(t)
	e.login("admin")

	r := e.req("POST", "/api/vpn/config/preview", `{}`, true)
	var pv struct {
		Diff    []string
		Changed bool
	}
	if r.StatusCode != 200 {
		t.Fatal("no-op preview:", r.Status)
	}
	json.NewDecoder(r.Body).Decode(&pv)
	if pv.Changed || len(pv.Diff) != 0 {
		t.Fatalf("no-op preview should report no change, got %+v", pv)
	}

	r = e.req("POST", "/api/vpn/config/preview", `{"Port":443}`, true)
	json.NewDecoder(r.Body).Decode(&pv)
	if r.StatusCode != 200 || !pv.Changed {
		t.Fatalf("port-change preview: status=%d %+v", r.StatusCode, pv)
	}
	if !containsLine(pv.Diff, "-port 1194") || !containsLine(pv.Diff, "+port 443") {
		t.Fatalf("preview diff missing the port change: %+v", pv.Diff)
	}

	r = e.req("GET", "/api/vpn/config", "", true)
	var got struct{ Port int }
	json.NewDecoder(r.Body).Decode(&got)
	if got.Port != 1194 {
		t.Fatalf("preview must not persist: GET /api/config Port = %d, want 1194", got.Port)
	}

	if r := e.req("POST", "/api/vpn/config/preview", `{"Proto":"sctp"}`, true); r.StatusCode != 400 {
		t.Fatal("bad proto preview must 400, got", r.Status)
	}
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestDNSProc covers /api/dns/{op} — same shape as /api/vpn/{op} (which
// itself never had a "status" op either; that's GET /api/status), minus reconnect.
func TestDNSProc(t *testing.T) {
	e := setup(t)
	e.login("admin")
	for _, op := range []string{"start", "stop", "restart"} {
		r := e.req("POST", "/api/dns/"+op, "", true)
		if r.StatusCode != 200 {
			t.Fatalf("%s: %s", op, r.Status)
		}
		// the before/after Pid() diff itself is exercised against a real
		// flip in internal/controller (TestControlChangedFlag) — this just
		// confirms the field actually reaches the client.
		var out struct {
			Changed bool `json:"changed"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &out); err != nil || !strings.Contains(string(body), `"changed"`) {
			t.Fatalf("%s: response missing changed field: %s (err=%v)", op, body, err)
		}
	}
	if r := e.req("POST", "/api/dns/reconnect", "", true); r.StatusCode != 404 {
		t.Fatalf("dns reconnect must not exist, got %s", r.Status)
	}
}

// TestOpStatus: a busy lifecycle op is a 409 (client should retry), anything
// else stays the generic 502.
func TestOpStatus(t *testing.T) {
	if got := opStatus(fmt.Errorf("wrap: %w", controller.ErrBusy)); got != 409 {
		t.Errorf("busy: got %d, want 409", got)
	}
	if got := opStatus(fmt.Errorf("openvpn not found")); got != 502 {
		t.Errorf("other error: got %d, want 502", got)
	}
}

// TestCertDNSToggle: default include, toggle exclude/include, unknown serial errors.
func TestCertDNSToggle(t *testing.T) {
	e := setup(t)
	e.login("admin")
	r := e.req("POST", "/api/certs", `{"CN":"dnstoggle","Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var out struct{ Serial string }
	json.NewDecoder(r.Body).Decode(&out)

	certs := e.req("GET", "/api/certs", "", false)
	var rows []struct {
		Serial     string
		IncludeDNS bool
	}
	json.NewDecoder(certs.Body).Decode(&rows)
	found := false
	for _, row := range rows {
		if row.Serial == out.Serial {
			found = true
			if !row.IncludeDNS {
				t.Fatal("newly issued cert should default IncludeDNS=true")
			}
		}
	}
	if !found {
		t.Fatal("issued cert missing from /api/certs")
	}

	if r := e.req("PATCH", "/api/certs/"+out.Serial+"/dns", `{"IncludeDNS":false}`, true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	// already excluded: must report no-op, not silently re-apply and re-audit.
	var toggled struct{ Changed bool }
	r = e.req("PATCH", "/api/certs/"+out.Serial+"/dns", `{"IncludeDNS":false}`, true)
	json.NewDecoder(r.Body).Decode(&toggled)
	if r.StatusCode != 200 || toggled.Changed {
		t.Fatalf("already-excluded PATCH should report changed=false, got status=%d %+v", r.StatusCode, toggled)
	}
	if r := e.req("PATCH", "/api/certs/nonexistent/dns", `{"IncludeDNS":true}`, true); r.StatusCode != 404 {
		t.Fatalf("unknown serial must 404, got %s", r.Status)
	}

	// server's DNS line is unconditional — the toggle must 404 even hit
	// directly, not just be hidden client-side (Certs.svelte's checkbox).
	certs = e.req("GET", "/api/certs", "", false)
	var all []struct{ Serial, Kind string }
	json.NewDecoder(certs.Body).Decode(&all)
	var serverSerial string
	for _, c := range all {
		if c.Kind == "server" {
			serverSerial = c.Serial
		}
	}
	if serverSerial == "" {
		t.Fatal("no server cert in fixture")
	}
	if r := e.req("PATCH", "/api/certs/"+serverSerial+"/dns", `{"IncludeDNS":false}`, true); r.StatusCode != 404 {
		t.Fatalf("server cert DNS toggle must 404, got %s", r.Status)
	}
}

// TestCustomHosts covers get/put/preview for the free-form custom.hosts file.
func TestCustomHosts(t *testing.T) {
	e := setup(t)
	e.login("admin")

	r := e.req("GET", "/api/records", "", false)
	var got struct{ Custom string }
	json.NewDecoder(r.Body).Decode(&got)
	if r.StatusCode != 200 || got.Custom != "" {
		t.Fatalf("initial custom.hosts should be empty: status=%d %+v", r.StatusCode, got)
	}

	r = e.req("POST", "/api/records/custom/preview", `{"Content":"10.8.0.50 pihole\n"}`, true)
	var pv struct {
		Diff    []string
		Changed bool
	}
	json.NewDecoder(r.Body).Decode(&pv)
	if r.StatusCode != 200 || !pv.Changed || !containsLine(pv.Diff, "+10.8.0.50 pihole") {
		t.Fatalf("preview: status=%d %+v", r.StatusCode, pv)
	}

	if r := e.req("PUT", "/api/records/custom", `{"Content":"10.8.0.50 pihole\n"}`, true); r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	r = e.req("GET", "/api/records", "", false)
	json.NewDecoder(r.Body).Decode(&got)
	if got.Custom != "10.8.0.50 pihole\n" {
		t.Fatalf("custom.hosts not persisted, got %q", got.Custom)
	}
}

// TestUserEndpoints covers user-management routes, above all the self-lockout
// guards ("cannot delete/disable your own account") that exist only in this layer.
func TestUserEndpoints(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("POST", "/api/users", `{"Username":"bob","Password":"`+testUserPW+`","Role":"operator"}`, true); r.StatusCode != 200 {
		t.Fatal("add:", r.Status)
	}
	if r := e.req("POST", "/api/users", `{"Username":"eve","Password":"short","Role":"operator"}`, true); r.StatusCode != 400 {
		t.Fatal("short password must 400, got", r.Status)
	}
	if r := e.req("POST", "/api/users", `{"Username":"eve","Password":"alllowercase","Role":"operator"}`, true); r.StatusCode != 400 {
		t.Fatal("single-class password must 400, got", r.Status)
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

// TestPasswordYOLO: OVCP_YOLO_PASSWORD waives complexity through the API too,
// since `serve` inherits its env — every acceptance through that door is audited.
func TestPasswordYOLO(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("POST", "/api/users", `{"Username":"eve","Password":"alllowercase","Role":"operator"}`, true); r.StatusCode != 400 {
		t.Fatal("weak password must 400 without the env var, got", r.Status)
	}

	t.Setenv(auth.SecretYOLOEnv, "1")
	if r := e.req("POST", "/api/users", `{"Username":"eve","Password":"alllowercase","Role":"operator"}`, true); r.StatusCode != 200 {
		t.Fatal("weak password must be accepted with the env var set, got", r.Status)
	}
	if r := e.req("POST", "/api/users/eve/password", `{"Password":"stillweak"}`, true); r.StatusCode != 200 {
		t.Fatal("weak password change must be accepted with the env var set, got", r.Status)
	}

	r := e.req("GET", "/api/audit", "", true)
	var tail []struct{ Actor, Action, Detail string }
	json.NewDecoder(r.Body).Decode(&tail)
	var found int
	for _, e := range tail {
		if e.Action == "weak_password_accepted" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("expected 2 weak_password_accepted audit entries, got %d in %+v", found, tail)
	}
}

// TestExportBundle: the API twin of the CLI's TestExportFollowsConfig — the
// rendered profile must reflect the persisted server config, not defaults.
func TestExportBundle(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("PUT", "/api/vpn/config", `{"Proto":"tcp","Port":443,"Cipher":"CHACHA20-POLY1305"}`, true); r.StatusCode != 200 {
		t.Fatal("config put:", r.Status)
	}
	r := e.req("POST", "/api/certs/export", `{"CN":"alice","Passphrase":"`+pass+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatal("export:", r.Status)
	}
	var out ExportResult
	json.NewDecoder(r.Body).Decode(&out)
	body := out.Bundle
	for _, want := range []string{
		"remote vpn.example.com 443", "proto tcp", "data-ciphers CHACHA20-POLY1305",
		"verify-x509-name vpn.example.com name", "<cert>", "<key>", "<tls-crypt>",
	} {
		if !strings.Contains(body, want) {
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
	var out ExportResult
	json.NewDecoder(r.Body).Decode(&out)
	if body := out.Bundle; !strings.Contains(body, `pull-filter ignore "redirect-gateway"`) {
		t.Fatalf("bundle missing pull-filter:\n%s", body)
	}
}

func TestExportSplitTunnelRejected(t *testing.T) {
	e := setup(t)
	e.login("admin")
	if r := e.req("PUT", "/api/vpn/config", `{"RedirectGW":false}`, true); r.StatusCode != 200 {
		t.Fatal("config put:", r.Status)
	}
	r := e.req("POST", "/api/certs/export", `{"CN":"bob","Passphrase":"`+pass+`","SplitTunnel":true}`, true)
	if r.StatusCode != 400 {
		t.Fatalf("split-tunnel without server redirect should 400, got %s", r.Status)
	}
}

// TestStatsEndpoint: global must aggregate across clients, ?cn= must return
// only that one's own series (the client_samples per-CN branch).
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

	// same bound pki.Issue enforces at creation — a cn this long could never
	// have been issued, so this can't reject one actually in use.
	r = e.req("GET", "/api/stats?cn="+strings.Repeat("a", pki.MaxCNLen+1), "", false)
	if r.StatusCode != 400 {
		t.Fatalf("cn over MaxCNLen should 400, got %d", r.StatusCode)
	}
}

// TestStatsConfigEndpoint covers get/set for the sampling/retention policy —
// same merge-onto-current shape as vpn config, and the CLI's own get/set.
func TestStatsConfigEndpoint(t *testing.T) {
	e := setup(t)
	e.login("viewer")

	var cfg struct{ SampleIntervalSec, RetentionHours int }
	r := e.req("GET", "/api/stats/config", "", false)
	json.NewDecoder(r.Body).Decode(&cfg)
	if r.StatusCode != 200 || cfg.SampleIntervalSec != 60 || cfg.RetentionHours != 24 {
		t.Fatalf("defaults: status=%d %+v", r.StatusCode, cfg)
	}

	e.login("admin")
	if r := e.req("PUT", "/api/logs/config", `{"RetentionDays":-1}`, true); r.StatusCode != 400 {
		t.Fatalf("negative log retention: status %d, want 400", r.StatusCode)
	}
	if r := e.req("PUT", "/api/stats/config", `{"RetentionHours":0}`, true); r.StatusCode != 400 {
		t.Fatal("zero retention must 400, got", r.Status)
	}
	r = e.req("PUT", "/api/stats/config", `{"RetentionHours":48}`, true)
	json.NewDecoder(r.Body).Decode(&cfg)
	if r.StatusCode != 200 || cfg.RetentionHours != 48 || cfg.SampleIntervalSec != 60 {
		t.Fatalf("partial set: status=%d %+v", r.StatusCode, cfg)
	}
}

// TestLogsConfigEndpoint covers get/set for the log-rotation policy — same
// merge-onto-current shape, and the CLI's `logs config` twin.
func TestLogsConfigEndpoint(t *testing.T) {
	e := setup(t)
	e.login("viewer")

	var cfg struct {
		Enabled                         bool
		RetentionDays, KeepUncompressed int
	}
	r := e.req("GET", "/api/logs/config", "", false)
	json.NewDecoder(r.Body).Decode(&cfg)
	if r.StatusCode != 200 || !cfg.Enabled || cfg.RetentionDays != 14 || cfg.KeepUncompressed != 2 {
		t.Fatalf("defaults: status=%d %+v", r.StatusCode, cfg)
	}

	e.login("admin")
	r = e.req("PUT", "/api/logs/config", `{"RetentionDays":30}`, true)
	json.NewDecoder(r.Body).Decode(&cfg)
	if r.StatusCode != 200 || cfg.RetentionDays != 30 || cfg.KeepUncompressed != 2 || !cfg.Enabled {
		t.Fatalf("partial set: status=%d %+v", r.StatusCode, cfg)
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

func TestDNSBlockInternetToggle(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	var out struct{ BlockInternet bool }
	r := e.req("GET", "/api/dns/config", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || out.BlockInternet {
		t.Fatalf("want blockInternet=false initially, got status=%d %v", r.StatusCode, out.BlockInternet)
	}
	if r := e.req("PUT", "/api/dns/config", `{"BlockInternet":true}`, true); r.StatusCode != 403 {
		t.Fatal("readonly must not toggle it, got", r.Status)
	}

	e.login("admin")
	r = e.req("PUT", "/api/dns/config", `{"BlockInternet":true}`, true)
	json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || !out.BlockInternet {
		t.Fatalf("want blockInternet=true after enabling, got status=%d %v", r.StatusCode, out.BlockInternet)
	}
	r = e.req("GET", "/api/dns/config", "", false)
	json.NewDecoder(r.Body).Decode(&out)
	if !out.BlockInternet {
		t.Fatal("GET after enable should report blockInternet=true")
	}
}

func TestTelegramEndpoints(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "good-token/getMe") {
			w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true}}`))
			return
		}
		w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer mock.Close()
	defer telegram.SetAPIBaseForTesting(mock.URL + "/bot")()

	e := setup(t)
	e.login("admin")

	var st struct {
		Running  bool
		TokenSet bool
		Admin    string
		Changed  bool
	}
	r := e.req("GET", "/api/telegram/config", "", false)
	json.NewDecoder(r.Body).Decode(&st)
	if r.StatusCode != 200 || st.TokenSet {
		t.Fatalf("want unconfigured, got status=%d %+v", r.StatusCode, st)
	}

	if r := e.req("PUT", "/api/telegram/config", `{"Token":"bad-token"}`, true); r.StatusCode != 400 {
		t.Fatal("rejected token must 400, got", r.Status)
	}
	// token and admin are independently settable — setting one must never
	// require resupplying the other.
	r = e.req("PUT", "/api/telegram/config", `{"Token":"good-token"}`, true)
	json.NewDecoder(r.Body).Decode(&st)
	if r.StatusCode != 200 || !st.TokenSet || st.Admin != "" {
		t.Fatalf("token alone: status=%d %+v", r.StatusCode, st)
	}
	r = e.req("PUT", "/api/telegram/config", `{"Admin":"@alice"}`, true)
	json.NewDecoder(r.Body).Decode(&st)
	if r.StatusCode != 200 || !st.TokenSet || st.Admin != "@alice" {
		t.Fatalf("admin alone: status=%d %+v", r.StatusCode, st)
	}

	r = e.req("POST", "/api/telegram/start", "", true)
	json.NewDecoder(r.Body).Decode(&st)
	if r.StatusCode != 200 || !st.Running || !st.Changed {
		t.Fatalf("start: status=%d %+v", r.StatusCode, st)
	}
	r = e.req("POST", "/api/telegram/start", "", true) // already running
	json.NewDecoder(r.Body).Decode(&st)
	if r.StatusCode != 200 || !st.Running || st.Changed {
		t.Fatalf("start again: status=%d %+v, want changed=false", r.StatusCode, st)
	}
	r = e.req("POST", "/api/telegram/stop", "", true)
	json.NewDecoder(r.Body).Decode(&st)
	if r.StatusCode != 200 || st.Running || !st.Changed {
		t.Fatalf("stop: status=%d %+v", r.StatusCode, st)
	}
	if r := e.req("POST", "/api/telegram/bogus", "", true); r.StatusCode != 404 {
		t.Fatal("unknown op must 404, got", r.Status)
	}
}

// TestRequestLogWarnsOn5xx: a 500 must be visible at the default log level,
// not only under -debug.
func TestRequestLogWarnsOn5xx(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil))) // default level: Info, Debug excluded

	h := requestLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))

	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("want a WARN line for a 500 response, got: %s", buf.String())
	}
}
