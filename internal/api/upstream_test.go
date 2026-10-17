package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

func testUpstreamServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &Server{
		Store: s,
		Mgmt:  controller.NewClient(filepath.Join(dir, "no.sock"), filepath.Join(dir, "no-status.log")),
	}
}

// TestApplyUpstreamsNeverFails: a down egress (or Apply failing entirely)
// must never surface as an error — the return type makes that impossible.
// No real nft/root needed: Apply's own failure is tolerated regardless.
func TestApplyUpstreamsNeverFails(t *testing.T) {
	srv := testUpstreamServer(t)
	srv.UpstreamsEnabled = true
	cfg := upstream.Config{Upstreams: []upstream.Upstream{{ID: "ghost", Iface: "ovcp-test-ghost0", Table: 100}}}
	if warning := srv.applyUpstreams(cfg); warning != "unreachable (iface down): ghost" {
		t.Fatalf("warning = %q", warning)
	}
}

// TestViewUpstreamsRedactsSOCKS: the one view the CLI and the API return
// never carries a stored SOCKS password.
func TestViewUpstreamsRedactsSOCKS(t *testing.T) {
	cfg := upstream.Config{Default: "tor", Upstreams: []upstream.Upstream{
		{ID: "tor", SOCKS: "socks5://user:s3cret@127.0.0.1:9050", Table: 100}}}
	data, err := json.Marshal(ViewUpstreams(cfg, "some warning"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s3cret") {
		t.Fatalf("view leaks the SOCKS password: %s", data)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil || m["default"] != "tor" || m["warning"] != "some warning" {
		t.Fatalf("got %s, want default and warning at the top level", data)
	}
}

// testAssignFixture returns a fresh store + a server.conf path in a real
// (writable) temp dir — ApplyAssign's SetManagementClientAuth call needs
// both: the store for vpn_config, the path for WriteAtomic.
func testAssignFixture(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, filepath.Join(dir, "server.conf")
}

// TestApplyAssignFirstActivationWarns: assigning the very first per-CN
// override flips ManagementClientAuth empty->non-empty, which — per
// internal/controller/supervisor.go's Restart/Reconnect split — needs a
// real `vpn restart` to take effect, so ApplyAssign must both persist the
// flag and report RestartWarning.
func TestApplyAssignFirstActivationWarns(t *testing.T) {
	s, confPath := testAssignFixture(t)
	cfg, err := upstream.Config{Upstreams: []upstream.Upstream{{ID: "wan1", SOCKS: "socks5://127.0.0.1:1", Table: 100}}}.Assign("alice", "wan1", false)
	if err != nil {
		t.Fatal(err)
	}
	warning, err := applyAssign(s, confPath, false /* before */, cfg, "wan1")
	if err != nil {
		t.Fatalf("applyAssign: %v", err)
	}
	if warning != RestartWarning {
		t.Fatalf("warning = %q, want RestartWarning", warning)
	}
	if !UpstreamAuthActive(s) {
		t.Fatal("PerCN was persisted but UpstreamAuthActive reports false")
	}
	raw, _ := s.GetSetting("vpn_config")
	if !ovpnconf.Load(raw).ManagementClientAuth {
		t.Fatal("vpn_config was not flipped to ManagementClientAuth=true")
	}
	if _, err := os.Stat(confPath); err != nil {
		t.Fatalf("server.conf was not written: %v", err)
	}
}

// TestApplyAssignNoWarningWhenAlreadyActive: a second CN assigned while
// per-CN routing is already active is a live-only change — before==after,
// so no restart is needed and none should be claimed.
func TestApplyAssignNoWarningWhenAlreadyActive(t *testing.T) {
	s, confPath := testAssignFixture(t)
	cfg, err := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "wan1", SOCKS: "socks5://127.0.0.1:1", Table: 100}},
		PerCN:     map[string]string{"bob": "wan1"},
	}.Assign("alice", "wan1", false)
	if err != nil {
		t.Fatal(err)
	}
	warning, err := applyAssign(s, confPath, true /* before: bob already active */, cfg, "wan1")
	if err != nil {
		t.Fatalf("applyAssign: %v", err)
	}
	if warning != "" {
		t.Fatalf("warning = %q, want none — auth was already active", warning)
	}
}

// TestApplyAssignClearingLastOverrideFlipsOffSilently: clearing the only
// remaining override flips ManagementClientAuth back off. No restart
// warning either way — turning it off doesn't need one, only turning it on
// does (see RestartWarning's own doc comment).
func TestApplyAssignClearingLastOverrideFlipsOffSilently(t *testing.T) {
	s, confPath := testAssignFixture(t)
	cfg, err := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "wan1", Iface: "eth1", Table: 100}},
		PerCN:     map[string]string{"alice": "wan1"},
	}.Assign("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	warning, err := applyAssign(s, confPath, true /* before: alice was the only override */, cfg, "" /* clearing, no target */)
	if err != nil {
		t.Fatalf("applyAssign: %v", err)
	}
	if warning != "" {
		t.Fatalf("warning = %q, want none", warning)
	}
	if UpstreamAuthActive(s) {
		t.Fatal("PerCN is now empty but UpstreamAuthActive still reports true")
	}
	raw, _ := s.GetSetting("vpn_config")
	if ovpnconf.Load(raw).ManagementClientAuth {
		t.Fatal("vpn_config was not flipped back to ManagementClientAuth=false")
	}
}

// TestApplyAssignWarnsOnDownTarget: assigning a CN to an upstream whose
// iface doesn't exist must warn, same wording applyUpstreams already uses
// for add/del/set-default — assign is the one mutator that doesn't route
// through applyUpstreams, so it has to compute this itself.
func TestApplyAssignWarnsOnDownTarget(t *testing.T) {
	s, confPath := testAssignFixture(t)
	cfg, err := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "wan1", SOCKS: "socks5://127.0.0.1:1", Table: 100}},
	}.Assign("alice", "wan1", false)
	if err != nil {
		t.Fatal(err)
	}
	// wan1 is up (SOCKS), so RestartWarning is the only signal so far —
	// swap in a second, iface-mode upstream that's actually down and assign
	// bob to it, PerCN already non-empty so no RestartWarning muddies this.
	cfg.Upstreams = append(cfg.Upstreams, upstream.Upstream{ID: "wan2", Iface: "ovcp-ghost0", Table: 101})
	cfg, err = cfg.Assign("bob", "wan2", false)
	if err != nil {
		t.Fatal(err)
	}
	warning, err := applyAssign(s, confPath, true /* before: wan1 already active */, cfg, "wan2")
	if err != nil {
		t.Fatalf("applyAssign: %v", err)
	}
	if warning != "unreachable (iface down): wan2" {
		t.Fatalf("warning = %q, want the down-target warning", warning)
	}
}

// TestAssignUpstreamDisabled: with upstreams off, assign is refused before
// anything persists, server.conf included.
func TestAssignUpstreamDisabled(t *testing.T) {
	s, confPath := testAssignFixture(t)
	if err := SaveUpstreamConfig(s, upstream.Config{Upstreams: []upstream.Upstream{{ID: "wan1", Iface: "eth1", Table: 100}}}); err != nil {
		t.Fatal(err)
	}
	noRewrite := func(string) error { t.Fatal("rewrite must not run"); return nil }
	if _, err := AssignUpstream(s, "admin", false, confPath, "alice", "wan1", false, noRewrite); !errors.Is(err, ErrUpstreamsDisabled) {
		t.Fatalf("err = %v, want ErrUpstreamsDisabled", err)
	}
	if UpstreamAuthActive(s) {
		t.Fatal("a refused assign must not persist PerCN")
	}
	if _, err := os.Stat(confPath); err == nil {
		t.Fatal("server.conf must not be written when upstreams are disabled")
	}
}

// TestRewriteConnectedClientRuleNotConnectedIsNoOp: cn isn't in the live
// client list — a no-op, not an error; the new mapping takes effect on
// their next connect instead.
func TestRewriteConnectedClientRuleNotConnectedIsNoOp(t *testing.T) {
	srv := testUpstreamServer(t)
	if err := os.WriteFile(srv.Mgmt.StatusPath, []byte("TITLE\tfake\r\nEND\r\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := srv.RewriteConnectedClientRule("alice"); err != nil {
		t.Fatalf("RewriteConnectedClientRule: %v", err)
	}
}

// TestRewriteConnectedClientRuleFindsLiveClient proves the CID/CN/address
// found via Status() actually reaches upstream.Reassign: an override
// pointing at a nonexistent upstream can only surface this specific error
// from inside Reassign, once it's been given alice's live CID.
func TestRewriteConnectedClientRuleFindsLiveClient(t *testing.T) {
	srv := testUpstreamServer(t)
	status := "TITLE\tfake\r\n" +
		"HEADER\tCLIENT_LIST\t...\r\n" +
		"CLIENT_LIST\talice\t203.0.113.7:1\t10.8.0.9\t\t0\t0\tSat Jul  5 11:00:00 2026\t1783080000\tUNDEF\t3\t0\tAES-256-GCM\r\n" +
		"END\r\n"
	if err := os.WriteFile(srv.Mgmt.StatusPath, []byte(status), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SaveUpstreamConfig(srv.Store, upstream.Config{PerCN: map[string]string{"alice": "gone"}}); err != nil {
		t.Fatal(err)
	}
	err := srv.RewriteConnectedClientRule("alice")
	if err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("got %v, want the assigned-upstream-missing error from Reassign", err)
	}
}

// TestVPNStartRunsAfterStart: a web API start or restart re-applies upstreams
// and reattaches mgmt (AfterVPNStart) exactly as the control socket does.
func TestVPNStartRunsAfterStart(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	calls := 0
	srv := &Server{Store: s, VPN: &fakeVPN{}, AfterVPNStart: func() error { calls++; return nil }}
	for _, op := range []string{"start", "restart", "stop", "reconnect"} {
		r := httptest.NewRequest("POST", "/api/vpn/"+op, nil)
		r.SetPathValue("op", op)
		w := httptest.NewRecorder()
		srv.handleProc("vpn", srv.VPN, true)(w, r, &store.User{Username: "admin"})
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", op, w.Code, w.Body)
		}
	}
	if calls != 2 {
		t.Fatalf("AfterVPNStart ran %d times, want 2 (start, restart)", calls)
	}
}
