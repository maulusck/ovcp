package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ovcp/ovcp/internal/controller"
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

// TestUpstreamApplyResultJSONIsFlat guards the "don't break the web UI"
// requirement: Upstreams/Default/PerCN must stay at the JSON top level
// (embedded), not nested under a wrapper key.
func TestUpstreamApplyResultJSONIsFlat(t *testing.T) {
	cfg := upstream.Config{Default: "wan2"}
	data, err := json.Marshal(upstreamApplyResult{cfg, "some warning"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["Default"] != "wan2" || m["warning"] != "some warning" {
		t.Fatalf("got %s, want Default and warning both at top level", data)
	}
}

// TestOnClientConnectDeniesOnStatusError: with no live client list to check
// against, proceeding could hand an IP to two clients at once. Testable
// without nft — Status() failing means upstream.Connect is never reached.
func TestOnClientConnectDeniesOnStatusError(t *testing.T) {
	srv := testUpstreamServer(t) // Mgmt.StatusPath points at a nonexistent file
	upCfg := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "wan2", Iface: "eth1", Table: 100}},
		PerCN:     map[string]string{"alice": "wan2"},
	}
	if err := SaveUpstreamConfig(srv.Store, upCfg); err != nil {
		t.Fatal(err)
	}
	reply := srv.OnClientConnect("1", "0", map[string]string{"common_name": "alice"})
	if reply.Deny == "" {
		t.Fatal("want a deny when the live client list can't be read, not a silent proceed")
	}
}
