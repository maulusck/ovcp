package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
