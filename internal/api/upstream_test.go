package api

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

func TestPickFreeIP(t *testing.T) {
	ip, err := pickFreeIP("10.8.0.0/24", nil, nil)
	if err != nil || ip != "10.8.0.2" {
		t.Fatalf("got %q, %v; want 10.8.0.2 (skip network+server)", ip, err)
	}

	live := []controller.VPNClient{{VirtualAddress: "10.8.0.2"}}
	reserved := map[string]bool{"10.8.0.3": true}
	ip, err = pickFreeIP("10.8.0.0/24", live, reserved)
	if err != nil || ip != "10.8.0.4" {
		t.Fatalf("got %q, %v; want 10.8.0.4 (skip live and reserved)", ip, err)
	}

	if _, err := pickFreeIP("not-a-cidr", nil, nil); err == nil {
		t.Fatal("bad subnet must error")
	}
}

func TestPickFreeIPExhausted(t *testing.T) {
	// /30: only .1 (server) and .2 are usable; .2 is taken, nothing left.
	live := []controller.VPNClient{{VirtualAddress: "10.8.0.2"}}
	if _, err := pickFreeIP("10.8.0.0/30", live, nil); err == nil {
		t.Fatal("exhausted subnet must error, not loop forever or return a bad address")
	}
}

func TestUpstreamTracker(t *testing.T) {
	var tr upstreamTracker
	if _, ok := tr.get("cid1"); ok {
		t.Fatal("empty tracker should have nothing")
	}
	tr.set("cid1", trackedRule{handle: 5, ip: "10.8.0.5", cn: "alice"})
	e, ok := tr.get("cid1")
	if !ok || e.handle != 5 || e.ip != "10.8.0.5" {
		t.Fatalf("got %+v, %v", e, ok)
	}
	tr.setHandle("cid1", 6)
	if e, _ := tr.get("cid1"); e.handle != 6 || e.ip != "10.8.0.5" {
		t.Fatalf("setHandle must update handle without touching ip/cn: %+v", e)
	}
	tr.delete("cid1")
	if _, ok := tr.get("cid1"); ok {
		t.Fatal("delete must remove the entry")
	}
}

// TestAllocateAvoidsAlreadyReserved: allocate must skip an IP a prior
// allocate already reserved for a different cid — the exact collision that
// used to happen between a per-CN push and OpenVPN's own pool, now that
// every connect goes through this one path.
func TestAllocateAvoidsAlreadyReserved(t *testing.T) {
	var tr upstreamTracker
	ip1, err := tr.allocate("cid1", "alice", "10.8.0.0/24", nil)
	if err != nil || ip1 != "10.8.0.2" {
		t.Fatalf("got %q, %v; want 10.8.0.2", ip1, err)
	}
	ip2, err := tr.allocate("cid2", "bob", "10.8.0.0/24", nil)
	if err != nil || ip2 == ip1 {
		t.Fatalf("got %q, %v; want a different ip than %q", ip2, err, ip1)
	}
	e, ok := tr.get("cid1")
	if !ok || e.ip != ip1 || e.cn != "alice" || e.handle != 0 {
		t.Fatalf("allocate must track ip/cn with handle 0 (no nft rule yet): %+v", e)
	}
}

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

// TestReconcileReinstallsTrackedRules: a second Apply (e.g. an unrelated
// `upstream add` while a per-CN client is connected) deletes the whole nft
// table, wiping any incrementally-added client rule — must be reinstalled.
func TestReconcileReinstallsTrackedRules(t *testing.T) {
	nft := requireRealNFT(t)
	srv := testUpstreamServer(t)
	srv.UpstreamsEnabled = true
	upCfg := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "lo-test", Iface: "lo", Table: 100}},
		PerCN:     map[string]string{"alice": "lo-test"},
	}
	if err := SaveUpstreamConfig(srv.Store, upCfg); err != nil {
		t.Fatal(err)
	}
	if err := upstream.Apply(upCfg, ""); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer upstream.Teardown()

	handle, err := upstream.AddClientRule("10.8.0.77", 100)
	if err != nil {
		t.Fatalf("AddClientRule: %v", err)
	}
	srv.upstream.set("1", trackedRule{handle: handle, ip: "10.8.0.77", cn: "alice"})

	// Simulates an unrelated admin mutation triggering a routine re-apply
	// of the same base config while alice is connected.
	if _, warning := srv.ReconcileUpstreams(); warning != "" {
		t.Fatalf("unexpected warning: %s", warning)
	}

	out, _ := exec.Command(nft, "list", "chain", "inet", "ovcp-upstreams", "ovcp-prerouting").CombinedOutput()
	if !strings.Contains(string(out), "10.8.0.77") {
		t.Fatalf("tracked client rule did not survive reconcile:\n%s", out)
	}
}

// TestOnClientConnectNoOverrideStillGetsIP: this handler only ever runs
// while management-client-auth is active (some CN is overridden), and once
// it does, every connecting client needs an ovcp-assigned IP — not just
// overridden ones — or they fall back to OpenVPN's own --ifconfig-pool,
// which doesn't know an override already claimed an address from under it.
func TestOnClientConnectNoOverrideStillGetsIP(t *testing.T) {
	srv := testUpstreamServer(t)
	if err := os.WriteFile(srv.Mgmt.StatusPath, []byte("TITLE\tfake\r\nEND\r\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SaveUpstreamConfig(srv.Store, upstream.Config{PerCN: map[string]string{"bob": "wan2"}}); err != nil {
		t.Fatal(err)
	}
	reply := srv.OnClientConnect("1", "0", map[string]string{"common_name": "alice"})
	if reply.Deny != "" || len(reply.Directives) != 1 {
		t.Fatalf("got %+v, want one ifconfig-push — alice has no override but still needs an ip", reply)
	}
	e, ok := srv.upstream.get("1")
	if !ok || e.handle != 0 {
		t.Fatalf("got %+v, %v; want tracked with no nft rule (alice isn't overridden)", e, ok)
	}
}

// TestOnClientConnectNoCollisionAcrossOverrideAndPlain is the regression
// test for the bug this replaces: a per-CN client and a plain client used
// to draw from two unrelated allocators (ovcp's push vs OpenVPN's own
// pool) and could both land on the same address. Now there's one allocator
// for both.
func TestOnClientConnectNoCollisionAcrossOverrideAndPlain(t *testing.T) {
	requireRealNFT(t)
	srv := testUpstreamServer(t)
	if err := os.WriteFile(srv.Mgmt.StatusPath, []byte("TITLE\tfake\r\nEND\r\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	upCfg := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "lo-test", Iface: "lo", Table: 100}},
		PerCN:     map[string]string{"alice": "lo-test"},
	}
	if err := SaveUpstreamConfig(srv.Store, upCfg); err != nil {
		t.Fatal(err)
	}
	if err := upstream.Apply(upCfg, ""); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer upstream.Teardown()

	aliceReply := srv.OnClientConnect("1", "0", map[string]string{"common_name": "alice"})
	bobReply := srv.OnClientConnect("2", "0", map[string]string{"common_name": "bob"})
	if aliceReply.Deny != "" || bobReply.Deny != "" {
		t.Fatalf("unexpected deny: alice=%+v bob=%+v", aliceReply, bobReply)
	}
	aliceIP, _ := srv.upstream.get("1")
	bobIP, _ := srv.upstream.get("2")
	if aliceIP.ip == bobIP.ip {
		t.Fatalf("collision: both got %q", aliceIP.ip)
	}
}

func TestOnClientConnectReauthSkipsReAdd(t *testing.T) {
	srv := testUpstreamServer(t)
	srv.upstream.set("1", trackedRule{handle: 9, ip: "10.8.0.9", cn: "alice"})
	reply := srv.OnClientConnect("1", "0", map[string]string{"common_name": "alice"})
	if reply.Deny != "" || len(reply.Directives) != 0 {
		t.Fatalf("got %+v, want a plain approve for an already-tracked cid", reply)
	}
}

// TestOnClientConnectDeniesOnStatusError: with no live client list to check
// against, proceeding could hand an IP to two clients at once. Testable
// without nft — Status() failing means AddClientRule is never reached.
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

// TestOnClientConnectRoundTripRealNFT exercises the whole path against real
// nft: a real upstream, a PerCN override, a connect that installs the rule
// and returns ifconfig-push, then a disconnect that removes it.
func TestOnClientConnectRoundTripRealNFT(t *testing.T) {
	nft := requireRealNFT(t)
	srv := testUpstreamServer(t)
	// OnClientConnect needs a real (even if empty) status file — Status()
	// failing now correctly denies (see TestOnClientConnectDeniesOnStatusError).
	if err := os.WriteFile(srv.Mgmt.StatusPath, []byte("TITLE\tfake\r\nEND\r\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	upCfg := upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "lo-test", Iface: "lo", Table: 100}},
		PerCN:     map[string]string{"alice": "lo-test"},
	}
	if err := SaveUpstreamConfig(srv.Store, upCfg); err != nil {
		t.Fatal(err)
	}
	// s.LoadConfig() falls back to ovpnconf.Default()'s Subnet (10.8.0.0/24)
	// when nothing's persisted — no separate vpn_config setup needed.
	if err := upstream.Apply(upCfg, ""); err != nil { // just to create the table/chains
		t.Fatalf("Apply: %v", err)
	}
	defer upstream.Teardown()

	reply := srv.OnClientConnect("1", "0", map[string]string{"common_name": "alice"})
	if reply.Deny != "" {
		t.Fatalf("connect denied: %s", reply.Deny)
	}
	if len(reply.Directives) != 1 {
		t.Fatalf("want one ifconfig-push directive, got %v", reply.Directives)
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", "ovcp-upstreams", "ovcp-prerouting").CombinedOutput()
	if !strings.Contains(string(out), "10.8.0.") {
		t.Fatalf("rule not present after connect:\n%s", out)
	}

	srv.OnClientDisconnect("1", map[string]string{"common_name": "alice"})
	if _, ok := srv.upstream.get("1"); ok {
		t.Fatal("disconnect must clear the tracker entry")
	}
	out, _ = exec.Command(nft, "list", "chain", "inet", "ovcp-upstreams", "ovcp-prerouting").CombinedOutput()
	if strings.Contains(string(out), "10.8.0.") {
		t.Fatalf("rule still present after disconnect:\n%s", out)
	}
}

// A failed removal (bogus handle — nft has nothing to delete) must leave
// the entry tracked, not silently orphan it — OnVPNExit is the retry.
func TestOnClientDisconnectKeepsTrackingOnFailure(t *testing.T) {
	requireRealNFT(t)
	srv := testUpstreamServer(t)
	upCfg := upstream.Config{Upstreams: []upstream.Upstream{{ID: "lo-test", Iface: "lo", Table: 100}}}
	if err := upstream.Apply(upCfg, ""); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer upstream.Teardown()

	srv.upstream.set("1", trackedRule{handle: 99999, ip: "10.8.0.60", cn: "alice"})
	srv.OnClientDisconnect("1", map[string]string{"common_name": "alice"})
	if _, ok := srv.upstream.get("1"); !ok {
		t.Fatal("a failed removal must keep the entry tracked so OnVPNExit can retry it")
	}
}

// TestOnVPNExitClearsTrackedRules: openvpn's process exiting (Stop, Restart,
// or a crash) must wipe every per-CN rule it was holding — real nft, not
// just the in-memory tracker, since that's what a reconnecting client would
// otherwise silently inherit stale marking from.
func TestOnVPNExitClearsTrackedRules(t *testing.T) {
	nft := requireRealNFT(t)
	srv := testUpstreamServer(t)
	upCfg := upstream.Config{Upstreams: []upstream.Upstream{{ID: "lo-test", Iface: "lo", Table: 100}}}
	if err := upstream.Apply(upCfg, ""); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer upstream.Teardown()

	handle, err := upstream.AddClientRule("10.8.0.55", 100)
	if err != nil {
		t.Fatalf("AddClientRule: %v", err)
	}
	srv.upstream.set("1", trackedRule{handle: handle, ip: "10.8.0.55", cn: "alice"})

	srv.OnVPNExit()

	if _, ok := srv.upstream.get("1"); ok {
		t.Fatal("OnVPNExit must clear every tracked entry")
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", "ovcp-upstreams", "ovcp-prerouting").CombinedOutput()
	if strings.Contains(string(out), "10.8.0.55") {
		t.Fatalf("rule still present in nft after OnVPNExit:\n%s", out)
	}
}

// requireRealNFT skips t unless nft/ip work inside a throwaway unprivileged
// netns (unshare + nsenter, never real root). Same idea as
// upstream.RequireRealNFT, duplicated: _test.go symbols can't cross packages.
func requireRealNFT(t *testing.T) (nft string) {
	t.Helper()
	for _, bin := range []string{"unshare", "nsenter", "nft", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	holder := exec.Command("unshare", "--user", "--net", "--map-root-user", "--", "sleep", "3600")
	if err := holder.Start(); err != nil {
		t.Skipf("rootless netns unavailable (unshare): %v", err)
	}
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	pid := strconv.Itoa(holder.Process.Pid)

	dir := t.TempDir()
	for _, name := range []string{"ip", "nft"} {
		script := fmt.Sprintf("#!/bin/sh\nexec nsenter --target %s --net --user --preserve-credentials -- %s \"$@\"\n", pid, name)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Skipf("rootless netns: lo up failed: %v\n%s", err, out)
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("rootless netns nft probe failed: %v\n%s", err, out)
	}
	return "nft"
}
