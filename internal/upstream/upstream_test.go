package upstream

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func valid() Config {
	return Config{
		Upstreams: []Upstream{
			{ID: "wan2", Iface: "eth1", Gateway: "192.0.2.1", Table: tableBase},
			{ID: "wg-mullvad", Iface: "wg0", Table: tableBase + 1}, // onlink, no gateway
		},
		Default: "wan2",
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(c *Config){
		"duplicate id": func(c *Config) {
			c.Upstreams = append(c.Upstreams, Upstream{ID: "wan2", Iface: "eth2", Table: tableBase + 2})
		},
		"empty iface":           func(c *Config) { c.Upstreams[0].Iface = "" },
		"bad gateway":           func(c *Config) { c.Upstreams[0].Gateway = "not-an-ip" },
		"table out of range":    func(c *Config) { c.Upstreams[0].Table = tableBase - 1 },
		"table collision":       func(c *Config) { c.Upstreams[1].Table = c.Upstreams[0].Table },
		"unknown default":       func(c *Config) { c.Default = "ghost" },
		"unknown per-cn target": func(c *Config) { c.PerCN = map[string]string{"alice": "ghost"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: expected error, got nil", name)
			}
		})
	}
}

func TestValidateSOCKS(t *testing.T) {
	c := Config{
		Upstreams: []Upstream{{ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase}},
		Default:   "tor",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid socks upstream rejected: %v", err)
	}
}

// TestValidateSOCKSTimeoutOverrides: per-upstream dial/handshake timeout
// overrides are accepted for socks-mode.
func TestValidateSOCKSTimeoutOverrides(t *testing.T) {
	c := Config{
		Upstreams: []Upstream{{
			ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase,
			DialTimeout: 5, HandshakeTimeout: 60,
		}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid socks timeout overrides rejected: %v", err)
	}
}

func TestValidateRejectsSOCKS(t *testing.T) {
	base := func() Upstream { return Upstream{ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase} }
	cases := map[string]Upstream{
		"socks with iface":      func() Upstream { u := base(); u.Iface = "eth0"; return u }(),
		"socks with gateway":    func() Upstream { u := base(); u.Gateway = "192.0.2.1"; return u }(),
		"non-socks5 scheme":     func() Upstream { u := base(); u.SOCKS = "http://127.0.0.1:9050"; return u }(),
		"missing port":          func() Upstream { u := base(); u.SOCKS = "socks5://127.0.0.1"; return u }(),
		"missing host":          func() Upstream { u := base(); u.SOCKS = "socks5://:9050"; return u }(),
		"unparseable url":       func() Upstream { u := base(); u.SOCKS = "socks5://%zz"; return u }(),
		"negative dial timeout": func() Upstream { u := base(); u.DialTimeout = -1; return u }(),
		"negative handshake timeout": func() Upstream {
			u := base()
			u.HandshakeTimeout = -1
			return u
		}(),
		"timeout on iface-mode": func() Upstream {
			u := Upstream{ID: "wan2", Iface: "eth1", Table: tableBase}
			u.DialTimeout = 5
			return u
		}(),
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			c := Config{Upstreams: []Upstream{u}}
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: expected error, got nil", name)
			}
		})
	}
}

func TestNextTable(t *testing.T) {
	if got, err := NextTable(nil); err != nil || got != tableBase {
		t.Fatalf("empty: got %d, %v; want %d, nil", got, err, tableBase)
	}
	existing := []Upstream{{Table: tableBase}, {Table: tableBase + 2}}
	if got, err := NextTable(existing); err != nil || got != tableBase+1 {
		t.Fatalf("gap: got %d, %v; want %d, nil", got, err, tableBase+1)
	}
	full := make([]Upstream, maxUpstreams)
	for i := range full {
		full[i] = Upstream{Table: tableBase + i}
	}
	if _, err := NextTable(full); err == nil {
		t.Fatal("full band: expected error, got nil")
	}
}

func TestResolve(t *testing.T) {
	c := valid()
	c.PerCN = map[string]string{"alice": "wg-mullvad"}
	if got := c.Resolve("alice"); got != "wg-mullvad" {
		t.Fatalf("per-cn override: got %q, want wg-mullvad", got)
	}
	if got := c.Resolve("bob"); got != "wan2" {
		t.Fatalf("fallthrough to default: got %q, want wan2", got)
	}
}

func TestAssign(t *testing.T) {
	c := valid()
	got, err := c.Assign("alice", "wan2", false)
	if err != nil || got.PerCN["alice"] != "wan2" {
		t.Fatalf("got %+v, %v", got.PerCN, err)
	}
	if c.PerCN != nil {
		t.Fatal("Assign must not mutate the receiver")
	}

	cleared, err := got.Assign("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cleared.PerCN["alice"]; ok {
		t.Fatal("clear must delete the key, not set it to empty")
	}

	if _, err := c.Assign("bob", "ghost-upstream", false); err == nil {
		t.Fatal("assigning to a nonexistent upstream must fail Validate")
	}

	// clearing a CN with no existing entry is a no-op, not an error.
	if _, err := c.Assign("nobody", "", true); err != nil {
		t.Fatalf("clearing an absent entry should be a harmless no-op: %v", err)
	}
}

func TestSetDefault(t *testing.T) {
	c := valid()
	got, err := c.SetDefault("wg-mullvad")
	if err != nil || got.Default != "wg-mullvad" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if c.Default != "wan2" {
		t.Fatal("SetDefault must not mutate the receiver")
	}

	off, err := got.SetDefault("")
	if err != nil || off.Default != "" {
		t.Fatalf("got %+v, %v; want off", off, err)
	}

	if _, err := c.SetDefault("ghost-upstream"); err == nil {
		t.Fatal("setting a nonexistent upstream as default must fail Validate")
	}
}

func TestWithAdded(t *testing.T) {
	c := valid()
	got, added, err := c.WithAdded(Upstream{ID: "tor-relay", Iface: "eth2"})
	if err != nil {
		t.Fatalf("WithAdded: %v", err)
	}
	if added.Table != tableBase+2 {
		t.Errorf("assigned table = %d, want %d", added.Table, tableBase+2)
	}
	if len(got.Upstreams) != 3 || len(c.Upstreams) != 2 {
		t.Errorf("got %d upstreams, orig still %d — mutated the receiver?", len(got.Upstreams), len(c.Upstreams))
	}
	if _, _, err := c.WithAdded(Upstream{ID: "wan2", Iface: "eth3"}); err == nil {
		t.Error("duplicate id should fail Validate")
	}
}

func TestWithoutClearsReferences(t *testing.T) {
	c := valid()
	c.PerCN = map[string]string{"alice": "wan2", "bob": "wg-mullvad"}
	got, found := c.Without("wan2")
	if !found {
		t.Fatal("expected found=true")
	}
	if len(got.Upstreams) != 1 || got.Upstreams[0].ID != "wg-mullvad" {
		t.Errorf("upstream not removed: %+v", got.Upstreams)
	}
	if got.Default != "" {
		t.Errorf("Default still points at removed upstream: %q", got.Default)
	}
	if _, ok := got.PerCN["alice"]; ok {
		t.Error("PerCN entry pointing at removed upstream not cleared")
	}
	if got.PerCN["bob"] != "wg-mullvad" {
		t.Error("unrelated PerCN entry should survive")
	}
	if _, found := c.Without("ghost"); found {
		t.Error("removing an unknown id should report found=false")
	}
}

func TestRouteArgsKillSwitch(t *testing.T) {
	u := Upstream{ID: "wan2", Iface: "eth1", Gateway: "192.0.2.1", Table: tableBase}
	args := routeArgs(u)
	if len(args) != 3 {
		t.Fatalf("got %d commands, want 3 (primary route, unreachable fallback, ip rule)", len(args))
	}
	joined := func(a []string) string { return strings.Join(a, " ") }
	if !strings.Contains(joined(args[0]), "via 192.0.2.1 dev eth1") {
		t.Errorf("primary route missing gateway/iface: %v", args[0])
	}
	if !strings.Contains(joined(args[1]), "unreachable default") {
		t.Errorf("no unreachable fallback route: %v", args[1])
	}
	if !strings.Contains(joined(args[2]), "fwmark 100 table 100") {
		t.Errorf("rule doesn't bind fwmark to table: %v", args[2])
	}
}

func TestRouteArgsOnlink(t *testing.T) {
	u := Upstream{ID: "wg-mullvad", Iface: "wg0", Table: tableBase}
	args := routeArgs(u)
	if strings.Contains(strings.Join(args[0], " "), "via") {
		t.Errorf("onlink upstream (no Gateway) shouldn't render 'via': %v", args[0])
	}
}

func TestNFTRulesetOff(t *testing.T) {
	defer swapIfaceExists(func(string) bool { return true })()
	c := valid()
	c.Default = "" // off: no mark rule, subnet keeps the host's own default route
	out := string(nftRuleset(c))
	if strings.Contains(out, "meta mark set") {
		t.Errorf("Default off must not emit a mark rule:\n%s", out)
	}
	if !strings.Contains(out, `oif "eth1" masquerade`) || !strings.Contains(out, `oif "wg0" masquerade`) {
		t.Errorf("NAT rules must still exist per upstream even when Default is off:\n%s", out)
	}
	// Transparent mode: unmarked (mark 0) traffic must still be masqueraded
	// out whatever the host's own routing picks — this is what used to be a
	// hand-maintained "baseline-nat" table outside ovcp entirely, lost on
	// every `nft flush ruleset`. Folded into ovcp's own reconciled table.
	if !strings.Contains(out, `iifname "ovcp0" meta mark 0 masquerade`) {
		t.Errorf("transparent mode must masquerade unmarked traffic via the host's own default route:\n%s", out)
	}
}

// swapIfaceExists overrides ifaceExists for a test, returning the restore func.
func swapIfaceExists(f func(string) bool) (restore func()) {
	prev := ifaceExists
	ifaceExists = f
	return func() { ifaceExists = prev }
}

// TestNFTRulesetSkipsMissingIface: a missing egress must not poison the
// whole ruleset (nft rejects one bad oif for the entire -f/-c input) — but
// must still mark its traffic, so Apply's kill-switch route catches it.
func TestNFTRulesetSkipsMissingIface(t *testing.T) {
	defer swapIfaceExists(func(name string) bool { return name == "wan2-iface" })()
	c := Config{
		Upstreams: []Upstream{
			{ID: "wan2", Iface: "wan2-iface", Table: tableBase},
			{ID: "ghost", Iface: "ghost-iface", Table: tableBase + 1},
		},
		Default: "ghost",
	}
	out := string(nftRuleset(c))
	if !strings.Contains(out, "meta mark set 101") {
		t.Errorf("missing-iface upstream must still be marked (kill-switch depends on it):\n%s", out)
	}
	if !strings.Contains(out, `oif "wan2-iface" masquerade`) {
		t.Errorf("a live upstream's masquerade rule must still be emitted:\n%s", out)
	}
	if strings.Contains(out, "ghost-iface") {
		t.Errorf("a missing-iface upstream must not appear in a masquerade rule (nft would reject the whole ruleset):\n%s", out)
	}
}

func TestDownIDsAndWarning(t *testing.T) {
	defer swapIfaceExists(func(name string) bool { return name == "wan2-iface" })()
	ups := []Upstream{
		{ID: "wan2", Iface: "wan2-iface", Table: tableBase},
		{ID: "ghost", Iface: "ghost-iface", Table: tableBase + 1},
	}
	if down := DownIDs(ups); len(down) != 1 || down[0] != "ghost" {
		t.Fatalf("DownIDs = %v, want [ghost]", down)
	}
	if w := Warning(ups); w != "unreachable (iface down): ghost" {
		t.Fatalf("Warning = %q", w)
	}
	if down := DownIDs(ups[:1]); down != nil {
		t.Fatalf("DownIDs = %v, want nil when all up", down)
	}
	if w := Warning(ups[:1]); w != "" {
		t.Fatalf("Warning = %q, want \"\" when all up", w)
	}
}

// Runs the real ruleset through real nft -c — caught the "mark" keyword
// bug our string-matching tests couldn't. Needs root: `sudo go test ./internal/upstream/...`.
func TestNFTRulesetValidatesAgainstRealNFT(t *testing.T) {
	nft := RequireRealNFT(t)
	c := Config{
		Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}},
		Default:   "lo-test",
	}
	ruleset := nftRuleset(c)
	cmd := exec.Command(nft, "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the generated ruleset: %v\n%s\nruleset:\n%s", err, out, ruleset)
	}
}

// TestNFTRulesetValidatesWithMissingIface: a real upstream (lo) plus one
// whose iface doesn't exist must still validate against real nft — the
// exact real-hardware failure (an upstream not up yet poisoned the whole ruleset).
func TestNFTRulesetValidatesWithMissingIface(t *testing.T) {
	nft := RequireRealNFT(t)
	c := Config{
		Upstreams: []Upstream{
			{ID: "lo-test", Iface: "lo", Table: tableBase},
			{ID: "ghost", Iface: "ovcp-test-ghost0", Table: tableBase + 1},
		},
		Default: "ghost",
	}
	ruleset := nftRuleset(c)
	cmd := exec.Command(nft, "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the ruleset despite the missing-iface guard: %v\n%s\nruleset:\n%s", err, out, ruleset)
	}
}

// TestNFTRulesetValidatesTransparentMode: the catch-all "mark 0" masquerade
// rule (Default off, replacing the old hand-maintained baseline-nat table)
// must itself be valid nft syntax, not just string-matched.
func TestNFTRulesetValidatesTransparentMode(t *testing.T) {
	nft := RequireRealNFT(t)
	ruleset := nftRuleset(Config{})
	cmd := exec.Command(nft, "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the transparent-mode ruleset: %v\n%s\nruleset:\n%s", err, out, ruleset)
	}
}

func TestNFTRulesetActive(t *testing.T) {
	out := string(nftRuleset(valid()))
	if !strings.Contains(out, `iifname "ovcp0" meta mark set 100`) {
		t.Errorf("missing mark rule for active default:\n%s", out)
	}
	if strings.Contains(out, "ip saddr") {
		t.Fatalf("no base rule may trust a source address, another host can forge it:\n%s", out)
	}
}

// TestNFTRulesetPerCNWithNoDefault: a per-CN override with no server-wide
// default set must skip the blanket tunnel-wide mark line entirely (there's
// no Default to resolve to) while still falling through to the transparent
// masquerade for mark 0 — a non-overridden client must still reach the
// internet, just not via any upstream.
func TestNFTRulesetPerCNWithNoDefault(t *testing.T) {
	c := Config{
		Upstreams: []Upstream{{ID: "wan1", Iface: "eth1", Table: tableBase}},
		PerCN:     map[string]string{"alice": "wan1"},
	}
	out := string(nftRuleset(c))
	if strings.Contains(out, "meta mark set") {
		t.Errorf("no Default is set — must not emit a blanket tunnel-wide mark rule:\n%s", out)
	}
	if !strings.Contains(out, `iifname "ovcp0" meta mark 0 masquerade`) {
		t.Errorf("missing transparent fallback for non-overridden clients:\n%s", out)
	}
}

func TestNFTRulesetSOCKSRedirect(t *testing.T) {
	defer swapIfaceExists(func(string) bool { return true })()
	c := Config{
		Upstreams: []Upstream{
			{ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase},
			{ID: "wan2", Iface: "eth1", Table: tableBase + 1},
		},
		Default: "tor",
	}
	out := string(nftRuleset(c))
	if !strings.Contains(out, "meta mark 100 meta l4proto tcp redirect to :20000") {
		t.Errorf("missing socks redirect rule:\n%s", out)
	}
	if strings.Contains(out, "mark 100 oif") {
		t.Errorf("socks-kind upstream must not get a masquerade rule:\n%s", out)
	}
	if !strings.Contains(out, `oif "eth1" masquerade`) {
		t.Errorf("iface-kind upstream masquerade must be unaffected:\n%s", out)
	}
	if !strings.Contains(out, `iifname "ovcp0" meta mark set 100`) {
		t.Errorf("missing mark rule for socks default:\n%s", out)
	}
}

// Real-nft-gated: string-matching tests can't tell valid nft syntax from
// invalid (the "mark" keyword bug already taught this package that lesson).
func TestNFTRulesetValidatesSOCKSAgainstRealNFT(t *testing.T) {
	nft := RequireRealNFT(t)
	c := Config{
		Upstreams: []Upstream{{ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase}},
		Default:   "tor",
	}
	ruleset := nftRuleset(c)
	cmd := exec.Command(nft, "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the socks redirect ruleset: %v\n%s\nruleset:\n%s", err, out, ruleset)
	}
}

// A socks-kind upstream has no interface to route via — Apply must not emit
// any ip route/rule for it, only the nft redirect (checked separately above).
func TestApplySkipsRouteCommandsForSOCKS(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	fake := func(name string) string {
		p := filepath.Join(dir, name)
		script := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\nexit 0\n"
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	origIP, origNFT := ipBin, nftBin
	ipBin, nftBin = fake("ip"), fake("nft")
	defer func() { ipBin, nftBin = origIP, origNFT }()

	cfg := Config{
		Upstreams: []Upstream{{ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase}},
		Default:   "tor",
	}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()
	out, _ := os.ReadFile(log)
	if strings.Contains(string(out), "route replace default") {
		t.Errorf("socks-kind upstream must not get an ip route:\n%s", out)
	}
	if !strings.Contains(string(out), "-c -f -") {
		t.Error("nft apply must still run for a socks-only config")
	}
}

func TestTeardownArgsCoversWholeBand(t *testing.T) {
	args := teardownArgs()
	if len(args) != maxUpstreams*2 {
		t.Fatalf("got %d commands, want %d (rule del + route flush per slot)", len(args), maxUpstreams*2)
	}
}

// Exercises Apply's orchestration against fake ip/nft scripts that log their
// invocation — same stand-in as controller_test.fakeOpenVPN.
func TestApplyInvokesFakeTools(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	fake := func(name string) string {
		p := filepath.Join(dir, name)
		script := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\nexit 0\n"
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	origIP, origNFT := ipBin, nftBin
	ipBin, nftBin = fake("ip"), fake("nft")
	defer func() { ipBin, nftBin = origIP, origNFT }()

	if err := Apply(valid()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "rule del priority") {
		t.Error("missing teardown of the reserved ip-rule band")
	}
	if !strings.Contains(got, "route replace default via 192.0.2.1") {
		t.Error("missing rebuilt route for the wan2 upstream")
	}
	if !strings.Contains(got, "-c -f -") {
		t.Error("missing nft check-mode pass before real apply")
	}
	if !strings.Contains(got, "delete table inet "+nftTable) {
		t.Error("missing best-effort delete of any prior nft table")
	}
}

// Locks in the fail-closed fix: one upstream's route failing must not skip
// its own kill-switch route or the nft mark table — that would fail open.
func TestApplyContinuesAfterOneUpstreamFails(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	ipScript := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\ncase \"$*\" in *eth1*) exit 1;; esac\nexit 0\n"
	ipPath := filepath.Join(dir, "ip")
	if err := os.WriteFile(ipPath, []byte(ipScript), 0o755); err != nil {
		t.Fatal(err)
	}
	nftPath := filepath.Join(dir, "nft")
	nftScript := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(nftPath, []byte(nftScript), 0o755); err != nil {
		t.Fatal(err)
	}
	origIP, origNFT := ipBin, nftBin
	ipBin, nftBin = ipPath, nftPath
	defer func() { ipBin, nftBin = origIP, origNFT }()

	err := Apply(valid())
	if err == nil {
		t.Fatal("expected an error surfacing the eth1 failure, got nil")
	}
	out, _ := os.ReadFile(log)
	got := string(out)
	if !strings.Contains(got, "unreachable default table 100") {
		t.Error("eth1's own kill-switch fallback route must still be attempted after its primary route fails")
	}
	if !strings.Contains(got, "table 101") {
		t.Error("the other (working) upstream's routes must still be attempted")
	}
	if !strings.Contains(got, "-c -f -") || !strings.Contains(got, " -f -") {
		t.Error("nft mark/NAT table must still be attempted despite the route failure — skipping it fails open")
	}
}

func TestValidateRejectsBadIface(t *testing.T) {
	bad := []string{"", "eth1;rm -rf", "eth 1", "eth1\"; add rule x", strings.Repeat("a", 16)}
	for _, iface := range bad {
		c := valid()
		c.Upstreams[0].Iface = iface
		if err := c.Validate(); err == nil {
			t.Errorf("iface %q should be rejected", iface)
		}
	}
}

// TestApplyWaitsWhileBusy: used to be a TryLock that silently dropped a
// racing Apply (ErrBusy, config change never lands, caller sees no
// error) — an E2E test caught two close-together CLI calls hitting this.
func TestApplyWaitsWhileBusy(t *testing.T) {
	RequireRealNFT(t)
	applyMu.Lock()
	release := make(chan struct{})
	go func() {
		<-release
		time.Sleep(50 * time.Millisecond)
		applyMu.Unlock()
	}()

	done := make(chan error, 1)
	go func() { done <- Apply(Config{}) }()

	select {
	case <-done:
		t.Fatal("Apply returned while applyMu was still held — it must wait, not give up")
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Apply after waiting its turn: %v", err)
		}
	case <-time.After(10 * time.Second): // a deadlock check: real nft under full-suite load can take seconds
		t.Fatal("Apply never returned after the lock was released")
	}
}

func TestParseHandle(t *testing.T) {
	out := "add rule inet ovcp-upstreams ovcp-prerouting ip saddr 10.8.0.55 meta mark set 0x64 # handle 7\n# new generation 4 by process 123 (nft)\n"
	got, err := parseHandle([]byte(out))
	if err != nil || got != 7 {
		t.Fatalf("got %d, %v; want 7, nil", got, err)
	}
	if _, err := parseHandle([]byte("no handle here\n")); err == nil {
		t.Fatal("expected error when no handle line present")
	}
}

func TestAddRuleBadIP(t *testing.T) {
	if _, err := addRule("not-an-ip", tableBase); err == nil {
		t.Fatal("expected error for invalid ip")
	}
}

// TestAddRuleFakeNFT checks argv shape and handle parsing without a real
// nft — same fake-script stand-in as TestApplyInvokesFakeTools.
func TestAddRuleFakeNFT(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"add rule inet x y ip saddr 10.8.0.55 meta mark set 0x64 # handle 9\"\n"
	p := filepath.Join(dir, "nft")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := nftBin
	nftBin = p
	defer func() { nftBin = orig }()

	handle, err := addRule("10.8.0.55", tableBase)
	if err != nil || handle != 9 {
		t.Fatalf("got %d, %v; want 9, nil", handle, err)
	}
}

// Add/removeRule against real nft: rule appears, then really gone.
func TestClientRuleRoundTripRealNFT(t *testing.T) {
	nft := RequireRealNFT(t)
	cfg := Config{Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}}}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()

	handle, err := addRule("10.8.0.77", tableBase)
	if err != nil {
		t.Fatalf("addRule: %v", err)
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if !strings.Contains(string(out), "10.8.0.77") {
		t.Fatalf("rule not present after add:\n%s", out)
	}

	if err := removeRule(handle); err != nil {
		t.Fatalf("removeRule: %v", err)
	}
	out, _ = exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if strings.Contains(string(out), "10.8.0.77") {
		t.Fatalf("rule still present after remove:\n%s", out)
	}
}

// TestEstablishIgnoresPlainClients: ovcp never chooses or tracks an
// address for a cn with no override — OpenVPN's own ifconfig-pool already
// handled it, there's nothing here for ovcp to do.
func TestEstablishIgnoresPlainClients(t *testing.T) {
	defer func() { tracked = map[string]trackedRule{} }()
	cfg := Config{PerCN: map[string]string{"bob": "wan2"}}
	if err := Establish("1", "alice", "10.8.0.55", cfg); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if _, ok := tracked["1"]; ok {
		t.Fatal("a plain (non-overridden) client must not be tracked at all")
	}
}

// TestEstablishDeniesOnBadOverride: an override pointing at a since-deleted
// upstream must error, not silently proceed or track anything.
func TestEstablishDeniesOnBadOverride(t *testing.T) {
	defer func() { tracked = map[string]trackedRule{} }()
	cfg := Config{PerCN: map[string]string{"alice": "gone"}}
	if err := Establish("1", "alice", "10.8.0.55", cfg); err == nil {
		t.Fatal("want an error, assigned upstream no longer exists")
	}
	if _, ok := tracked["1"]; ok {
		t.Fatal("a failed establish must not leave a tracked entry behind")
	}
}

// TestEstablishAndDisconnectRoundTripRealNFT exercises the whole path
// against real nft: a per-CN override installs the rule for the address
// OpenVPN's own pool already assigned, then removes it on disconnect.
func TestEstablishAndDisconnectRoundTripRealNFT(t *testing.T) {
	nft := RequireRealNFT(t)
	cfg := Config{
		Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}},
		PerCN:     map[string]string{"alice": "lo-test"},
	}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()

	if err := Establish("1", "alice", "10.8.0.42", cfg); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if !strings.Contains(string(out), "10.8.0.42") {
		t.Fatalf("rule not present after establish:\n%s", out)
	}

	Disconnect("1")
	if _, ok := tracked["1"]; ok {
		t.Fatal("disconnect must clear the tracked entry")
	}
	out, _ = exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if strings.Contains(string(out), "10.8.0.42") {
		t.Fatalf("rule still present after disconnect:\n%s", out)
	}
}

// TestReassignInstallsRuleForUntrackedCid: Reassign doesn't require
// Establish to have tracked cid first — a plain client's first-ever
// override takes effect immediately, the same as changing an existing one.
func TestReassignInstallsRuleForUntrackedCid(t *testing.T) {
	nft := RequireRealNFT(t)
	cfg := Config{
		Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}},
		PerCN:     map[string]string{"alice": "lo-test"},
	}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()
	defer func() { tracked = map[string]trackedRule{} }()

	if err := Reassign("1", "alice", "10.8.0.42", cfg); err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if !strings.Contains(string(out), "10.8.0.42") {
		t.Fatalf("rule not present after reassign:\n%s", out)
	}
	if tracked["1"].ip != "10.8.0.42" {
		t.Fatalf("got %+v, want it tracked now", tracked["1"])
	}
}

// TestReassignClearingUntrackedCidIsNoOp: clearing an override for a cid
// that was never overridden to begin with must be a harmless no-op.
func TestReassignClearingUntrackedCidIsNoOp(t *testing.T) {
	if err := Reassign("1", "alice", "10.8.0.42", Config{}); err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	if _, ok := tracked["1"]; ok {
		t.Fatal("must not track a cid that has no override and was never tracked")
	}
}

// TestReassignReplacesExistingRule: changing an already-overridden client's
// upstream removes the old rule and installs the new one.
func TestReassignReplacesExistingRule(t *testing.T) {
	nft := RequireRealNFT(t)
	cfg := Config{
		Upstreams: []Upstream{
			{ID: "lo-test", Iface: "lo", Table: tableBase},
			{ID: "lo-test2", Iface: "lo", Table: tableBase + 1},
		},
	}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()
	defer func() { tracked = map[string]trackedRule{} }()

	first := cfg
	first.PerCN = map[string]string{"alice": "lo-test"}
	if err := Reassign("1", "alice", "10.8.0.42", first); err != nil {
		t.Fatalf("Reassign(first): %v", err)
	}
	oldHandle := tracked["1"].handle

	second := cfg
	second.PerCN = map[string]string{"alice": "lo-test2"}
	if err := Reassign("1", "alice", "10.8.0.42", second); err != nil {
		t.Fatalf("Reassign(second): %v", err)
	}
	if tracked["1"].handle == oldHandle {
		t.Fatal("changing upstream must install a new rule, not reuse the old handle")
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if !strings.Contains(string(out), fmt.Sprintf("mark set 0x%08x", tableBase+1)) {
		t.Fatalf("rule doesn't reflect the new upstream's table:\n%s", out)
	}
}

// TestReassignClearsExistingOverride: clearing an already-overridden
// client's assignment removes its rule and untracks it.
func TestReassignClearsExistingOverride(t *testing.T) {
	nft := RequireRealNFT(t)
	cfg := Config{Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}}}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()
	defer func() { tracked = map[string]trackedRule{} }()

	overridden := cfg
	overridden.PerCN = map[string]string{"alice": "lo-test"}
	if err := Reassign("1", "alice", "10.8.0.42", overridden); err != nil {
		t.Fatalf("Reassign(install): %v", err)
	}
	if err := Reassign("1", "alice", "10.8.0.42", cfg); err != nil { // cfg has no override for alice
		t.Fatalf("Reassign(clear): %v", err)
	}
	if _, ok := tracked["1"]; ok {
		t.Fatal("clearing an override must untrack the client")
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if strings.Contains(string(out), "10.8.0.42") {
		t.Fatalf("rule still present after clearing override:\n%s", out)
	}
}

// A failed removal (bogus handle — nft has nothing to delete) must leave
// the entry tracked, not silently orphan it — ClearAll is the retry.
func TestDisconnectKeepsTrackingOnFailure(t *testing.T) {
	RequireRealNFT(t)
	if err := Apply(Config{Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()
	defer func() { tracked = map[string]trackedRule{} }()

	tracked["1"] = trackedRule{handle: 99999, ip: "10.8.0.60", cn: "alice"}
	Disconnect("1")
	if _, ok := tracked["1"]; !ok {
		t.Fatal("a failed removal must keep the entry tracked so ClearAll can retry it")
	}
}

// TestClearAllRemovesRules: openvpn's process exiting (Stop, Restart, or a
// crash) must wipe every per-CN rule it was holding — real nft, not just
// the in-memory tracker, since that's what a reconnecting client would
// otherwise silently inherit stale marking from.
func TestClearAllRemovesRules(t *testing.T) {
	nft := RequireRealNFT(t)
	if err := Apply(Config{Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()

	handle, err := addRule("10.8.0.55", tableBase)
	if err != nil {
		t.Fatalf("addRule: %v", err)
	}
	tracked["1"] = trackedRule{handle: handle, ip: "10.8.0.55", cn: "alice"}

	ClearAll()

	if _, ok := tracked["1"]; ok {
		t.Fatal("ClearAll must clear every tracked entry")
	}
	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if strings.Contains(string(out), "10.8.0.55") {
		t.Fatalf("rule still present in nft after ClearAll:\n%s", out)
	}
}

// TestApplyReinstallsTrackedRules: a second Apply (e.g. an unrelated
// `upstream add` while a per-CN client is connected) deletes the whole nft
// table, wiping any incrementally-added client rule — must be reinstalled.
func TestApplyReinstallsTrackedRules(t *testing.T) {
	nft := RequireRealNFT(t)
	cfg := Config{
		Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}},
		PerCN:     map[string]string{"alice": "lo-test"},
	}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer Teardown()

	if err := Establish("1", "alice", "10.8.0.42", cfg); err != nil {
		t.Fatalf("Establish: %v", err)
	}

	// Simulates an unrelated admin mutation triggering a routine re-apply of
	// the same base config while alice is connected.
	if err := Apply(cfg); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	out, _ := exec.Command(nft, "list", "chain", "inet", nftTable, preroutingChain).CombinedOutput()
	if !strings.Contains(string(out), "10.8.0.42") {
		t.Fatalf("tracked client rule did not survive reconcile:\n%s", out)
	}
}

// TestEstablishRaceAgainstUpstreamDeletion: Establish can be called with a
// cfg snapshot taken just before a concurrent `upstream del` removes the
// very upstream it references (Establish's caller loads cfg, then an admin
// deletes the upstream, then Establish actually runs) — whichever of
// Establish/Apply wins applyMu first, this must never panic or deadlock,
// and the very next Apply must fully reconcile away any leftover tracking
// for a cn the config no longer overrides.
func TestEstablishRaceAgainstUpstreamDeletion(t *testing.T) {
	RequireRealNFT(t)
	stale := Config{
		Upstreams: []Upstream{{ID: "wan1", Iface: "lo", Table: tableBase}},
		PerCN:     map[string]string{"alice": "wan1"},
	}
	if err := Apply(stale); err != nil {
		t.Fatalf("Apply(stale): %v", err)
	}
	defer Teardown()

	after, found := stale.Without("wan1")
	if !found {
		t.Fatal("setup: Without should have found wan1")
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); Establish("1", "alice", "10.8.0.42", stale) }()
	go func() { defer wg.Done(); Apply(after) }()
	wg.Wait()

	if err := Apply(after); err != nil {
		t.Fatalf("Apply(after): %v", err)
	}
	if _, ok := tracked["1"]; ok {
		t.Fatal("a deleted upstream's override must not survive reconciliation")
	}
}

func TestTeardownIsApplyWithEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	fake := func(name string) string {
		p := filepath.Join(dir, name)
		script := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\nexit 0\n"
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	origIP, origNFT := ipBin, nftBin
	ipBin, nftBin = fake("ip"), fake("nft")
	defer func() { ipBin, nftBin = origIP, origNFT }()

	if err := Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	out, _ := os.ReadFile(log)
	if !strings.Contains(string(out), "rule del priority") {
		t.Error("Teardown must still sweep the reserved band")
	}
}

// RequireRealNFT skips t unless nft/ip work inside a throwaway unprivileged
// netns (unshare + nsenter, never real root). Swaps ipBin/nftBin for t's
// duration, returns the nft binary callers should verify against.
func RequireRealNFT(t *testing.T) (nft string) {
	t.Helper()
	nftReal, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not on PATH")
	}
	ipReal, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip not on PATH")
	}
	prevIP, prevNft := ipBin, nftBin
	t.Cleanup(func() { ipBin, nftBin = prevIP, prevNft })

	holder := exec.Command("unshare", "--user", "--net", "--map-root-user", "--", "sleep", "3600")
	if err := holder.Start(); err != nil {
		t.Skipf("rootless netns unavailable (unshare): %v", err)
	}
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	pid := strconv.Itoa(holder.Process.Pid)

	dir := t.TempDir()
	ipBin = nsWrap(t, dir, "ip", pid, ipReal)
	nftBin = nsWrap(t, dir, "nft", pid, nftReal)

	// A fresh netns's lo exists but starts administratively down — routing
	// tests that use it (the one interface guaranteed to exist anywhere)
	// need it up first.
	if out, err := exec.Command(ipBin, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Skipf("rootless netns: bringing up lo failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(nftBin, "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("rootless netns nft probe failed: %v\n%s", err, out)
	}
	return nftBin
}

// nsWrap writes a wrapper script that re-enters holder's (pid) net+user
// namespace before exec'ing realBin.
func nsWrap(t *testing.T, dir, name, pid, realBin string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nexec nsenter --target %s --net --user --preserve-credentials -- %s \"$@\"\n", pid, realBin)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
