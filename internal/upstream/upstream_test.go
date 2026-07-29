package upstream

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ovcp/ovcp/internal/controller"
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
	c := valid()
	c.Default = "" // off: no mark rule, subnet keeps the host's own default route
	out := string(nftRuleset(c, "10.8.0.0/24"))
	if strings.Contains(out, "meta mark set") {
		t.Errorf("Default off must not emit a mark rule:\n%s", out)
	}
	if !strings.Contains(out, `oif "eth1" masquerade`) || !strings.Contains(out, `oif "wg0" masquerade`) {
		t.Errorf("NAT rules must still exist per upstream even when Default is off:\n%s", out)
	}
}

// Runs the real ruleset through real nft -c — caught the "mark" keyword
// bug our string-matching tests couldn't. Needs root: `sudo go test ./internal/upstream/...`.
func TestNFTRulesetValidatesAgainstRealNFT(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not on PATH")
	}
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs root (netlink cache access)")
	}
	c := Config{
		Upstreams: []Upstream{{ID: "lo-test", Iface: "lo", Table: tableBase}},
		Default:   "lo-test",
	}
	ruleset := nftRuleset(c, "10.8.0.0/24")
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the generated ruleset: %v\n%s\nruleset:\n%s", err, out, ruleset)
	}
}

func TestNFTRulesetActive(t *testing.T) {
	out := string(nftRuleset(valid(), "10.8.0.0/24"))
	if !strings.Contains(out, "ip saddr 10.8.0.0/24 meta mark set 100") {
		t.Errorf("missing mark rule for active default:\n%s", out)
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

	if err := Apply(valid(), "10.8.0.0/24"); err != nil {
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

	err := Apply(valid(), "10.8.0.0/24")
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

// TestApplyRejectsWhileBusy: the lock lives inside Apply itself, so every
// caller — API, CLI, serve's own startup/shutdown — shares one guard, not
// just whichever call site remembered to take it.
func TestApplyRejectsWhileBusy(t *testing.T) {
	applyMu.Lock()
	defer applyMu.Unlock()
	if err := Apply(Config{}, ""); !errors.Is(err, controller.ErrBusy) {
		t.Fatalf("got %v, want controller.ErrBusy", err)
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
