// Package upstream steers connected VPN clients' outbound traffic through an
// admin-chosen egress instead of the box's own default route — policy routing + NAT only, ovcp never brings the upstream connection itself up.
package upstream

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ovcp/ovcp/internal/controller"
)

// Reserved band ovcp exclusively owns — never touches a rule/table outside
// these ranges, so it can never step on another service's routing.
const (
	tableBase    = 100
	maxUpstreams = 64
	rulePrioBase = 20000
	nftTable     = "ovcp-upstreams"
)

// ipBin/nftBin: package vars, not hardcoded argv[0], so tests can swap in a fake script.
var (
	ipBin  = "ip"
	nftBin = "nft"
)

// applyMu serializes every Apply call in this process — intrinsic to Apply
// itself so every caller (API, CLI, serve's startup/shutdown) shares it.
var applyMu sync.Mutex

type Upstream struct {
	ID          string // slug, referenced by Config.Default/PerCN
	Iface       string // egress interface; admin brings it up, ovcp only references it
	Gateway     string // next-hop IP; empty = onlink route via Iface
	Table       int    // routing table number, assigned once via NextTable, stable
	Description string
}

type Config struct {
	Upstreams []Upstream
	Default   string // active Upstream.ID server-wide; "" = off, host's own default route

	// PerCN: not wired to anything yet — needs static per-CN tunnel IPs first.
	// Kept on this same Config, not a parallel mechanism, so it's additive later.
	PerCN map[string]string
}

// Resolve is the one place that decides which upstream a client's traffic
// uses: a per-CN override if PerCN has one, else Default.
func (c Config) Resolve(cn string) string {
	if id, ok := c.PerCN[cn]; ok {
		return id
	}
	return c.Default
}

// WithAdded assigns u the next free table via NextTable, appends it, and
// validates the result — the one path both the API and CLI add through.
func (c Config) WithAdded(u Upstream) (cfg Config, added Upstream, err error) {
	if u.Table, err = NextTable(c.Upstreams); err != nil {
		return c, Upstream{}, err
	}
	cfg = c
	cfg.Upstreams = append(append([]Upstream{}, c.Upstreams...), u)
	if err := cfg.Validate(); err != nil {
		return c, Upstream{}, err
	}
	return cfg, u, nil
}

// Without returns cfg with id's upstream removed and any Default/PerCN
// reference to it cleared — the one path both the API and CLI delete through.
func (c Config) Without(id string) (cfg Config, found bool) {
	kept := make([]Upstream, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.ID == id {
			found = true
			continue
		}
		kept = append(kept, u)
	}
	cfg = c
	cfg.Upstreams = kept
	if cfg.Default == id {
		cfg.Default = ""
	}
	if cfg.PerCN != nil {
		perCN := make(map[string]string, len(cfg.PerCN))
		for cn, target := range cfg.PerCN {
			if target != id {
				perCN[cn] = target
			}
		}
		cfg.PerCN = perCN
	}
	return cfg, found
}

func (c Config) find(id string) (Upstream, bool) {
	for _, u := range c.Upstreams {
		if u.ID == id {
			return u, true
		}
	}
	return Upstream{}, false
}

// NextTable picks the lowest free table number in the managed band — stable
// for every other upstream, since it only looks at what's currently used.
func NextTable(existing []Upstream) (int, error) {
	used := make(map[int]bool, len(existing))
	for _, u := range existing {
		used[u.Table] = true
	}
	for i := 0; i < maxUpstreams; i++ {
		if t := tableBase + i; !used[t] {
			return t, nil
		}
	}
	return 0, fmt.Errorf("upstream: no free table slot (max %d upstreams)", maxUpstreams)
}

// ifaceRe: Linux interface names, max IFNAMSIZ-1 (15) bytes. Iface ends up
// both as an ip(8) argv element (no shell, safe by construction) and inside
// an nft ruleset string — this regex is what keeps it there, not %q.
var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,14}$`)

// Validate checks syntax and internal references only — host state (does
// Iface actually exist) is an Apply-time concern, not this one.
func (c Config) Validate() error {
	seen := make(map[string]bool, len(c.Upstreams))
	tables := make(map[int]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.ID == "" {
			return fmt.Errorf("upstream: empty id")
		}
		if seen[u.ID] {
			return fmt.Errorf("upstream: duplicate id %q", u.ID)
		}
		seen[u.ID] = true
		if !ifaceRe.MatchString(u.Iface) {
			return fmt.Errorf("upstream: %q: invalid iface %q", u.ID, u.Iface)
		}
		if u.Gateway != "" && net.ParseIP(u.Gateway) == nil {
			return fmt.Errorf("upstream: %q: bad gateway %q", u.ID, u.Gateway)
		}
		if u.Table < tableBase || u.Table >= tableBase+maxUpstreams {
			return fmt.Errorf("upstream: %q: table %d outside managed range [%d,%d)", u.ID, u.Table, tableBase, tableBase+maxUpstreams)
		}
		if tables[u.Table] {
			return fmt.Errorf("upstream: %q: table %d already used", u.ID, u.Table)
		}
		tables[u.Table] = true
	}
	if c.Default != "" && !seen[c.Default] {
		return fmt.Errorf("upstream: default %q not defined", c.Default)
	}
	for cn, id := range c.PerCN {
		if !seen[id] {
			return fmt.Errorf("upstream: per-cn %q: upstream %q not defined", cn, id)
		}
	}
	return nil
}

// rulePrio returns this table's fixed ip-rule priority within the band.
func rulePrio(table int) int { return rulePrioBase + (table - tableBase) }

// teardownArgs sweeps the whole reserved band regardless of cfg, so a
// deleted upstream's leftovers get cleared too. Failures are expected/ignored.
func teardownArgs() [][]string {
	cmds := make([][]string, 0, maxUpstreams*2)
	for i := 0; i < maxUpstreams; i++ {
		table := tableBase + i
		cmds = append(cmds,
			[]string{"rule", "del", "priority", strconv.Itoa(rulePrio(table))},
			[]string{"route", "flush", "table", strconv.Itoa(table)},
		)
	}
	return cmds
}

// routeArgs: a real default route via Gateway/Iface, plus an unreachable
// fallback in the same table — the kill switch, so a dead gateway fails
// closed instead of falling through to the host's own default route.
func routeArgs(u Upstream) [][]string {
	table := strconv.Itoa(u.Table)
	var primary []string
	if u.Gateway != "" {
		primary = []string{"route", "replace", "default", "via", u.Gateway, "dev", u.Iface, "table", table}
	} else {
		primary = []string{"route", "replace", "default", "dev", u.Iface, "table", table}
	}
	return [][]string{
		primary,
		{"route", "replace", "unreachable", "default", "table", table, "metric", "999"},
		{"rule", "add", "fwmark", table, "table", table, "priority", strconv.Itoa(rulePrio(u.Table))},
	}
}

// nftRuleset: a prerouting chain marking vpnSubnet with the resolved
// upstream's table (nothing if off), a postrouting chain masquerading every
// configured upstream's marked traffic out its own Iface.
func nftRuleset(cfg Config, vpnSubnet string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	// Chain names match their own hook (idiomatic nft), ovcp-prefixed like the
	// table itself — "mark" alone is an nft keyword and fails as a bare name.
	b.WriteString("\tchain ovcp-prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	if vpnSubnet != "" {
		if u, ok := cfg.find(cfg.Resolve("")); ok {
			fmt.Fprintf(&b, "\t\tip saddr %s meta mark set %d\n", vpnSubnet, u.Table)
		}
	}
	b.WriteString("\t}\n\tchain ovcp-postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, u := range cfg.Upstreams {
		fmt.Fprintf(&b, "\t\tmeta mark %d oif %q masquerade\n", u.Table, u.Iface)
	}
	b.WriteString("\t}\n}\n")
	return []byte(b.String())
}

func run(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("upstream: %s %s: %w: %s", bin, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// Apply tears down and rebuilds ovcp's reserved band fresh from cfg. One
// upstream's route failure never skips its own kill-switch fallback or the
// nft mark table below — skipping either would fail open, not closed.
func Apply(cfg Config, vpnSubnet string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !applyMu.TryLock() {
		return fmt.Errorf("upstream: %w", controller.ErrBusy)
	}
	defer applyMu.Unlock()
	for _, args := range teardownArgs() {
		run(ipBin, args...) // best-effort, see doc comment
	}
	run(nftBin, "delete", "table", "inet", nftTable) // best-effort: may not exist yet

	var errs []error
	for _, u := range cfg.Upstreams {
		for _, args := range routeArgs(u) {
			if err := run(ipBin, args...); err != nil {
				errs = append(errs, err)
			}
		}
	}

	ruleset := nftRuleset(cfg, vpnSubnet)
	if err := runNFTStdin([]string{"-c", "-f", "-"}, ruleset); err != nil {
		return errors.Join(append(errs, fmt.Errorf("upstream: nft ruleset check: %w", err))...)
	}
	if err := runNFTStdin([]string{"-f", "-"}, ruleset); err != nil {
		errs = append(errs, fmt.Errorf("upstream: nft apply: %w", err))
	}
	return errors.Join(errs...)
}

// runNFTStdin feeds ruleset to nft on stdin — no temp file to leak or clean up.
func runNFTStdin(args []string, ruleset []byte) error {
	cmd := exec.Command(nftBin, args...)
	cmd.Stdin = bytes.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("upstream: %s %s: %w: %s", nftBin, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// Teardown clears ovcp's whole band — same path Apply(Config{}, "") takes,
// since an empty Config has nothing to rebuild after.
func Teardown() error { return Apply(Config{}, "") }
