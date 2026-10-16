// Package upstream steers connected VPN clients' outbound traffic through an
// admin-chosen egress instead of the box's own default route — policy routing + NAT only, ovcp never brings the upstream connection itself up.
package upstream

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
)

// Reserved band ovcp exclusively owns — never touches a rule/table outside
// these ranges, so it can never step on another service's routing.
const (
	tableBase        = 100
	maxUpstreams     = 64
	rulePrioBase     = 20000
	socksPortBase    = 20000 // unrelated to rulePrioBase — same value is coincidence, not a link
	nftTable         = "ovcp-upstreams"
	preroutingChain  = "ovcp-prerouting"
	postroutingChain = "ovcp-postrouting"
	redirectChain    = "ovcp-redirect" // SOCKS-mode: DNATs marked traffic to the local relay
)

// ipBin/nftBin: package vars, not hardcoded argv[0], so tests can swap in a fake script.
var (
	ipBin  = "ip"
	nftBin = "nft"
)

// Enabled reports whether the upstream feature can actually be used: a
// firewall backend was found (nft today — backendPath is whatever the
// caller detected, "" means none) and OVCP_UPSTREAMS_ENABLED hasn't
// explicitly turned it off. Backend-agnostic on purpose: a future non-nft
// backend only has to supply its own detected path, not a new gate.
func Enabled(backendPath string) bool {
	return backendPath != "" && os.Getenv("OVCP_UPSTREAMS_ENABLED") != "false"
}

// ifaceExists reports whether name is a live interface right now — a
// package var like ipBin/nftBin, so tests can override it instead of
// depending on real host interfaces.
var ifaceExists = func(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// DownIDs returns the IDs of every upstream that isn't up right now — nil
// if all are reachable.
func DownIDs(ups []Upstream) []string {
	var down []string
	for _, u := range ups {
		if !u.IsUp() {
			down = append(down, u.ID)
		}
	}
	return down
}

// Warning summarizes any down upstreams as one line, "" if none — the one
// wording both the API and CLI derive an apply-time warning from.
func Warning(ups []Upstream) string {
	down := DownIDs(ups)
	if len(down) == 0 {
		return ""
	}
	return "unreachable (iface down): " + strings.Join(down, ", ")
}

// applyMu serializes every Apply call in this process — intrinsic to Apply
// itself so every caller (API, CLI, serve's startup/shutdown) shares it.
// Blocking, not TryLock: a racing caller must eventually apply, not no-op.
var applyMu sync.Mutex

type Upstream struct {
	ID      string // slug, referenced by Config.Default/PerCN
	Iface   string // egress interface; admin brings it up, ovcp only references it
	Gateway string // next-hop IP; empty = onlink route via Iface. Iface-mode only.
	SOCKS   string // socks5://[user:pass@]host:port; mutually exclusive with Iface/Gateway

	// DialTimeout/HandshakeTimeout: seconds, 0 = server default (see
	// OVCP_UPSTREAM_SOCKS_*_TIMEOUT). SOCKS-mode only — a fast/local backend
	// wants these low, Tor wants headroom for real circuit-build time.
	DialTimeout      int
	HandshakeTimeout int

	Table       int // routing table number (Iface-mode) or, offset from tableBase, the local relay port (SOCKS-mode); assigned once via NextTable, stable
	Description string
}

// IsSOCKS reports whether u is relayed through a SOCKS backend instead of
// routed via Iface — the one check both nftRuleset and Apply branch on.
func (u Upstream) IsSOCKS() bool { return u.SOCKS != "" }

// socksPort derives u's local relay port from its Table slot — no second
// allocator, stable for the same reason Table already is.
func (u Upstream) socksPort() int { return socksPortBase + (u.Table - tableBase) }

// IsUp: Iface-mode needs its interface to exist; socks-mode has no cheap
// liveness check (that means dialing the backend), so it's reported up
// once configured. The one check DownIDs and every caller shares.
func (u Upstream) IsUp() bool { return u.IsSOCKS() || ifaceExists(u.Iface) }

type Config struct {
	Upstreams []Upstream
	Default   string // active Upstream.ID server-wide; "" = off, host's own default route

	// PerCN: CN -> Upstream.ID override, set via Assign. No static tunnel
	// IPs — the address stays whatever OpenVPN's own ifconfig-pool assigns;
	// Establish only reacts to it, via >CLIENT:ESTABLISHED.
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

// validated applies mutate to a copy of c and validates the result — the
// copy-mutate-rollback-on-error shape Assign/SetDefault share.
func (c Config) validated(mutate func(*Config)) (Config, error) {
	cfg := c
	mutate(&cfg)
	if err := cfg.Validate(); err != nil {
		return c, err
	}
	return cfg, nil
}

// Assign sets or clears cfg.PerCN[cn]. clear deletes the key, not an
// empty-string value — Resolve would return that directly instead of
// falling through to Default.
func (c Config) Assign(cn, id string, clear bool) (Config, error) {
	if cn == "" || clear == (id != "") {
		return c, fmt.Errorf("upstream: assign needs a cn and exactly one of an id or clear")
	}
	return c.validated(func(cfg *Config) {
		perCN := make(map[string]string, len(c.PerCN)+1)
		for k, v := range c.PerCN {
			perCN[k] = v
		}
		if clear {
			delete(perCN, cn)
		} else {
			perCN[cn] = id
		}
		cfg.PerCN = perCN
	})
}

// SetDefault sets cfg.Default — id="" turns it off.
func (c Config) SetDefault(id string) (Config, error) {
	return c.validated(func(cfg *Config) { cfg.Default = id })
}

// Find looks up one Upstream by ID — the one lookup Establish, Reassign,
// reinstall, and nftRuleset's own default-egress line all share.
func (c Config) Find(id string) (Upstream, bool) {
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

// validateSOCKSURL: scheme must be socks5 (only CONNECT is implemented, see
// socks.go), host:port required. User:pass in the URL is optional auth,
// consumed as-is by socksConnect — no further shape to check here.
func validateSOCKSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// Not %w-wrapped: url.Error echoes the raw input (may carry a
		// password) verbatim, and this can reach slog. Never even indirectly.
		return fmt.Errorf("bad socks url: unparseable")
	}
	if u.Scheme != "socks5" {
		return fmt.Errorf("socks url must use socks5://, got %q", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return fmt.Errorf("socks url needs host:port")
	}
	for _, c := range raw { // RFC 3986: a URL is ASCII (percent-encode, punycode); keeps table cells single-width
		if c > 127 {
			return fmt.Errorf("socks url must be ASCII")
		}
	}
	return nil
}

// RedactSOCKS masks a socks5:// URL's password for display — same posture
// as every other secret this CLI never echoes back. Returns raw unchanged
// if it doesn't parse or carries no password.
func RedactSOCKS(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPass := u.User.Password(); !hasPass {
		return raw
	}
	u.User = url.UserPassword(u.User.Username(), "***")
	return u.String()
}

// Validate checks syntax and internal references only — host state (does
// Iface actually exist) is an Apply-time concern, not this one.
func (c Config) Validate() error {
	seen := make(map[string]bool, len(c.Upstreams))
	tables := make(map[int]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.ID == "" {
			return fmt.Errorf("upstream: empty id")
		}
		if err := pki.CheckName("upstream: id", u.ID); err != nil {
			return err
		}
		if seen[u.ID] {
			return fmt.Errorf("upstream: duplicate id %q", u.ID)
		}
		seen[u.ID] = true
		if u.IsSOCKS() {
			if u.Iface != "" || u.Gateway != "" {
				return fmt.Errorf("upstream: %q: socks is mutually exclusive with iface/gateway", u.ID)
			}
			if err := validateSOCKSURL(u.SOCKS); err != nil {
				return fmt.Errorf("upstream: %q: %w", u.ID, err)
			}
			if u.DialTimeout < 0 || u.HandshakeTimeout < 0 {
				return fmt.Errorf("upstream: %q: timeouts must not be negative", u.ID)
			}
		} else {
			if !ifaceRe.MatchString(u.Iface) {
				return fmt.Errorf("upstream: %q: invalid iface %q", u.ID, u.Iface)
			}
			if u.Gateway != "" && net.ParseIP(u.Gateway) == nil {
				return fmt.Errorf("upstream: %q: bad gateway %q", u.ID, u.Gateway)
			}
			if u.DialTimeout != 0 || u.HandshakeTimeout != 0 {
				return fmt.Errorf("upstream: %q: dial/handshake timeout is socks-mode only", u.ID)
			}
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

// nftRuleset: VPN traffic is whatever arrives on the tunnel interface,
// never a source address another host could forge. Prerouting marks it even
// for a down upstream (the kill-switch needs the mark); postrouting
// masquerades each upstream out its Iface, skipping a down one (nft rejects
// one bad oif for the whole ruleset).
func nftRuleset(cfg Config) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	// Chain names match their own hook (idiomatic nft), ovcp-prefixed like the
	// table itself — "mark" alone is an nft keyword and fails as a bare name.
	fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n", preroutingChain)
	if u, ok := cfg.Find(cfg.Resolve("")); ok {
		fmt.Fprintf(&b, "\t\tiifname %q meta mark set %d\n", ovpnconf.TunDev, u.Table)
	}
	// SOCKS-mode marks never reach postrouting/masquerade: redirect rewrites
	// the destination in prerouting, dstnat priority runs right after this
	// mangle chain, so the mark set above is already in place by then.
	fmt.Fprintf(&b, "\t}\n\tchain %s {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n", redirectChain)
	for _, u := range cfg.Upstreams {
		if !u.IsSOCKS() {
			continue
		}
		fmt.Fprintf(&b, "\t\tmeta mark %d meta l4proto tcp redirect to :%d\n", u.Table, u.socksPort())
	}
	fmt.Fprintf(&b, "\t}\n\tchain %s {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n", postroutingChain)
	for _, u := range cfg.Upstreams {
		if u.IsSOCKS() || !ifaceExists(u.Iface) {
			continue
		}
		fmt.Fprintf(&b, "\t\tmeta mark %d oif %q masquerade\n", u.Table, u.Iface)
	}
	// Transparent mode: a client with no resolved upstream (mark 0, never
	// set above) still needs NAT to leave via the host's own default route
	// — ovcp's own table, not a hand-maintained one, so it survives an
	// `nft flush ruleset` + `ovcp serve` restart like everything else here.
	fmt.Fprintf(&b, "\t\tiifname %q meta mark 0 masquerade\n", ovpnconf.TunDev)
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
func Apply(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	clearBand()

	var errs []error
	for _, u := range cfg.Upstreams {
		if u.IsSOCKS() {
			continue // no interface to route via; redirect (nftRuleset) handles it
		}
		for _, args := range routeArgs(u) {
			if err := run(ipBin, args...); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := syncSOCKSRelays(cfg); err != nil {
		errs = append(errs, err)
	}

	ruleset := nftRuleset(cfg)
	if err := runNFTStdin([]string{"-c", "-f", "-"}, ruleset); err != nil {
		return errors.Join(append(errs, fmt.Errorf("upstream: nft ruleset check: %w", err))...)
	}
	if err := runNFTStdin([]string{"-f", "-"}, ruleset); err != nil {
		errs = append(errs, fmt.Errorf("upstream: nft apply: %w", err))
	} else {
		reinstall(cfg, &errs)
	}
	return errors.Join(errs...)
}

// reinstall re-adds every tracked client's nft rule after the rebuild above
// wiped them — inside Apply's own lock hold, so no Establish/Disconnect/
// Reassign can land between the wipe and this. A tracked entry whose cn is
// no longer overridden in cfg (override cleared, or its upstream deleted
// out from under it) is dropped entirely — Establish wouldn't track it
// again either, and the rebuild already dropped its rule.
func reinstall(cfg Config, errs *[]error) {
	for cid, e := range tracked {
		id, has := cfg.PerCN[e.cn]
		if !has {
			delete(tracked, cid) // no longer overridden; Establish wouldn't track this cn again either
			continue
		}
		up, ok := cfg.Find(id)
		if !ok {
			*errs = append(*errs, fmt.Errorf("upstream: reinstall %q: assigned upstream %q no longer exists", e.cn, id))
			delete(tracked, cid)
			continue
		}
		if err := addTracked(cid, e.cn, e.ip, up); err != nil {
			*errs = append(*errs, fmt.Errorf("upstream: reinstall %q: %w", e.cn, err))
			delete(tracked, cid)
		}
	}
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

// clearBand removes ovcp's routes, rules and nft table, best-effort (any of
// them may not exist). Caller must hold applyMu.
func clearBand() {
	for _, args := range teardownArgs() {
		run(ipBin, args...)
	}
	run(nftBin, "delete", "table", "inet", nftTable)
}

// Teardown removes ovcp's whole band and stops every SOCKS relay.
func Teardown() error {
	applyMu.Lock()
	defer applyMu.Unlock()
	clearBand()
	return syncSOCKSRelays(Config{})
}

// trackedRule is one connected, per-CN-overridden client's nft rule. Keyed
// by CID, not CN — a fast reconnect can't have its handle clobbered by a
// stale disconnect for the session it replaced. A plain (non-overridden)
// client is never tracked at all — there's nothing here for it to need.
type trackedRule struct {
	ip     string
	cn     string
	handle int
}

// tracked is every connected, currently-overridden client. Guarded by
// applyMu, the same lock as every nft mutation below: deciding what a
// client needs and making it so must happen as one step, never two
// separately-locked halves a concurrent Apply/Reassign could land between.
var tracked = map[string]trackedRule{}

// addTracked adds cid's nft rule for ip via up and records it. Pure add,
// no removal of anything old — reinstall depends on this: after Apply's
// rebuild, nft's handle counter resets, so removing a "stale" handle here
// could delete an unrelated, freshly-added rule instead (the exact bug
// reinstallTrackedRules was written to fix). Shared by Establish
// (brand-new session, nothing to remove) and reinstall (rebuild already
// wiped every old rule). Caller must hold applyMu.
func addTracked(cid, cn, ip string, up Upstream) error {
	handle, err := addRule(ip, up.Table)
	if err != nil {
		return err
	}
	tracked[cid] = trackedRule{ip: ip, cn: cn, handle: handle}
	return nil
}

// installRule adds cid's new rule and replaces any previous one it had,
// add-before-remove so a failed removal never leaves cn unrouted. Only
// safe against a live, not-just-rebuilt table (old handles are still
// real) — Reassign, never reinstall. Caller must hold applyMu.
func installRule(cid, cn, ip string, up Upstream) error {
	old, hadOld := tracked[cid]
	if err := addTracked(cid, cn, ip, up); err != nil {
		return err
	}
	if hadOld {
		if err := removeRule(old.handle); err != nil {
			slog.Warn("upstream: assign left an inert old rule behind", "cn", cn, "err", err)
		}
	}
	return nil
}

// uninstallRule removes cid's tracked rule, if it has one; a no-op
// otherwise. A failed removal stays tracked (caller decides whether to
// warn or propagate) so cleanup can retry later. Caller must hold applyMu.
func uninstallRule(cid string) error {
	e, ok := tracked[cid]
	if !ok {
		return nil
	}
	if err := removeRule(e.handle); err != nil {
		return err
	}
	delete(tracked, cid)
	return nil
}

// Establish installs cn's nft rule for ip — the address OpenVPN's own
// ifconfig-pool already assigned, reported via >CLIENT:ESTABLISHED. ovcp
// never chooses a client's address, so there's no allocator here and
// nothing to collide with OpenVPN's own pool; a plain (non-overridden) cn
// is not tracked at all. >CLIENT:ESTABLISHED fires exactly once per
// session — verified live against real OpenVPN 2.6.14 across three
// reneg-sec cycles, REAUTH re-fired each time and ESTABLISHED never did —
// so this never runs twice for the same cid.
func Establish(cid, cn, ip string, cfg Config) error {
	id, overridden := cfg.PerCN[cn]
	if !overridden {
		return nil
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	up, ok := cfg.Find(id)
	if !ok {
		return fmt.Errorf("upstream: assigned upstream %q no longer exists", id)
	}
	return addTracked(cid, cn, ip, up)
}

// Disconnect removes cid's nft rule, if it had one. A failed removal stays
// tracked (not deleted) so ClearAll retries it on the next vpn exit — a
// one-shot failure here shouldn't orphan the rule.
func Disconnect(cid string) {
	applyMu.Lock()
	defer applyMu.Unlock()
	cn := tracked[cid].cn
	if err := uninstallRule(cid); err != nil {
		slog.Warn("upstream: remove client rule failed, will retry on next vpn restart", "cn", cn, "err", err)
	}
}

// Reassign updates cid's (cn's current session, from Status()) live rule
// to match cfg — works whether or not cid was already tracked, so a plain
// client's first-ever override takes effect immediately too, not just a
// change to one it already had. A no-op if cn isn't connected at all
// (caller's Status() lookup found nothing): the new mapping takes effect
// on their next connect, via Establish.
func Reassign(cid, cn, ip string, cfg Config) error {
	applyMu.Lock()
	defer applyMu.Unlock()
	id, has := cfg.PerCN[cn]
	if !has {
		return uninstallRule(cid)
	}
	up, ok := cfg.Find(id)
	if !ok {
		return fmt.Errorf("upstream: assigned upstream %q no longer exists", id)
	}
	return installRule(cid, cn, ip, up)
}

// ClearAll clears every tracked entry and removes its nft rule — call on
// any openvpn exit (Supervisor's OnExit), including a crash: a
// crash-triggered auto-restart relaunches openvpn directly, without an
// Apply, so the nft table (and every per-client rule in it) survives
// untouched while every CID that held one is now gone regardless.
func ClearAll() {
	applyMu.Lock()
	defer applyMu.Unlock()
	for cid, e := range tracked {
		if err := uninstallRule(cid); err != nil {
			slog.Warn("upstream: cleanup on vpn exit failed", "cn", e.cn, "err", err)
		}
	}
}

// addRule appends one mark rule — the fast per-connection path Apply's full
// rebuild is too heavy for. Caller must hold applyMu.
func addRule(ip string, table int) (handle int, err error) {
	if net.ParseIP(ip).To4() == nil {
		return 0, fmt.Errorf("upstream: bad client ip %q", ip)
	}
	out, err := exec.Command(nftBin, "-a", "-e", "add", "rule", "inet", nftTable, preroutingChain,
		"iifname", ovpnconf.TunDev, "ip", "saddr", ip, "meta", "mark", "set", strconv.Itoa(table)).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("upstream: add client rule: %w: %s", err, bytes.TrimSpace(out))
	}
	return parseHandle(out)
}

// parseHandle extracts the trailing "# handle N" nft appends when run with -e.
func parseHandle(out []byte) (int, error) {
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "# handle "); i >= 0 {
			return strconv.Atoi(strings.TrimSpace(line[i+len("# handle "):]))
		}
	}
	return 0, fmt.Errorf("upstream: no handle in nft output: %s", bytes.TrimSpace(out))
}

// removeRule deletes exactly the rule addRule created. Caller must hold applyMu.
func removeRule(handle int) error {
	return run(nftBin, "delete", "rule", "inet", nftTable, preroutingChain, "handle", strconv.Itoa(handle))
}
