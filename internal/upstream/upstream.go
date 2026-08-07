// Package upstream steers connected VPN clients' outbound traffic through an
// admin-chosen egress instead of the box's own default route — policy routing + NAT only, ovcp never brings the upstream connection itself up.
package upstream

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
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
	tableBase        = 100
	maxUpstreams     = 64
	rulePrioBase     = 20000
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
func (u Upstream) socksPort() int { return 20000 + (u.Table - tableBase) }

// IsUp: Iface-mode needs its interface to exist; socks-mode has no cheap
// liveness check (that means dialing the backend), so it's reported up
// once configured. The one check DownIDs and every caller shares.
func (u Upstream) IsUp() bool { return u.IsSOCKS() || ifaceExists(u.Iface) }

type Config struct {
	Upstreams []Upstream
	Default   string // active Upstream.ID server-wide; "" = off, host's own default route

	// PerCN: CN -> Upstream.ID override, set via Assign. No static tunnel IPs —
	// the assigned IP is pushed live by internal/api's per-CN connect handler.
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

// Find looks up one Upstream by ID — exported for callers outside this
// package (the per-CN connect handler) that need the same lookup.
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

// Redacted returns cfg with every upstream's SOCKS password masked — the
// shape REST responses return, so a stored credential never round-trips to
// the browser in plain text.
func (c Config) Redacted() Config {
	out := c
	out.Upstreams = make([]Upstream, len(c.Upstreams))
	for i, u := range c.Upstreams {
		u.SOCKS = RedactSOCKS(u.SOCKS)
		out.Upstreams[i] = u
	}
	return out
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

// nftRuleset: prerouting marks vpnSubnet even for a down upstream (the
// kill-switch needs the mark); postrouting masquerades each upstream out
// its Iface, skipping a down one (nft rejects one bad oif for the whole ruleset).
func nftRuleset(cfg Config, vpnSubnet string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	// Chain names match their own hook (idiomatic nft), ovcp-prefixed like the
	// table itself — "mark" alone is an nft keyword and fails as a bare name.
	fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n", preroutingChain)
	if vpnSubnet != "" {
		if u, ok := cfg.Find(cfg.Resolve("")); ok {
			fmt.Fprintf(&b, "\t\tip saddr %s meta mark set %d\n", vpnSubnet, u.Table)
		}
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
	if vpnSubnet != "" {
		fmt.Fprintf(&b, "\t\tip saddr %s meta mark 0 masquerade\n", vpnSubnet)
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
	applyMu.Lock()
	defer applyMu.Unlock()
	for _, args := range teardownArgs() {
		run(ipBin, args...) // best-effort, see doc comment
	}
	run(nftBin, "delete", "table", "inet", nftTable) // best-effort: may not exist yet

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
	if err := startSOCKSRelays(cfg); err != nil {
		errs = append(errs, err)
	}

	ruleset := nftRuleset(cfg, vpnSubnet)
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
// wiped them — inside Apply's own lock hold, so no Connect/Disconnect/
// Reassign can land between the wipe and this. Every tracked IP reservation
// stands regardless of PerCN status; only entries actually in cfg.PerCN get
// a rule, everyone else's stale handle is cleared to 0 (the rebuild already
// dropped it).
func reinstall(cfg Config, errs *[]error) {
	for cid, e := range tracked {
		e.handle = 0
		if id, has := cfg.PerCN[e.cn]; has {
			if up, ok := cfg.Find(id); ok {
				if handle, err := addRule(e.ip, up.Table); err == nil {
					e.handle = handle
				} else {
					*errs = append(*errs, fmt.Errorf("upstream: reinstall %q: %w", e.cn, err))
				}
			} else {
				*errs = append(*errs, fmt.Errorf("upstream: reinstall %q: assigned upstream %q no longer exists", e.cn, id))
			}
		}
		tracked[cid] = e
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

// Teardown clears ovcp's whole band — same path Apply(Config{}, "") takes,
// since an empty Config has nothing to rebuild after.
func Teardown() error { return Apply(Config{}, "") }

// trackedRule is one live client's ovcp-assigned IP and, if it has a per-CN
// override, the nft rule installed for it (0 = none). Keyed by CID, not CN
// — a fast reconnect can't have its handle clobbered by a stale disconnect
// for the session it replaced.
type trackedRule struct {
	ip     string
	cn     string
	handle int
}

// tracked is every currently-connected client ovcp has assigned an IP to.
// Guarded by applyMu, the same lock as every nft mutation below: deciding
// what a client needs and making it so must happen as one step, never two
// separately-locked halves a concurrent Apply/Reassign could land between.
var tracked = map[string]trackedRule{}

// findByCN is Reassign's lookup — it only knows the CN, not which CID
// currently holds it. Caller must hold applyMu.
func findByCN(cn string) (cid string, e trackedRule, ok bool) {
	for c, entry := range tracked {
		if entry.cn == cn {
			return c, entry, true
		}
	}
	return "", trackedRule{}, false
}

// pickFreeIP returns the lowest address in prefix that's neither live nor
// already tracked — excludes the network address and the server's own
// (network+1). Caller must hold applyMu.
func pickFreeIP(prefix netip.Prefix, live []controller.VPNClient) (string, error) {
	inUse := make(map[string]bool, len(live)+len(tracked))
	for _, c := range live {
		inUse[c.VirtualAddress] = true
	}
	for _, e := range tracked {
		inUse[e.ip] = true
	}
	size := 1 << (32 - prefix.Bits())
	ip := prefix.Masked().Addr().Next().Next() // skip network (.0) and server (.1)
	for i := 2; i < size-1; i++ {              // stop before broadcast
		if !inUse[ip.String()] {
			return ip.String(), nil
		}
		ip = ip.Next()
	}
	return "", fmt.Errorf("upstream: no free ip in %s", prefix)
}

// Connect is the one place a client gets its IP and, if cn has a per-CN
// override in cfg, its nft rule — one lock hold covering allocate, decide,
// mutate and track, so a concurrent Apply/Reassign can never land
// mid-sequence. already=true means cid is a REAUTH of an already-tracked
// session: it already has everything it needs, nothing to do.
func Connect(cid, cn string, cfg Config, subnet string, live []controller.VPNClient) (ip, mask string, already bool, err error) {
	applyMu.Lock()
	defer applyMu.Unlock()
	if _, ok := tracked[cid]; ok {
		return "", "", true, nil
	}
	var up Upstream
	if id, overridden := cfg.PerCN[cn]; overridden {
		var ok bool
		if up, ok = cfg.Find(id); !ok {
			return "", "", false, fmt.Errorf("upstream: assigned upstream %q no longer exists", id)
		}
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "", "", false, fmt.Errorf("upstream: bad subnet %q", subnet)
	}
	if ip, err = pickFreeIP(prefix, live); err != nil {
		return "", "", false, err
	}
	entry := trackedRule{ip: ip, cn: cn}
	if up.ID != "" {
		if entry.handle, err = addRule(ip, up.Table); err != nil {
			return "", "", false, err
		}
	}
	tracked[cid] = entry
	return ip, net.IP(net.CIDRMask(prefix.Bits(), 32)).String(), false, nil
}

// Disconnect releases cid's IP and, if it had an nft rule, removes it. A
// failed removal stays tracked (not deleted) so ClearAll retries it on the
// next vpn exit — a one-shot failure here shouldn't orphan the rule.
func Disconnect(cid string) {
	applyMu.Lock()
	defer applyMu.Unlock()
	e, ok := tracked[cid]
	if !ok {
		return
	}
	if e.handle != 0 {
		if err := removeRule(e.handle); err != nil {
			slog.Warn("upstream: remove client rule failed, will retry on next vpn restart", "cn", e.cn, "err", err)
			return
		}
	}
	delete(tracked, cid)
}

// Reassign updates cn's live rule to match cfg, if cn is currently
// connected — a no-op if not, the new mapping takes effect on their next
// connect. Every connected client is tracked, overridden or not, so this
// also covers a plain client getting its first-ever override live.
func Reassign(cn string, cfg Config) error {
	applyMu.Lock()
	defer applyMu.Unlock()
	cid, old, ok := findByCN(cn)
	if !ok {
		return nil
	}
	id, has := cfg.PerCN[cn]
	if !has {
		if old.handle == 0 {
			return nil // wasn't overridden to begin with, nothing to clear
		}
		if err := removeRule(old.handle); err != nil {
			return err
		}
		old.handle = 0
		tracked[cid] = old
		return nil
	}
	up, ok := cfg.Find(id)
	if !ok {
		return fmt.Errorf("upstream: assigned upstream %q no longer exists", id)
	}
	// Add the new rule before removing the old — appended last, its mark
	// wins regardless, so a failed old-removal never leaves cn unrouted.
	newHandle, err := addRule(old.ip, up.Table)
	if err != nil {
		return err
	}
	oldHandle := old.handle
	old.handle = newHandle
	tracked[cid] = old
	if oldHandle != 0 {
		if err := removeRule(oldHandle); err != nil {
			slog.Warn("upstream: assign left an inert old rule behind", "cn", cn, "err", err)
		}
	}
	return nil
}

// ClearAll clears every tracked entry and removes its nft rule, if any —
// call on any openvpn exit (Supervisor's OnExit), including a crash: a
// crash-triggered auto-restart relaunches openvpn directly, without an
// Apply, so the nft table (and every per-client rule in it) survives
// untouched while every CID that held one is now gone regardless.
func ClearAll() {
	applyMu.Lock()
	defer applyMu.Unlock()
	for cid, e := range tracked {
		if e.handle != 0 {
			if err := removeRule(e.handle); err != nil {
				slog.Warn("upstream: cleanup on vpn exit failed", "cn", e.cn, "err", err)
				continue
			}
		}
		delete(tracked, cid)
	}
}

// addRule appends one mark rule — the fast per-connection path Apply's full
// rebuild is too heavy for. Caller must hold applyMu.
func addRule(ip string, table int) (handle int, err error) {
	if net.ParseIP(ip).To4() == nil {
		return 0, fmt.Errorf("upstream: bad client ip %q", ip)
	}
	out, err := exec.Command(nftBin, "-a", "-e", "add", "rule", "inet", nftTable, preroutingChain,
		"ip", "saddr", ip, "meta", "mark", "set", strconv.Itoa(table)).CombinedOutput()
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
