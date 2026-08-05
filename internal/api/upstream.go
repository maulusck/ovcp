package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sync"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

const upstreamConfigKey = "upstream_config"

// DefaultUpstreamConfig seeds one SOCKS upstream from OVCP_UPSTREAM_SOCKS,
// same shape as DefaultDNSConfig/DefaultStatsConfig, validated the same way
// `upstream add` is. Invalid: logged and ignored, never fatal.
func DefaultUpstreamConfig() upstream.Config {
	raw := os.Getenv("OVCP_UPSTREAM_SOCKS")
	if raw == "" {
		return upstream.Config{}
	}
	cfg, _, err := upstream.Config{}.WithAdded(upstream.Upstream{ID: "socks", SOCKS: raw})
	if err == nil {
		cfg, err = cfg.SetDefault("socks")
	}
	if err != nil {
		slog.Warn("OVCP_UPSTREAM_SOCKS invalid, ignoring", "err", err)
		return upstream.Config{}
	}
	return cfg
}

func LoadUpstreamConfig(s *store.Store) upstream.Config {
	return store.LoadJSON(s, upstreamConfigKey, DefaultUpstreamConfig())
}

func SaveUpstreamConfig(s *store.Store, cfg upstream.Config) error {
	return store.SaveJSON(s, upstreamConfigKey, cfg)
}

// UpstreamAuthActive reports whether server.conf needs
// management-client-auth — shared by serve's own startup and `upstream
// assign` (Piece 4), so both compute the same thing the same way.
func UpstreamAuthActive(s *store.Store) bool {
	return len(LoadUpstreamConfig(s).PerCN) > 0
}

// applyUpstreams re-programs routing/NAT and reinstalls any live per-CN
// rules the rebuild wiped — a no-op when disabled. Never fails the caller;
// returns a warning instead, "" if clean, same convention as DNSLeakWarning.
func (s *Server) applyUpstreams(cfg upstream.Config) string {
	if !s.UpstreamsEnabled {
		return ""
	}
	if err := upstream.Apply(cfg, s.LoadConfig().Subnet); err != nil {
		slog.Warn("upstream apply", "err", err)
	} else {
		slog.Debug("upstream: applied", "upstreams", len(cfg.Upstreams), "default", cfg.Default)
	}
	s.reinstallTrackedRules()
	return upstream.Warning(cfg.Upstreams)
}

// ReconcileUpstreams re-applies the persisted config and reports any
// warning — exported so both the REST handler and the control-socket
// `upstream-reapply` op (main.go) share the one path.
func (s *Server) ReconcileUpstreams() (upstream.Config, string) {
	cfg := LoadUpstreamConfig(s.Store)
	return cfg, s.applyUpstreams(cfg)
}

// upstreamApplyResult adds applyUpstreams' warning to cfg's own JSON shape
// — embedded, not wrapped, so Upstreams/Default/PerCN stay at the top level
// for existing consumers (the web UI reads them directly).
type upstreamApplyResult struct {
	upstream.Config
	Warning string `json:"warning,omitempty"`
}

func (s *Server) handleUpstreamsGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, LoadUpstreamConfig(s.Store).Redacted())
}

func (s *Server) handleUpstreamAdd(w http.ResponseWriter, r *http.Request, u *store.User) {
	if !s.UpstreamsEnabled {
		jsonErr(w, 400, "upstreams disabled: nftables not found or turned off")
		return
	}
	var in struct{ ID, Iface, Gateway, SOCKS, Description string }
	if !decode(r, &in) || in.ID == "" {
		jsonErr(w, 400, "id required")
		return
	}
	if (in.Iface == "") == (in.SOCKS == "") {
		jsonErr(w, 400, "exactly one of iface or socks required")
		return
	}
	if in.SOCKS != "" && in.Gateway != "" {
		jsonErr(w, 400, "gateway is not valid with socks")
		return
	}
	cfg, _, err := LoadUpstreamConfig(s.Store).WithAdded(upstream.Upstream{
		ID: in.ID, Iface: in.Iface, Gateway: in.Gateway, SOCKS: in.SOCKS, Description: in.Description,
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	warning := s.applyUpstreams(cfg)
	s.Store.Audit(u.Username, "upstream_add", in.ID)
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

func (s *Server) handleUpstreamDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	cfg, found := LoadUpstreamConfig(s.Store).Without(id)
	if !found {
		jsonErr(w, 404, "upstream not found")
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	warning := s.applyUpstreams(cfg)
	s.Store.Audit(u.Username, "upstream_del", id)
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

// regenManagementClientAuth rewrites server.conf's management-client-auth
// flag to match active — the same computation main.go does at startup,
// redone here since PerCN can flip empty<->non-empty mid-session.
func (s *Server) regenManagementClientAuth(active bool) error {
	cfg := s.LoadConfig()
	cfg.ManagementClientAuth = active
	if err := s.saveConfig(cfg); err != nil {
		return err
	}
	return cfg.WriteAtomic(s.ConfigPath)
}

// handleUpstreamAssign sets or clears a CN's per-upstream override, rewrites
// server.conf if that flips management-client-auth on/off, and instantly
// updates an already-connected client's live rule.
func (s *Server) handleUpstreamAssign(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		CN, ID string
		Clear  bool
	}
	if !decode(r, &in) || in.CN == "" {
		jsonErr(w, 400, "cn required")
		return
	}
	before := s.UpstreamsEnabled && UpstreamAuthActive(s.Store)
	cfg, err := LoadUpstreamConfig(s.Store).Assign(in.CN, in.ID, in.Clear)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	var warning string
	if after := s.UpstreamsEnabled && UpstreamAuthActive(s.Store); before != after {
		if err := s.regenManagementClientAuth(after); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if after {
			// management-client-auth is a config-file directive: the
			// already-running openvpn process won't pick it up until
			// restarted, so per-CN routing stays inactive until then.
			warning = "run `ovcp vpn restart` to activate per-CN routing"
		}
	}
	if err := s.RewriteConnectedClientRule(in.CN); err != nil {
		jsonErr(w, opStatus(err), err.Error())
		return
	}
	action := "upstream_assign"
	if in.Clear {
		action = "upstream_unassign"
	}
	s.Store.Audit(u.Username, action, in.CN)
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

// handleUpstreamSetDefault: the ad-hoc exit switch — id="" turns it off,
// back to the host's own default route.
func (s *Server) handleUpstreamSetDefault(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ ID string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	cfg, err := LoadUpstreamConfig(s.Store).SetDefault(in.ID)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	warning := s.applyUpstreams(cfg)
	action := "upstream_default_set"
	if in.ID == "" {
		action = "upstream_default_off"
	}
	s.Store.Audit(u.Username, action, in.ID)
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

// handleUpstreamReconcile is the explicit "situation's stable now" trigger
// — re-applies and reports what's still down. Not on any timer.
func (s *Server) handleUpstreamReconcile(w http.ResponseWriter, r *http.Request, u *store.User) {
	cfg, warning := s.ReconcileUpstreams()
	s.Store.Audit(u.Username, "upstream_reconcile", "")
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

// trackedRule is one live client's ovcp-assigned IP, plus its nft rule
// handle if it has one (0 = none, e.g. no PerCN override). Keyed by CID
// (not CN) so a fast reconnect can't have its handle clobbered by a stale
// disconnect for the session it replaced.
type trackedRule struct {
	handle int
	ip     string
	cn     string
}

// upstreamTracker is mutex-protected: touched from the mgmt reader
// goroutine (connect/disconnect) and OnVPNExit.
type upstreamTracker struct {
	mu      sync.Mutex
	entries map[string]trackedRule
}

func (t *upstreamTracker) get(cid string) (trackedRule, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[cid]
	return e, ok
}

func (t *upstreamTracker) set(cid string, e trackedRule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = map[string]trackedRule{}
	}
	t.entries[cid] = e
}

// setHandle updates cid's nft rule handle in place, leaving ip/cn untouched.
func (t *upstreamTracker) setHandle(cid string, handle int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[cid]
	e.handle = handle
	t.entries[cid] = e
}

func (t *upstreamTracker) delete(cid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, cid)
}

// findByCN is the assign path's lookup — it only knows the CN, not which
// CID currently holds it.
func (t *upstreamTracker) findByCN(cn string) (cid string, e trackedRule, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c, entry := range t.entries {
		if entry.cn == cn {
			return c, entry, true
		}
	}
	return "", trackedRule{}, false
}

// allocate picks a free subnet IP and reserves it under cid, all under one
// lock — read-live, read-reserved, pick and reserve as one step, so two
// connects racing for the same address can't both win it.
func (t *upstreamTracker) allocate(cid, cn, subnet string, live []controller.VPNClient) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	reserved := make(map[string]bool, len(t.entries))
	for _, e := range t.entries {
		reserved[e.ip] = true
	}
	ip, err := pickFreeIP(subnet, live, reserved)
	if err != nil {
		return "", err
	}
	if t.entries == nil {
		t.entries = map[string]trackedRule{}
	}
	t.entries[cid] = trackedRule{ip: ip, cn: cn}
	return ip, nil
}

// snapshot copies every tracked entry, keyed by CID — the reinstall path's
// input.
func (t *upstreamTracker) snapshot() map[string]trackedRule {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]trackedRule, len(t.entries))
	for cid, e := range t.entries {
		out[cid] = e
	}
	return out
}

// pickFreeIP returns the lowest subnet address not currently live and not
// already reserved — excludes the network address and the server's own
// (network+1).
func pickFreeIP(subnet string, live []controller.VPNClient, reserved map[string]bool) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("upstream: bad subnet %q", subnet)
	}
	inUse := make(map[string]bool, len(live)+len(reserved))
	for _, c := range live {
		inUse[c.VirtualAddress] = true
	}
	for ip := range reserved {
		inUse[ip] = true
	}
	size := 1 << (32 - prefix.Bits())
	ip := prefix.Masked().Addr().Next().Next() // skip network (.0) and server (.1)
	for i := 2; i < size-1; i++ {              // stop before broadcast
		if !inUse[ip.String()] {
			return ip.String(), nil
		}
		ip = ip.Next()
	}
	return "", fmt.Errorf("upstream: no free ip in %s", subnet)
}

// OnClientConnect wires directly to controller.Client.OnClientConnect in
// runServe, and only ever fires while management-client-auth is active
// (UpstreamAuthActive, i.e. PerCN non-empty) — so every client connecting
// in that state, overridden or not, goes through ovcp for its IP rather
// than OpenVPN's own --ifconfig-pool. ifconfig-push always overrides pool
// allocation per client (see ifconfig-push(8)), so having ovcp assign it
// for every connect here is what actually closes the gap: previously only
// overridden CNs got a push, leaving everyone else to OpenVPN's pool,
// which has no idea an address was already handed out from under it.
func (s *Server) OnClientConnect(cid, kid string, env map[string]string) controller.AuthReply {
	if _, ok := s.upstream.get(cid); ok {
		return controller.AuthReply{} // REAUTH of an already-tracked session — don't re-add
	}
	cn := env["common_name"]
	cfg := LoadUpstreamConfig(s.Store)
	id, overridden := cfg.PerCN[cn]
	var up upstream.Upstream
	if overridden {
		var ok bool
		up, ok = cfg.Find(id)
		if !ok {
			return controller.AuthReply{Deny: "assigned upstream no longer exists"}
		}
	}
	vpnCfg := s.LoadConfig()
	mask, err := vpnCfg.Netmask()
	if err != nil {
		return controller.AuthReply{Deny: err.Error()}
	}
	live, err := s.Mgmt.Status()
	if err != nil {
		// Can't verify what's already in use — proceeding could hand this
		// IP to two clients at once. Deny, don't guess.
		return controller.AuthReply{Deny: err.Error()}
	}
	ip, err := s.upstream.allocate(cid, cn, vpnCfg.Subnet, live)
	if err != nil {
		return controller.AuthReply{Deny: err.Error()}
	}
	if overridden {
		handle, err := upstream.AddClientRule(ip, up.Table)
		if err != nil {
			s.upstream.delete(cid) // this connect never completes, release the reservation
			return controller.AuthReply{Deny: err.Error()}
		}
		s.upstream.setHandle(cid, handle)
		slog.Debug("upstream: per-CN rule installed", "cn", cn, "upstream", id, "ip", ip)
	} else {
		slog.Debug("upstream: ip assigned", "cn", cn, "ip", ip)
	}
	return controller.AuthReply{Directives: []string{fmt.Sprintf("ifconfig-push %s %s", ip, mask)}}
}

// OnClientDisconnect wires directly to controller.Client.OnClientDisconnect,
// releasing cid's IP reservation (every tracked client has one, not just
// per-CN ones) and, if it had an nft rule (handle != 0), removing that too.
// A failed removal stays tracked (not deleted) so OnVPNExit retries it on
// the next vpn restart — a one-shot failure here shouldn't orphan the rule
// permanently.
func (s *Server) OnClientDisconnect(cid string, env map[string]string) {
	e, ok := s.upstream.get(cid)
	if !ok {
		return
	}
	if e.handle != 0 {
		if err := upstream.RemoveClientRule(e.handle); err != nil {
			slog.Warn("upstream: remove client rule failed, will retry on next vpn restart", "cn", e.cn, "err", err)
			return
		}
	}
	s.upstream.delete(cid)
	slog.Debug("upstream: ip released", "cn", e.cn, "ip", e.ip)
}

// RewriteConnectedClientRule updates cn's live rule if they're currently
// connected — every connected client is tracked now, overridden or not, so
// this also covers a plain client getting its first-ever override without
// needing a reconnect. A cid with no tracked entry is a genuine no-op: not
// connected, so the new mapping takes effect on their next connect.
func (s *Server) RewriteConnectedClientRule(cn string) error {
	cid, old, ok := s.upstream.findByCN(cn)
	if !ok {
		return nil
	}
	cfg := LoadUpstreamConfig(s.Store)
	id, has := cfg.PerCN[cn]
	if !has {
		if old.handle == 0 {
			return nil // wasn't overridden to begin with, nothing to clear
		}
		if err := upstream.RemoveClientRule(old.handle); err != nil {
			return err
		}
		s.upstream.setHandle(cid, 0)
		slog.Debug("upstream: per-CN override cleared, live rule removed", "cn", cn)
		return nil
	}
	up, ok := cfg.Find(id)
	if !ok {
		return fmt.Errorf("upstream: assigned upstream %q no longer exists", id)
	}
	// Add the new rule before removing the old — appended last, its mark
	// wins regardless, so a failed old-removal never leaves cn unrouted.
	newHandle, err := upstream.AddClientRule(old.ip, up.Table)
	if err != nil {
		return err
	}
	s.upstream.setHandle(cid, newHandle)
	if old.handle != 0 {
		if err := upstream.RemoveClientRule(old.handle); err != nil {
			slog.Warn("upstream: assign left an inert old rule behind", "cn", cn, "err", err)
		}
	}
	slog.Debug("upstream: live rule rewritten", "cn", cn, "upstream", id)
	return nil
}

// reinstallTrackedRules re-adds every nft rule Apply's rebuild deletes — a
// plain re-add, not add-then-remove-old: nft reuses handle numbers
// post-rebuild, so removing the pre-rebuild handle risks deleting the new
// one. Every tracked entry's IP reservation stands regardless of PerCN
// status — only entries actually in PerCN get a rule; the stale handle on
// everyone else is cleared to 0, since the rebuild already dropped it.
func (s *Server) reinstallTrackedRules() {
	cfg := LoadUpstreamConfig(s.Store)
	for cid, e := range s.upstream.snapshot() {
		id, has := cfg.PerCN[e.cn]
		if !has {
			s.upstream.setHandle(cid, 0)
			continue
		}
		up, ok := cfg.Find(id)
		if !ok {
			slog.Warn("upstream: reinstall skipped, assigned upstream no longer exists", "cn", e.cn, "id", id)
			s.upstream.setHandle(cid, 0)
			continue
		}
		handle, err := upstream.AddClientRule(e.ip, up.Table)
		if err != nil {
			slog.Warn("upstream: reinstall failed", "cn", e.cn, "err", err)
			s.upstream.setHandle(cid, 0)
			continue
		}
		s.upstream.setHandle(cid, handle)
	}
}

// OnVPNExit clears every tracked entry on any openvpn exit (Supervisor's
// OnExit) — every session it held is gone unconditionally, no poll lag.
func (s *Server) OnVPNExit() {
	for cid, e := range s.upstream.snapshot() {
		if e.handle != 0 {
			if err := upstream.RemoveClientRule(e.handle); err != nil {
				slog.Warn("upstream: cleanup on vpn exit failed", "cn", e.cn, "err", err)
			}
		}
		s.upstream.delete(cid)
	}
}
