package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

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

// applyUpstreams re-programs routing/NAT (upstream.Apply reinstalls any live
// per-CN rules the rebuild wipes) — a no-op when disabled. Never fails the
// caller; returns a warning instead, "" if clean, same convention as
// DNSLeakWarning.
func (s *Server) applyUpstreams(cfg upstream.Config) string {
	if !s.UpstreamsEnabled {
		return ""
	}
	if err := upstream.Apply(cfg, s.LoadConfig().Subnet); err != nil {
		slog.Warn("upstream apply", "err", err)
	} else {
		slog.Debug("upstream: applied", "upstreams", len(cfg.Upstreams), "default", cfg.Default)
	}
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

// OnClientConnect wires directly to controller.Client.OnClientConnect in
// runServe, and only ever fires while management-client-auth is active
// (UpstreamAuthActive, i.e. PerCN non-empty) — so every client connecting
// in that state, overridden or not, goes through upstream.Connect for its
// IP rather than OpenVPN's own --ifconfig-pool. ifconfig-push always
// overrides pool allocation per client (see ifconfig-push(8)), so having
// ovcp assign it for every connect here is what actually closes the gap:
// previously only overridden CNs got a push, leaving everyone else to
// OpenVPN's pool, which has no idea an address was already handed out from
// under it.
func (s *Server) OnClientConnect(cid, kid string, env map[string]string) controller.AuthReply {
	live, err := s.Mgmt.Status()
	if err != nil {
		// Can't verify what's already in use — proceeding could hand this
		// IP to two clients at once. Deny, don't guess.
		return controller.AuthReply{Deny: err.Error()}
	}
	cn := env["common_name"]
	ip, mask, already, err := upstream.Connect(cid, cn, LoadUpstreamConfig(s.Store), s.LoadConfig().Subnet, live)
	if err != nil {
		return controller.AuthReply{Deny: err.Error()}
	}
	if already {
		return controller.AuthReply{} // REAUTH of an already-tracked session — don't re-push
	}
	slog.Debug("upstream: ip assigned", "cn", cn, "ip", ip)
	return controller.AuthReply{Directives: []string{fmt.Sprintf("ifconfig-push %s %s", ip, mask)}}
}

// OnClientDisconnect wires directly to controller.Client.OnClientDisconnect.
func (s *Server) OnClientDisconnect(cid string, env map[string]string) {
	upstream.Disconnect(cid)
}

// RewriteConnectedClientRule updates cn's live rule if they're currently
// connected — wired to control.go's `upstream-assign` op.
func (s *Server) RewriteConnectedClientRule(cn string) error {
	return upstream.Reassign(cn, LoadUpstreamConfig(s.Store))
}

// OnVPNExit clears every tracked entry on any openvpn exit (Supervisor's
// OnExit) — every session it held is gone unconditionally, no poll lag.
func (s *Server) OnVPNExit() {
	upstream.ClearAll()
}
