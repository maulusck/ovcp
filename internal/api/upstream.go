package api

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

const upstreamConfigKey = "upstream_config"

// RestartWarning is shown when a CN's first-ever per-CN override flips
// ManagementClientAuth on: a config-file-only OpenVPN directive, verified
// (internal/controller/supervisor.go: Restart re-execs, Reconnect's SIGUSR1
// doesn't reread server.conf) to need a real restart, not just reconnect.
const RestartWarning = "run `ovcp vpn restart` to activate per-CN routing"

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
	s.saveAndApplyUpstreams(w, u, cfg, "upstream_add", in.ID)
}

func (s *Server) handleUpstreamDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	cfg, found := LoadUpstreamConfig(s.Store).Without(id)
	if !found {
		jsonErr(w, 404, "upstream not found")
		return
	}
	s.saveAndApplyUpstreams(w, u, cfg, "upstream_del", id)
}

// saveAndApplyUpstreams persists cfg, re-applies routing/NAT, audits, and
// writes the standard upstream response — the one tail handleUpstreamAdd,
// handleUpstreamDelete and handleUpstreamSetDefault all share.
func (s *Server) saveAndApplyUpstreams(w http.ResponseWriter, u *store.User, cfg upstream.Config, action, detail string) {
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	warning := s.applyUpstreams(cfg)
	s.Store.Audit(u.Username, action, detail)
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

// ApplyAssign persists an already-computed assign (cfg, from
// Config.Assign) and flips ManagementClientAuth if that changed PerCN
// empty<->non-empty, reporting RestartWarning if so — the save+flip tail
// handleUpstreamAssign and cmdUpstreamAssign share, same shape as
// saveAndApplyUpstreams/saveAndApplyUpstreamsCLI for add/del/set-default.
// before is the caller's own pre-mutation UpstreamAuthActive snapshot;
// enabled gates the flip the same way s.UpstreamsEnabled does for the REST
// handler — the CLI, which already refuses to get here when upstreams are
// disabled (upstreamsReady), always passes true. The mutation call itself
// (Config.Assign) stays with each caller, same reason it does for
// add/del/set-default: its error is a 400/die, distinct from this
// function's save/persist failures. id is the just-assigned upstream, ""
// when clearing — unlike add/del/set-default, assign never routes through
// applyUpstreams, so this is the one place that warns the target is down
// (cfg.Find("") on a clear is always a miss, so no warning fires then).
// enabled also gates this warning, same as applyUpstreams gates its own:
// disabled means no warnings at all, not just no auth flip.
func ApplyAssign(s *store.Store, confPath string, enabled, before bool, cfg upstream.Config, id string) (warning string, err error) {
	if err := SaveUpstreamConfig(s, cfg); err != nil {
		return "", err
	}
	var warnings []string
	if after := enabled && UpstreamAuthActive(s); before != after {
		if err := SetManagementClientAuth(s, confPath, after); err != nil {
			return "", err
		}
		if after {
			warnings = append(warnings, RestartWarning)
		}
	}
	if u, ok := cfg.Find(id); enabled && ok && !u.IsUp() {
		warnings = append(warnings, upstream.Warning([]upstream.Upstream{u}))
	}
	return strings.Join(warnings, "; "), nil
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
	warning, err := ApplyAssign(s.Store, s.ConfigPath, s.UpstreamsEnabled, before, cfg, in.ID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
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
	action := "upstream_default_set"
	if in.ID == "" {
		action = "upstream_default_off"
	}
	s.saveAndApplyUpstreams(w, u, cfg, action, in.ID)
}

// handleUpstreamReconcile is the explicit "situation's stable now" trigger
// — re-applies and reports what's still down. Not on any timer.
func (s *Server) handleUpstreamReconcile(w http.ResponseWriter, r *http.Request, u *store.User) {
	cfg, warning := s.ReconcileUpstreams()
	s.Store.Audit(u.Username, "upstream_reconcile", "")
	jsonOK(w, upstreamApplyResult{cfg.Redacted(), warning})
}

// OnClientEstablished wires directly to controller.Client.OnClientEstablished:
// ovcp never chooses or pushes a client's address, it only reacts once
// OpenVPN's own ifconfig-pool has already assigned one and ESTABLISHED
// reports it — installing an nft rule for cn if it's per-CN overridden, a
// no-op otherwise.
func (s *Server) OnClientEstablished(cid, cn, ip string, env map[string]string) {
	if err := upstream.Establish(cid, cn, ip, LoadUpstreamConfig(s.Store)); err != nil {
		slog.Warn("upstream: establish failed", "cn", cn, "ip", ip, "err", err)
	}
}

// OnClientDisconnect wires directly to controller.Client.OnClientDisconnect.
func (s *Server) OnClientDisconnect(cid string, env map[string]string) {
	upstream.Disconnect(cid)
}

// RewriteConnectedClientRule updates cn's live rule if they're currently
// connected — wired to control.go's `upstream-assign` op. Looks up cn's
// live CID+address via Status() (the same source the dashboard's client
// list already reads) rather than ovcp's own tracked map, so this works
// instantly even for a client getting its first-ever override, not just
// one changing an existing one.
func (s *Server) RewriteConnectedClientRule(cn string) error {
	live, err := s.Mgmt.Status()
	if err != nil {
		return err
	}
	cfg := LoadUpstreamConfig(s.Store)
	for _, c := range live {
		if c.CN == cn {
			return upstream.Reassign(c.CID, cn, c.VirtualAddress, cfg)
		}
	}
	return nil // not currently connected; takes effect on their next connect
}

// OnVPNExit clears every tracked entry on any openvpn exit (Supervisor's
// OnExit) — every session it held is gone unconditionally, no poll lag.
func (s *Server) OnVPNExit() {
	upstream.ClearAll()
}
