package api

import (
	"errors"
	"fmt"
	"log/slog"
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
	if err := upstream.Apply(cfg); err != nil {
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

// UpstreamView is the upstream config as the CLI's -json and the API both
// show it: SOCKS passwords redacted, each entry's live up/down.
type UpstreamView struct {
	Upstreams []UpstreamRow     `json:"upstreams"`
	Default   string            `json:"default,omitempty"`
	PerCN     map[string]string `json:"perCN,omitempty"`
	Message   string            `json:"message,omitempty"` // a mutation's confirmation
	Warning   string            `json:"warning,omitempty"` // the CLI also prints it to stderr
}

// UpstreamRow is one UpstreamView entry.
type UpstreamRow struct {
	ID          string `json:"id"`
	Up          bool   `json:"up"`
	Iface       string `json:"iface,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	SOCKS       string `json:"socks,omitempty"`
	Table       int    `json:"table"`
	Description string `json:"description,omitempty"`
}

// ViewUpstreams computes cfg's view, live up/down checked once.
func ViewUpstreams(cfg upstream.Config, warning string) UpstreamView {
	rows := make([]UpstreamRow, len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		rows[i] = UpstreamRow{u.ID, u.IsUp(), u.Iface, u.Gateway, upstream.RedactSOCKS(u.SOCKS), u.Table, u.Description}
	}
	return UpstreamView{Upstreams: rows, Default: cfg.Default, PerCN: cfg.PerCN, Warning: warning}
}

func (s *Server) handleUpstreamsGet(c call, _ none) (UpstreamView, error) {
	return ViewUpstreams(LoadUpstreamConfig(s.Store), ""), nil
}

// applyAssign persists an assign's cfg, flips ManagementClientAuth when PerCN
// turns empty<->non-empty (RestartWarning), and warns if id's upstream is down.
func applyAssign(s *store.Store, confPath string, before bool, cfg upstream.Config, id string) (warning string, err error) {
	if err := SaveUpstreamConfig(s, cfg); err != nil {
		return "", err
	}
	var warnings []string
	if after := UpstreamAuthActive(s); before != after {
		if err := SetManagementClientAuth(s, confPath, after); err != nil {
			return "", err
		}
		if after {
			warnings = append(warnings, RestartWarning)
		}
	}
	if u, ok := cfg.Find(id); ok && !u.IsUp() {
		warnings = append(warnings, upstream.Warning([]upstream.Upstream{u}))
	}
	return strings.Join(warnings, "; "), nil
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

// ErrUpstreamsDisabled: no nft on PATH, or OVCP_UPSTREAMS_ENABLED=false.
var ErrUpstreamsDisabled = errors.New("upstreams disabled: nftables not found on PATH, or OVCP_UPSTREAMS_ENABLED=false")

// ErrNoUpstream: an upstream id that isn't configured.
var ErrNoUpstream = errors.New("no such upstream")

// Applier programs cfg over the caller's transport (serve in process, or the
// CLI through a running serve) and returns the warning for down upstreams.
type Applier func(cfg upstream.Config) string

// The upstream actions below are each the one implementation behind a CLI
// command and its web API route; enabled is whether nft is usable.

func saveApplyUpstreams(st *store.Store, actor string, cfg upstream.Config, apply Applier, msg, action, detail string) (UpstreamView, error) {
	if err := SaveUpstreamConfig(st, cfg); err != nil {
		return UpstreamView{}, err
	}
	v := ViewUpstreams(cfg, apply(cfg))
	v.Message = msg
	st.Audit(actor, action, detail)
	return v, nil
}

// AddUpstream defines u; its routing table is assigned here.
func AddUpstream(st *store.Store, actor string, enabled bool, u upstream.Upstream, apply Applier) (UpstreamView, error) {
	if !enabled {
		return UpstreamView{}, ErrUpstreamsDisabled
	}
	cfg, added, err := LoadUpstreamConfig(st).WithAdded(u)
	if err != nil {
		return UpstreamView{}, err
	}
	return saveApplyUpstreams(st, actor, cfg, apply, fmt.Sprintf("added: %s (table %d)", u.ID, added.Table), "upstream_add", u.ID)
}

// DeleteUpstream removes id and every default or per-CN reference to it.
func DeleteUpstream(st *store.Store, actor string, enabled bool, id string, apply Applier) (UpstreamView, error) {
	if !enabled {
		return UpstreamView{}, ErrUpstreamsDisabled
	}
	cfg, found := LoadUpstreamConfig(st).Without(id)
	if !found {
		return UpstreamView{}, fmt.Errorf("%q: %w", id, ErrNoUpstream)
	}
	return saveApplyUpstreams(st, actor, cfg, apply, "deleted: "+id, "upstream_del", id)
}

// SetDefaultUpstream routes every client without an override out id; "" turns it off.
func SetDefaultUpstream(st *store.Store, actor string, enabled bool, id string, apply Applier) (UpstreamView, error) {
	if !enabled {
		return UpstreamView{}, ErrUpstreamsDisabled
	}
	cfg, err := LoadUpstreamConfig(st).SetDefault(id)
	if err != nil {
		return UpstreamView{}, err
	}
	if id == "" {
		return saveApplyUpstreams(st, actor, cfg, apply, "default: off (host's own default route)", "upstream_default_off", "")
	}
	return saveApplyUpstreams(st, actor, cfg, apply, "default: "+id, "upstream_default_set", id)
}

// AssignUpstream overrides cn's egress (clear: back to the default), then
// rewrites cn's live rule over the caller's transport.
func AssignUpstream(st *store.Store, actor string, enabled bool, confPath, cn, id string, clear bool, rewrite func(cn string) error) (UpstreamView, error) {
	if !enabled {
		return UpstreamView{}, ErrUpstreamsDisabled
	}
	before := UpstreamAuthActive(st)
	cfg, err := LoadUpstreamConfig(st).Assign(cn, id, clear)
	if err != nil {
		return UpstreamView{}, err
	}
	warning, err := applyAssign(st, confPath, before, cfg, id)
	if err != nil {
		return UpstreamView{}, err
	}
	if err := rewrite(cn); err != nil {
		return UpstreamView{}, err
	}
	v := ViewUpstreams(cfg, warning)
	action := "upstream_assign"
	v.Message = fmt.Sprintf("assigned: %s -> %s", cn, id)
	if clear {
		action, v.Message = "upstream_unassign", "cleared: "+cn
	}
	st.Audit(actor, action, cn)
	return v, nil
}

// ReconcileUpstreams re-applies the persisted config and reports what's down.
func ReconcileUpstreams(st *store.Store, actor string, enabled bool, apply Applier) (UpstreamView, error) {
	if !enabled {
		return UpstreamView{}, ErrUpstreamsDisabled
	}
	cfg := LoadUpstreamConfig(st)
	v := ViewUpstreams(cfg, apply(cfg))
	st.Audit(actor, "upstream_reconcile", "")
	return v, nil
}

func (s *Server) handleUpstreamAdd(c call, in upstream.Upstream) (UpstreamView, error) {
	return AddUpstream(s.Store, c.u.Username, s.UpstreamsEnabled, in, s.applyUpstreams)
}

func (s *Server) handleUpstreamDelete(c call, in struct {
	ID string `json:"id"`
}) (UpstreamView, error) {
	return DeleteUpstream(s.Store, c.u.Username, s.UpstreamsEnabled, in.ID, s.applyUpstreams)
}

func (s *Server) handleUpstreamSetDefault(c call, in struct{ ID string }) (UpstreamView, error) {
	return SetDefaultUpstream(s.Store, c.u.Username, s.UpstreamsEnabled, in.ID, s.applyUpstreams)
}

func (s *Server) handleUpstreamAssign(c call, in struct {
	CN, ID string
	Clear  bool
}) (UpstreamView, error) {
	return AssignUpstream(s.Store, c.u.Username, s.UpstreamsEnabled, s.ConfigPath, in.CN, in.ID, in.Clear, s.RewriteConnectedClientRule)
}

func (s *Server) handleUpstreamReconcile(c call, _ none) (UpstreamView, error) {
	return ReconcileUpstreams(s.Store, c.u.Username, s.UpstreamsEnabled, s.applyUpstreams)
}
