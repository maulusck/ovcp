package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

// StatsConfig is the admin-tunable traffic-history sampling/retention
// policy, persisted under statsConfigKey.
type StatsConfig struct {
	SampleIntervalSec int // how often a traffic-history row is written/pruned
	RetentionHours    int // how far back samples/sessions are kept and queried
}

// DefaultStatsConfig seeds from OVCP_STATS_* env vars (container/unattended
// init), same pattern as ovpnconf.Default.
func DefaultStatsConfig() StatsConfig {
	return StatsConfig{
		SampleIntervalSec: ovpnconf.EnvInt("OVCP_STATS_SAMPLE_INTERVAL", 60),
		RetentionHours:    ovpnconf.EnvInt("OVCP_STATS_RETENTION_HOURS", 24),
	}
}

func (c StatsConfig) SampleInterval() time.Duration {
	return time.Duration(c.SampleIntervalSec) * time.Second
}
func (c StatsConfig) Retention() time.Duration { return time.Duration(c.RetentionHours) * time.Hour }

const statsConfigKey = "stats_config"

// LoadStatsConfig/SaveStatsConfig: the one read/write path, shared by the
// CLI (`ovcp stats config`) and Server.StatsConfig below.
func LoadStatsConfig(s *store.Store) StatsConfig {
	return store.LoadJSON(s, statsConfigKey, DefaultStatsConfig())
}
func SaveStatsConfig(s *store.Store, cfg StatsConfig) error {
	return store.SaveJSON(s, statsConfigKey, cfg)
}

// StatsConfig reads the live persisted config — RunSampler re-reads it every
// tick, so `stats config set` takes effect without restarting serve.
func (s *Server) StatsConfig() StatsConfig { return LoadStatsConfig(s.Store) }

// RunSampler polls on PollInterval (OVCP_STATUS_INTERVAL): every tick
// refreshes certs.hosts + detects disconnects, every SampleIntervalSec'th
// tick also records a traffic sample. ponytail: CN-keyed, so a same-tick reconnect is invisible.
func (s *Server) RunSampler(stop <-chan struct{}) {
	prev := map[string]controller.VPNClient{}
	tick := 0
	t := time.NewTicker(s.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			tick++
			cfg := s.StatsConfig()
			ticksPerSample := max(1, int(cfg.SampleInterval()/s.PollInterval))
			prev = s.samplerTick(tick%ticksPerSample == 0, cfg.Retention(), prev)
		}
	}
}

func (s *Server) samplerTick(sampleStats bool, retention time.Duration, prev map[string]controller.VPNClient) (next map[string]controller.VPNClient) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("sampler tick panicked, skipping", "err", r)
			next = prev
		}
	}()

	if s.VPN.Pid() == 0 {
		return prev // openvpn not running; skip this tick, not an error
	}
	// Connect is a no-op once already connected — this is the retry for
	// serve's own best-effort eager connect racing openvpn's own startup,
	// and the self-heal if the mgmt connection ever drops later.
	if s.UpstreamsEnabled && UpstreamAuthActive(s.Store) {
		if err := s.Mgmt.Connect(); err != nil {
			slog.Warn("mgmt connect (per-CN routing)", "err", err)
		}
	}
	cur, err := s.Mgmt.Status()
	if err != nil {
		return prev // status file not ready yet, or a torn read; skip this tick, not an error
	}
	if err := s.RefreshCertsHosts(cur); err != nil {
		slog.Warn("certs.hosts refresh failed", "err", err)
	}

	now := time.Now()
	curByCN := make(map[string]controller.VPNClient, len(cur))
	for _, c := range cur {
		curByCN[c.CN] = c
	}
	// Every tick, not gated behind sampleStats — a same-sample-window
	// connect+disconnect must still show up here, not vanish silently.
	for cn, was := range prev {
		if _, stillUp := curByCN[cn]; stillUp {
			continue
		}
		sess := store.ClientSession{
			CN: was.CN, RealAddress: was.RealAddress,
			ConnectedAt: was.ConnectedSince, DisconnectedAt: now,
			BytesRecv: was.BytesRecv, BytesSent: was.BytesSent,
		}
		if err := s.Store.EndSession(sess); err != nil {
			slog.Warn("stats session write failed", "cn", cn, "err", err)
		}
	}

	if !sampleStats {
		return curByCN
	}
	for _, c := range cur {
		if err := s.Store.AddClientSample(now, c.CN, c.BytesRecv, c.BytesSent); err != nil {
			slog.Warn("stats sample write failed", "cn", c.CN, "err", err)
		}
	}
	if err := s.Store.PruneStats(now.Add(-retention)); err != nil {
		slog.Warn("stats prune failed", "err", err)
	}
	return curByCN
}

// handleStats serves the global aggregate, or one client's series when ?cn=
// is given — same shape either way, so the frontend chart code doesn't care.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, u *store.User) {
	cn := r.URL.Query().Get("cn")
	if len(cn) > pki.MaxCNLen {
		jsonErr(w, 400, "cn too long")
		return
	}
	since := time.Now().Add(-s.StatsConfig().Retention())
	var samples []store.Sample
	var err error
	if cn != "" {
		samples, err = s.Store.ClientSamples(cn, since)
	} else {
		samples, err = s.Store.Samples(since)
	}
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	sessions, err := s.Store.Sessions(200)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if samples == nil {
		samples = []store.Sample{}
	}
	if sessions == nil {
		sessions = []store.ClientSession{}
	}
	jsonOK(w, map[string]any{"samples": samples, "sessions": sessions})
}
