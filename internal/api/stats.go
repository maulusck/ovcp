package api

import (
	"errors"
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

// LoadStatsConfig/SaveStatsConfig: the one read/write path, CLI and API alike;
// Save refuses a config the sampler can't run.
func LoadStatsConfig(s *store.Store) StatsConfig {
	return store.LoadJSON(s, statsConfigKey, DefaultStatsConfig())
}
func SaveStatsConfig(s *store.Store, actor string, cfg StatsConfig) (StatsConfig, error) {
	if cfg.SampleIntervalSec <= 0 || cfg.RetentionHours <= 0 {
		return cfg, errors.New("sample-interval-sec and retention-hours must be positive")
	}
	if err := store.SaveJSON(s, statsConfigKey, cfg); err != nil {
		return cfg, err
	}
	s.Audit(actor, "stats_config_change", "")
	return cfg, nil
}

// LoadLogConfig/SaveLogConfig: controller.LogConfig's one read/write path,
// CLI and API alike; Save refuses negative counts.
func LoadLogConfig(s *store.Store) controller.LogConfig {
	return store.LoadJSON(s, "log_config", controller.DefaultLogConfig())
}
func SaveLogConfig(s *store.Store, actor string, cfg controller.LogConfig) (controller.LogConfig, error) {
	if cfg.RetentionDays < 0 || cfg.KeepUncompressed < 0 {
		return cfg, errors.New("retention-days and keep-uncompressed must be 0 or more")
	}
	if err := store.SaveJSON(s, "log_config", cfg); err != nil {
		return cfg, err
	}
	s.Audit(actor, "log_config_change", "")
	return cfg, nil
}

// StatsConfig reads the live persisted config — RunSampler re-reads it every
// tick, so `stats config set` takes effect without restarting serve.
func (s *Server) StatsConfig() StatsConfig { return LoadStatsConfig(s.Store) }

// RunSampler polls on PollInterval (OVCP_STATUS_INTERVAL): every tick
// refreshes certs.hosts + detects disconnects, every SampleIntervalSec'th
// tick also records a traffic sample.
func (s *Server) RunSampler(stop <-chan struct{}) {
	prev := map[session]controller.VPNClient{}
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

// session identifies one connection: a reconnect between ticks, or a second
// client on the same CN, is a different session.
type session struct {
	cn    string
	since int64
}

func (s *Server) samplerTick(sampleStats bool, retention time.Duration, prev map[session]controller.VPNClient) (next map[session]controller.VPNClient) {
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
	live := make(map[session]controller.VPNClient, len(cur))
	for _, c := range cur {
		live[session{c.CN, c.ConnectedSince.Unix()}] = c
	}
	// Every tick, not gated behind sampleStats — a same-sample-window
	// connect+disconnect must still show up here, not vanish silently.
	for k, was := range prev {
		if _, stillUp := live[k]; stillUp {
			continue
		}
		sess := store.ClientSession{
			CN: was.CN, RealAddress: was.RealAddress,
			ConnectedAt: was.ConnectedSince, DisconnectedAt: now,
			BytesRecv: was.BytesRecv, BytesSent: was.BytesSent,
		}
		if err := s.Store.EndSession(sess); err != nil {
			slog.Warn("stats session write failed", "cn", was.CN, "err", err)
		}
	}

	if !sampleStats {
		return live
	}
	for _, c := range cur {
		if err := s.Store.AddClientSample(now, c.CN, c.BytesRecv, c.BytesSent); err != nil {
			slog.Warn("stats sample write failed", "cn", c.CN, "err", err)
		}
	}
	if err := s.Store.PruneStats(now.Add(-retention)); err != nil {
		slog.Warn("stats prune failed", "err", err)
	}
	return live
}

// StatsSnapshot is stats and GET /api/stats: samples within the retention
// window and the newest finished sessions, both for one CN when cn is set.
type StatsSnapshot struct {
	Samples  []store.Sample        `json:"samples"`
	Sessions []store.ClientSession `json:"sessions"`
}

// Stats reads the traffic history, globally or for cn.
func Stats(st *store.Store, cn string) (StatsSnapshot, error) {
	since := time.Now().Add(-LoadStatsConfig(st).Retention())
	var out StatsSnapshot
	var err error
	if cn != "" {
		out.Samples, err = st.ClientSamples(cn, since)
	} else {
		out.Samples, err = st.Samples(since)
	}
	if err != nil {
		return out, err
	}
	sessions, err := st.Sessions(200)
	if err != nil {
		return out, err
	}
	out.Sessions = []store.ClientSession{}
	for _, x := range sessions {
		if cn == "" || x.CN == cn {
			out.Sessions = append(out.Sessions, x)
		}
	}
	if out.Samples == nil {
		out.Samples = []store.Sample{}
	}
	return out, nil
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, u *store.User) {
	cn := r.URL.Query().Get("cn")
	if len(cn) > pki.MaxCNLen {
		jsonErr(w, 400, "cn too long")
		return
	}
	act(w)(Stats(s.Store, cn))
}
