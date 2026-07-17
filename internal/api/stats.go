package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

const (
	statsSampleInterval = time.Minute
	// bounds DB rows (~1440 samples) and the /api/stats payload; sessions key
	// by CN not serial, so history survives cert revocation like the audit log does.
	StatsRetention = 24 * time.Hour
)

// RunStatsSampler polls VPN status on a fixed interval, persisting an aggregate sample and sessions until stop closes; each tick is recovered so one bad tick can't kill the daemon.
// ponytail: CN keys a client across polls, so a same-interval reconnect is invisible; CLIENT_DISCONNECT gives exact timing if ever needed.
func (s *Server) RunStatsSampler(stop <-chan struct{}) {
	prev := map[string]controller.VPNClient{}
	t := time.NewTicker(statsSampleInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			prev = s.statsTick(prev)
		}
	}
}

func (s *Server) statsTick(prev map[string]controller.VPNClient) (next map[string]controller.VPNClient) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("stats sampler tick panicked, skipping", "err", r)
			next = prev
		}
	}()

	cur, err := s.Mgmt.Status()
	if err != nil {
		return prev // VPN down/restarting; skip this tick, not an error
	}
	now := time.Now()
	curByCN := make(map[string]controller.VPNClient, len(cur))
	for _, c := range cur {
		curByCN[c.CN] = c
		if err := s.Store.AddClientSample(now, c.CN, c.BytesRecv, c.BytesSent); err != nil {
			slog.Warn("stats sample write failed", "cn", c.CN, "err", err)
		}
	}
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
	if err := s.Store.PruneStats(now.Add(-StatsRetention)); err != nil {
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
	since := time.Now().Add(-StatsRetention)
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
