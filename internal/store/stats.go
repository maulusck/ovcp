package store

import "time"

// Sample is one tick of history: cumulative volume (BytesRecv/BytesSent, as
// OpenVPN itself reports them) and a rate (BytesRecvRate/BytesSentRate,
// bytes/sec since the previous sample — 0 for the first one, no baseline
// yet). Computed once here, so the HTTP API and the CLI's own snapshot mode
// display the exact same numbers; nothing downstream re-derives a rate.
type Sample struct {
	TS            time.Time
	Clients       int
	BytesRecv     uint64
	BytesSent     uint64
	BytesRecvRate uint64
	BytesSentRate uint64
}

// Rate returns bytes/sec for a counter that moved from prev to cur over dt.
// A counter that decreased (OpenVPN resets a client's own counter on
// reconnect) contributes 0 rather than a negative rate. The one rate
// formula in this codebase — used below for both the global and per-client
// history, and by the CLI's own live -follow view (cmd/ovcp/stats.go).
func Rate(prev, cur uint64, dt time.Duration) uint64 {
	if dt <= 0 {
		return 0
	}
	return uint64(float64(ClampedDelta(prev, cur)) / dt.Seconds())
}

// ClampedDelta is cur-prev floored at 0 — the same guard Rate applies to a
// single counter, exported so a caller summing many counters (Samples'
// global aggregate, the CLI's global -follow line) can clamp each one
// before summing. Summing first and clamping once would let one
// reconnecting client's dip cancel out another client's real growth.
func ClampedDelta(prev, cur uint64) uint64 {
	if cur <= prev {
		return 0
	}
	return cur - prev
}

type ClientSession struct {
	ID             int64
	CN             string
	RealAddress    string
	ConnectedAt    time.Time
	DisconnectedAt time.Time
	BytesRecv      uint64
	BytesSent      uint64
}

// AddClientSample records one connected client's byte counters at ts —
// the sampler calls this once per connected client per tick.
func (s *Store) AddClientSample(ts time.Time, cn string, bytesRecv, bytesSent uint64) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO client_samples(ts, cn, bytes_recv, bytes_sent) VALUES (?,?,?,?)`,
		ts.Unix(), cn, bytesRecv, bytesSent)
	return err
}

// Samples returns the whole-VPN aggregate since the given time, oldest first
// (chart order): connected-client count, summed volume, and a rate summed
// from each still-connected client's own clamped delta — not from
// differencing the aggregate itself, which would dip or spike whenever a
// client joins or leaves mid-window instead of just reflecting real traffic.
func (s *Store) Samples(since time.Time) ([]Sample, error) {
	rows, err := s.db.Query(
		`SELECT ts, cn, bytes_recv, bytes_sent FROM client_samples
		 WHERE ts >= ? ORDER BY ts, cn`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type reading struct{ recv, sent uint64 }
	type tick struct {
		ts   int64
		byCN map[string]reading
	}
	var ticks []tick
	for rows.Next() {
		var ts int64
		var cn string
		var r reading
		if err := rows.Scan(&ts, &cn, &r.recv, &r.sent); err != nil {
			return nil, err
		}
		if len(ticks) == 0 || ticks[len(ticks)-1].ts != ts {
			ticks = append(ticks, tick{ts: ts, byCN: map[string]reading{}})
		}
		ticks[len(ticks)-1].byCN[cn] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Sample, len(ticks))
	for i, tk := range ticks {
		sm := Sample{TS: time.Unix(tk.ts, 0), Clients: len(tk.byCN)}
		for _, r := range tk.byCN {
			sm.BytesRecv += r.recv
			sm.BytesSent += r.sent
		}
		if i > 0 {
			dt := time.Duration(tk.ts-ticks[i-1].ts) * time.Second
			var recvDelta, sentDelta uint64
			for cn, r := range tk.byCN {
				if prev, ok := ticks[i-1].byCN[cn]; ok {
					recvDelta += ClampedDelta(prev.recv, r.recv)
					sentDelta += ClampedDelta(prev.sent, r.sent)
				}
			}
			sm.BytesRecvRate = Rate(0, recvDelta, dt)
			sm.BytesSentRate = Rate(0, sentDelta, dt)
		}
		out[i] = sm
	}
	return out, nil
}

// ClientSamples returns one client's own series since the given time,
// oldest first. Clients is left unset — a per-CN row isn't a count.
func (s *Store) ClientSamples(cn string, since time.Time) ([]Sample, error) {
	rows, err := s.db.Query(
		`SELECT ts, bytes_recv, bytes_sent FROM client_samples
		 WHERE cn = ? AND ts >= ? ORDER BY ts`, cn, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	var prevTS int64
	var prevRecv, prevSent uint64
	for rows.Next() {
		var ts int64
		var recv, sent uint64
		if err := rows.Scan(&ts, &recv, &sent); err != nil {
			return nil, err
		}
		sm := Sample{TS: time.Unix(ts, 0), BytesRecv: recv, BytesSent: sent}
		if len(out) > 0 {
			dt := time.Duration(ts-prevTS) * time.Second
			sm.BytesRecvRate = Rate(prevRecv, recv, dt)
			sm.BytesSentRate = Rate(prevSent, sent, dt)
		}
		out = append(out, sm)
		prevTS, prevRecv, prevSent = ts, recv, sent
	}
	return out, rows.Err()
}

func (s *Store) EndSession(cs ClientSession) error {
	_, err := s.db.Exec(
		`INSERT INTO client_sessions(cn, real_address, connected_at, disconnected_at, bytes_recv, bytes_sent)
		 VALUES (?,?,?,?,?,?)`,
		cs.CN, cs.RealAddress, cs.ConnectedAt.Unix(), cs.DisconnectedAt.Unix(), cs.BytesRecv, cs.BytesSent)
	return err
}

// Sessions returns the most recently ended sessions, newest first.
func (s *Store) Sessions(limit int) ([]ClientSession, error) {
	rows, err := s.db.Query(
		`SELECT id, cn, real_address, connected_at, disconnected_at, bytes_recv, bytes_sent
		 FROM client_sessions ORDER BY disconnected_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientSession
	for rows.Next() {
		var cs ClientSession
		var connectedAt, disconnectedAt int64
		if err := rows.Scan(&cs.ID, &cs.CN, &cs.RealAddress, &connectedAt, &disconnectedAt,
			&cs.BytesRecv, &cs.BytesSent); err != nil {
			return nil, err
		}
		cs.ConnectedAt, cs.DisconnectedAt = time.Unix(connectedAt, 0), time.Unix(disconnectedAt, 0)
		out = append(out, cs)
	}
	return out, rows.Err()
}

// PruneStats drops samples/sessions older than before, bounding table growth
// (called every sampler tick — cheap no-op deletes most of the time).
func (s *Store) PruneStats(before time.Time) error {
	if _, err := s.db.Exec(`DELETE FROM client_samples WHERE ts < ?`, before.Unix()); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM client_sessions WHERE disconnected_at < ?`, before.Unix())
	return err
}
