package store

import "time"

type Sample struct {
	TS        time.Time
	Clients   int
	BytesRecv uint64
	BytesSent uint64
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

func (s *Store) AddSample(sm Sample) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO vpn_samples(ts, clients, bytes_recv, bytes_sent) VALUES (?,?,?,?)`,
		sm.TS.Unix(), sm.Clients, sm.BytesRecv, sm.BytesSent)
	return err
}

// Samples returns aggregate snapshots since the given time, oldest first (chart order).
func (s *Store) Samples(since time.Time) ([]Sample, error) {
	rows, err := s.db.Query(
		`SELECT ts, clients, bytes_recv, bytes_sent FROM vpn_samples WHERE ts >= ? ORDER BY ts`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var sm Sample
		var ts int64
		if err := rows.Scan(&ts, &sm.Clients, &sm.BytesRecv, &sm.BytesSent); err != nil {
			return nil, err
		}
		sm.TS = time.Unix(ts, 0)
		out = append(out, sm)
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
	if _, err := s.db.Exec(`DELETE FROM vpn_samples WHERE ts < ?`, before.Unix()); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM client_sessions WHERE disconnected_at < ?`, before.Unix())
	return err
}
