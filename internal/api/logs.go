package api

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/store"
)

const (
	tailMaxBytes  = 256 * 1024 // bound the read regardless of file size
	tailLineLimit = 200        // lines returned to the UI
	// ponytail: no unbounded audit query exists, so the "complete" export is
	// capped here instead — raise this (or add one) if an install ever has
	// more audit rows than this in its lifetime.
	auditDownloadLimit = 1_000_000
)

// tailLines returns up to n trailing lines of path, reading at most the last
// tailMaxBytes so an unbounded log file can't blow up memory. A missing file
// is not an error — it just means the process hasn't logged anything yet.
// Lines matching skip (nil = none) are dropped before the n-line cap is
// applied, so noise doesn't crowd real content out of the tail.
func tailLines(path string, n int, skip func(string) bool) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > tailMaxBytes {
		f.Seek(st.Size()-tailMaxBytes, io.SeekStart)
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if skip != nil && skip(line) {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// isStatusPollLine matches the "status 3" command openvpn logs on its
// management socket every time the app polls VPN status (every few seconds,
// see App.svelte). It's not connection noise (that's gone now that the
// mgmt client holds one connection instead of dialing per poll) — it's a
// real command echo, just one that fires often enough to drown out
// everything else in a 200-line tail.
func isStatusPollLine(line string) bool {
	return strings.Contains(line, `MANAGEMENT: CMD 'status 3'`)
}

// logHandler builds a GET handler tailing <DataDir>/logs/filename; shared by
// the openvpn.log and ovcp.log routes so the tailing logic exists exactly once.
func (s *Server) logHandler(filename string) handler {
	return func(w http.ResponseWriter, r *http.Request, u *store.User) {
		lines, err := tailLines(filepath.Join(s.DataDir, "logs", filename), tailLineLimit, isStatusPollLine)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonOK(w, map[string]any{"lines": lines})
	}
}

// handleLogsDownload bundles a complete, unencrypted audit package for
// security/ops review: the full log files, full audit trail, and a
// status.json snapshot (VPN/certs/users/config — all already served to any
// readonly admin individually, so bundling it adds no new exposure). No
// private keys, no DB file — that's what the encrypted `ovcp backup` is
// for. Deliberately unparametrized: nothing from the request reaches the
// filesystem or DB, so there's no parameter to get wrong.
func (s *Server) handleLogsDownload(w http.ResponseWriter, r *http.Request, u *store.User) {
	w.Header().Set("Content-Type", "application/zip")
	name := "ovcp-audit-" + time.Now().Format("20060102-150405") + ".zip"
	if cn := sanitizeFilename(s.DefaultRemote); cn != "" {
		name = "ovcp-audit-" + cn + "-" + time.Now().Format("20060102-150405") + ".zip"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, filename := range []string{"openvpn.log", "ovcp.log"} {
		data, err := os.ReadFile(filepath.Join(s.DataDir, "logs", filename))
		if err != nil {
			continue // missing log is not an error, same as the tailed view
		}
		f, err := zw.Create(filename)
		if err != nil {
			continue
		}
		f.Write(data)
	}
	if entries, err := s.Store.AuditTail(auditDownloadLimit); err == nil {
		var sb strings.Builder
		for _, e := range entries { // newest-first, same order the UI shows
			fmt.Fprintf(&sb, "%s %s %s %s\n", e.TS.Format(time.RFC3339), e.Actor, e.Action, e.Detail)
		}
		if f, err := zw.Create("audit.log"); err == nil {
			f.Write([]byte(sb.String()))
		}
	}
	if data, err := json.MarshalIndent(s.statusExport(), "", "  "); err == nil {
		if f, err := zw.Create("status.json"); err == nil {
			f.Write(data)
		}
	}
}

// statusExport is a non-sensitive, point-in-time snapshot of server state,
// built entirely from the same reads the /status, /certs, /users, /config
// endpoints already do — see handleLogsDownload. Certs carry no secrets
// (private keys are never stored); Users goes through userSummary because
// store.User does (PassHash, TOTPSecret).
type statusExport struct {
	GeneratedAt time.Time
	ServerCN    string
	Version     string
	VPNUp       bool
	Clients     []controller.VPNClient
	Certs       []store.Cert
	Users       []userSummary
	Config      ovpnconf.Config
}

func (s *Server) statusExport() statusExport {
	clients, err := s.Mgmt.Status()
	if clients == nil {
		clients = []controller.VPNClient{}
	}
	exp := statusExport{
		GeneratedAt: time.Now(),
		ServerCN:    s.DefaultRemote,
		Version:     s.Version,
		VPNUp:       err == nil,
		Clients:     clients,
		Certs:       []store.Cert{},
		Users:       []userSummary{},
		Config:      s.LoadConfig(),
	}
	if certs, _ := s.Store.ListCerts(); certs != nil {
		exp.Certs = certs
	}
	if users, err := s.Store.ListUsers(); err == nil {
		for _, x := range users {
			exp.Users = append(exp.Users, userSummary{x.Username, x.Role, x.Disabled, x.TOTPSecret != "", x.CreatedAt})
		}
	}
	return exp
}

// sanitizeFilename keeps a Content-Disposition filename segment (the server
// CN, which is admin-supplied and ends up in an HTTP response header) to a
// safe, boring character set.
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}
