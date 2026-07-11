package api

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ovcp/ovcp/internal/store"
)

const (
	tailMaxBytes  = 256 * 1024 // bound the read regardless of file size
	tailLineLimit = 200        // lines returned to the UI
)

// tailLines returns up to n trailing lines of path, reading at most the last
// tailMaxBytes so an unbounded log file can't blow up memory. A missing file
// is not an error — it just means the process hasn't logged anything yet.
func tailLines(path string, n int) ([]string, error) {
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
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// logHandler builds a GET handler tailing <DataDir>/filename; shared by the
// openvpn.log and ovcp.log routes so the tailing logic exists exactly once.
func (s *Server) logHandler(filename string) handler {
	return func(w http.ResponseWriter, r *http.Request, u *store.User) {
		lines, err := tailLines(filepath.Join(s.DataDir, filename), tailLineLimit)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonOK(w, map[string]any{"lines": lines})
	}
}

// logFilenames are the only files handleLogsDownload will ever serve — an
// allowlist, since ?file= is attacker-controlled input at a trust boundary.
var logFilenames = []string{"openvpn.log", "ovcp.log"}

// handleLogsDownload serves the full (untailed) log files for offline
// analysis — unlike the tailed panels, these are the complete files.
// No ?file= param: bundles everything into one zip. ?file=<name>: that one
// file raw, name must be in logFilenames.
func (s *Server) handleLogsDownload(w http.ResponseWriter, r *http.Request, u *store.User) {
	if f := r.URL.Query().Get("file"); f != "" {
		s.downloadOneLog(w, f)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	name := "ovcp-logs-" + time.Now().Format("20060102-150405") + ".zip"
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, filename := range logFilenames {
		data, err := os.ReadFile(filepath.Join(s.DataDir, filename))
		if err != nil {
			continue // missing log is not an error, same as the tailed view
		}
		f, err := zw.Create(filename)
		if err != nil {
			continue
		}
		f.Write(data)
	}
}

func (s *Server) downloadOneLog(w http.ResponseWriter, filename string) {
	valid := false
	for _, f := range logFilenames {
		if f == filename {
			valid = true
			break
		}
	}
	if !valid {
		jsonErr(w, 400, "unknown log file")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.DataDir, filename))
	if err != nil {
		jsonErr(w, 404, "log not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write(data)
}
