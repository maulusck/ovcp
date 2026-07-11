package api

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// logHandler builds a GET handler tailing <DataDir>/filename; shared by the
// openvpn.log and ovcp.log routes so the tailing logic exists exactly once.
func (s *Server) logHandler(filename string) handler {
	return func(w http.ResponseWriter, r *http.Request, u *store.User) {
		lines, err := tailLines(filepath.Join(s.DataDir, filename), tailLineLimit, isStatusPollLine)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonOK(w, map[string]any{"lines": lines})
	}
}

// handleLogsDownload bundles the full (untailed) log files into one zip for
// offline analysis — unlike the tailed panels, this is the complete file.
// Takes no request input at all: only ever reads these two fixed filenames,
// nothing derived from the request ever reaches the filesystem. Per-log
// copy/download in the UI is handled entirely client-side from what's
// already loaded, precisely to avoid needing a parametrized version of this.
func (s *Server) handleLogsDownload(w http.ResponseWriter, r *http.Request, u *store.User) {
	w.Header().Set("Content-Type", "application/zip")
	name := "ovcp-logs-" + time.Now().Format("20060102-150405") + ".zip"
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, filename := range []string{"openvpn.log", "ovcp.log"} {
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
