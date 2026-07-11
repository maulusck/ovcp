package api

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"path/filepath"

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
