package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTailLinesMissingFile(t *testing.T) {
	lines, err := tailLines(filepath.Join(t.TempDir(), "nope.log"), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("want no lines for a missing file, got %v", lines)
	}
}

func TestTailLinesCapsAtN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.log")
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString("line " + strconv.Itoa(i) + "\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := tailLines(path, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 10 {
		t.Fatalf("want 10 lines, got %d", len(lines))
	}
	if lines[len(lines)-1] != "line 499" {
		t.Fatalf("want last line to be the file's last line, got %q", lines[len(lines)-1])
	}
}

func TestTailLinesBoundsRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// well over tailMaxBytes; a naive whole-file read would be wasteful here
	for i := 0; i < 20000; i++ {
		f.WriteString("padding line " + strconv.Itoa(i) + "\n")
	}
	f.WriteString("the tail\n")
	f.Close()
	lines, err := tailLines(path, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "the tail" {
		t.Fatalf("want [\"the tail\"], got %v", lines)
	}
}

func TestTailLinesSkip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	content := "2026-07-11 20:00:00 MANAGEMENT: CMD 'status 3'\n" +
		"2026-07-11 20:00:03 TLS: Initial packet from [AF_INET]203.0.113.7:5000\n" +
		"2026-07-11 20:00:03 MANAGEMENT: CMD 'status 3'\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := tailLines(path, 10, isStatusPollLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "TLS: Initial packet") {
		t.Fatalf("want only the TLS line, got %v", lines)
	}
}

func TestLogEndpoints(t *testing.T) {
	e := setup(t)
	e.login("viewer") // logs are readonly-visible, same as audit
	if r := e.req("GET", "/api/logs/openvpn", "", false); r.StatusCode != 200 {
		t.Fatal("openvpn.log missing should still 200:", r.Status)
	} else {
		var out struct{ Lines []string }
		json.NewDecoder(r.Body).Decode(&out)
		if len(out.Lines) != 0 {
			t.Fatalf("want no lines before openvpn.log exists, got %v", out.Lines)
		}
	}

	os.WriteFile(filepath.Join(e.dir, "ovcp.log"), []byte("hello\nworld\n"), 0o644)
	r := e.req("GET", "/api/logs/ovcp", "", false)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	var out struct{ Lines []string }
	json.NewDecoder(r.Body).Decode(&out)
	if len(out.Lines) != 2 || out.Lines[1] != "world" {
		t.Fatalf("want [hello world], got %v", out.Lines)
	}
}

func TestLogsDownloadZip(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	// openvpn.log deliberately absent — must be skipped, not an error.
	os.WriteFile(filepath.Join(e.dir, "ovcp.log"), []byte("line one\nline two\n"), 0o644)

	r := e.req("GET", "/api/logs/download", "", false)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q", ct)
	}
	body, _ := io.ReadAll(r.Body)
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "ovcp.log" {
		t.Fatalf("want only ovcp.log in the archive, got %v", zr.File)
	}
	rc, _ := zr.File[0].Open()
	content, _ := io.ReadAll(rc)
	if string(content) != "line one\nline two\n" {
		t.Fatalf("got %q", content)
	}
}

// handleLogsDownload takes no request input: any query string, including a
// path-traversal attempt, must be silently ignored — it still just returns
// the fixed two-file zip, proving nothing from the request reaches the
// filesystem.
func TestLogsDownloadIgnoresQueryParams(t *testing.T) {
	e := setup(t)
	e.login("viewer")
	os.WriteFile(filepath.Join(e.dir, "ovcp.log"), []byte("hi\n"), 0o644)

	r := e.req("GET", "/api/logs/download?file=../../etc/passwd", "", false)
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q, query params must not change the response shape", ct)
	}
	body, _ := io.ReadAll(r.Body)
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "ovcp.log" {
		t.Fatalf("want only ovcp.log, got %v", zr.File)
	}
}
