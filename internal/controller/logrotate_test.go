package controller

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotateLogFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	if err := os.WriteFile(path, []byte("hello\nworld\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := RotateLog(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() != 0 {
		t.Fatalf("original not truncated: size=%v err=%v", fi, err)
	}
	gens, err := rotatedGenerations(path)
	if err != nil || len(gens) != 1 {
		t.Fatalf("gens=%v err=%v, want exactly 1", gens, err)
	}
	data, err := os.ReadFile(gens[0].file)
	if err != nil || string(data) != "hello\nworld\n" {
		t.Fatalf("rotated content = %q err=%v", data, err)
	}
}

// TestWriteRotatedFileCollision: two rotations in the same wall-clock second
// must not clobber each other — the second lands in a ".N" file instead.
func TestWriteRotatedFileCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	if err := writeRotatedFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeRotatedFile(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	gens, err := rotatedGenerations(path)
	if err != nil || len(gens) != 2 {
		t.Fatalf("gens=%v err=%v, want 2 (no clobber)", gens, err)
	}
	var contents []string
	for _, g := range gens {
		data, _ := os.ReadFile(g.file)
		contents = append(contents, string(data))
	}
	if !(contents[0] == "first" && contents[1] == "second") && !(contents[0] == "second" && contents[1] == "first") {
		t.Fatalf("contents = %v, want [first second] in some order", contents)
	}
}

func TestRotateLogMissingOrEmpty(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.log")
	if err := RotateLog(missing); err != nil {
		t.Fatalf("missing file should be a no-op, got %v", err)
	}
	if gens, _ := rotatedGenerations(missing); len(gens) != 0 {
		t.Fatalf("missing file rotated something: %v", gens)
	}

	empty := filepath.Join(dir, "empty.log")
	os.WriteFile(empty, nil, 0o640)
	if err := RotateLog(empty); err != nil {
		t.Fatalf("empty file should be a no-op, got %v", err)
	}
	if gens, _ := rotatedGenerations(empty); len(gens) != 0 {
		t.Fatalf("empty file rotated something: %v", gens)
	}
}

// writeGen fabricates a rotated generation with an explicit timestamp,
// bypassing RotateLog's time.Now() so compress/prune tests can control age.
func writeGen(t *testing.T, path string, age time.Duration, compressed bool, content string) {
	t.Helper()
	stamp := time.Now().UTC().Add(-age).Format(rotatedTimeFormat)
	name := path + "-" + stamp
	if compressed {
		name += ".gz"
		f, err := os.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		gw := gzip.NewWriter(f)
		gw.Write([]byte(content))
		gw.Close()
		f.Close()
		return
	}
	if err := os.WriteFile(name, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestCompressOldKeepsNewestUncompressed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	writeGen(t, path, 3*24*time.Hour, false, "oldest")
	writeGen(t, path, 2*24*time.Hour, false, "middle")
	writeGen(t, path, 1*24*time.Hour, false, "newest")

	if err := compressOld(path, 1); err != nil {
		t.Fatal(err)
	}
	gens, err := rotatedGenerations(path)
	if err != nil || len(gens) != 3 {
		t.Fatalf("gens=%v err=%v, want 3", gens, err)
	}
	// oldest 2 compressed, newest still plain
	if !gens[0].compressed || !gens[1].compressed || gens[2].compressed {
		t.Fatalf("compressed flags = %v,%v,%v, want true,true,false", gens[0].compressed, gens[1].compressed, gens[2].compressed)
	}
	f, err := os.Open(gens[0].file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(gr)
	if string(data) != "oldest" {
		t.Fatalf("decompressed content = %q, want %q", data, "oldest")
	}
}

func TestPruneOldByAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	writeGen(t, path, 30*24*time.Hour, false, "ancient")
	writeGen(t, path, 20*24*time.Hour, true, "old-compressed")
	writeGen(t, path, 1*24*time.Hour, false, "recent")

	if err := pruneOld(path, 14); err != nil {
		t.Fatal(err)
	}
	gens, err := rotatedGenerations(path)
	if err != nil || len(gens) != 1 {
		t.Fatalf("gens=%v err=%v, want 1 survivor", gens, err)
	}
	data, _ := os.ReadFile(gens[0].file)
	if string(data) != "recent" {
		t.Fatalf("survivor content = %q, want %q", data, "recent")
	}
}

func TestPruneOldDisabledAtZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	writeGen(t, path, 365*24*time.Hour, false, "ancient")
	if err := pruneOld(path, 0); err != nil {
		t.Fatal(err)
	}
	gens, _ := rotatedGenerations(path)
	if len(gens) != 1 {
		t.Fatalf("retentionDays<=0 must not prune, got %v", gens)
	}
}

func TestRotateLogsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "openvpn.log")
	b := filepath.Join(dir, "ovcp.log")
	os.WriteFile(a, []byte("a-content"), 0o640)
	os.WriteFile(b, []byte("b-content"), 0o640)

	cfg := LogConfig{Enabled: true, RetentionDays: 14, KeepUncompressed: 2}
	if err := RotateLogs([]string{a, b}, cfg); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a, b} {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() != 0 {
			t.Fatalf("%s not truncated: %v %v", p, fi, err)
		}
		gens, _ := rotatedGenerations(p)
		if len(gens) != 1 {
			t.Fatalf("%s gens = %v, want 1", p, gens)
		}
	}
}

func TestLogStatusFor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.log")
	os.WriteFile(path, []byte("current"), 0o640)
	writeGen(t, path, 2*24*time.Hour, true, "old")

	st := LogStatusFor("openvpn", path)
	if st.CurrentSize != int64(len("current")) || st.Generations != 1 || st.Oldest.IsZero() {
		t.Fatalf("status = %+v", st)
	}
}
