package controller

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ovcp/ovcp/internal/ovpnconf"
)

// LogConfig is the admin-tunable rotation policy for ovcp's own 3 flat log
// files (openvpn.log, ovcp.log, dnsmasq.log) — persisted under "log_config"
// (see `ovcp logs config`).
type LogConfig struct {
	Enabled          bool
	RetentionDays    int
	KeepUncompressed int
}

// DefaultLogConfig seeds from OVCP_LOG_* env vars (container/unattended
// init), same pattern as ovpnconf.Default. Only consulted while nothing's
// persisted yet — after the first save, `ovcp logs config set` takes over.
func DefaultLogConfig() LogConfig {
	return LogConfig{
		Enabled:          os.Getenv("OVCP_LOG_ROTATE_ENABLED") != "false",
		RetentionDays:    ovpnconf.EnvInt("OVCP_LOG_RETENTION_DAYS", 14),
		KeepUncompressed: ovpnconf.EnvInt("OVCP_LOG_KEEP_UNCOMPRESSED", 2),
	}
}

// rotatedTimeFormat: zero-padded so a lexical sort of filenames is also a
// chronological sort, and glob-safe (no ':' or spaces).
const rotatedTimeFormat = "20060102T150405Z"

// RotateLog copytruncates path: content moves to "path-<timestamp>", then
// path is truncated to 0 in place — a live O_APPEND writer's next write
// lands at the fresh EOF, no reopen needed. Not atomic; ok for non-audit logs.
func RotateLog(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	rotated := path + "-" + time.Now().UTC().Format(rotatedTimeFormat)
	if err := os.WriteFile(rotated, data, 0o640); err != nil {
		return err
	}
	return os.Truncate(path, 0)
}

// RotateLogs rotates every path under cfg's policy — RotateLog, then
// compress past KeepUncompressed, then delete past RetentionDays. One
// path's failure doesn't stop the rest; all errors are joined.
func RotateLogs(paths []string, cfg LogConfig) error {
	var errs []error
	for _, p := range paths {
		if err := RotateLog(p); err != nil {
			errs = append(errs, fmt.Errorf("%s: rotate: %w", p, err))
			continue
		}
		if err := compressOld(p, cfg.KeepUncompressed); err != nil {
			errs = append(errs, fmt.Errorf("%s: compress: %w", p, err))
		}
		if err := pruneOld(p, cfg.RetentionDays); err != nil {
			errs = append(errs, fmt.Errorf("%s: prune: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// generation is one rotated file for a log path.
type generation struct {
	file       string
	t          time.Time
	compressed bool
}

// rotatedGenerations lists path's rotated files ("path-<timestamp>[.gz]"),
// oldest first. Names that don't parse are skipped, not an error.
func rotatedGenerations(path string) ([]generation, error) {
	matches, err := filepath.Glob(path + "-*")
	if err != nil {
		return nil, err
	}
	prefix := filepath.Base(path) + "-"
	var gens []generation
	for _, m := range matches {
		stamp := strings.TrimPrefix(filepath.Base(m), prefix)
		compressed := strings.HasSuffix(stamp, ".gz")
		stamp = strings.TrimSuffix(stamp, ".gz")
		t, err := time.Parse(rotatedTimeFormat, stamp)
		if err != nil {
			continue
		}
		gens = append(gens, generation{file: m, t: t, compressed: compressed})
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i].t.Before(gens[j].t) })
	return gens, nil
}

// compressOld gzips every uncompressed generation of path except the newest
// keepUncompressed.
func compressOld(path string, keepUncompressed int) error {
	gens, err := rotatedGenerations(path)
	if err != nil {
		return err
	}
	var plain []generation
	for _, g := range gens {
		if !g.compressed {
			plain = append(plain, g)
		}
	}
	if keepUncompressed < 0 {
		keepUncompressed = 0
	}
	if len(plain) <= keepUncompressed {
		return nil
	}
	for _, g := range plain[:len(plain)-keepUncompressed] {
		if err := gzipFile(g.file); err != nil {
			return err
		}
	}
	return nil
}

func gzipFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		gw.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(path+".gz", buf.Bytes(), 0o640); err != nil {
		return err
	}
	return os.Remove(path)
}

// pruneOld deletes path's generations older than retentionDays.
// <=0 disables pruning — an explicit "keep forever", not "delete everything".
func pruneOld(path string, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	gens, err := rotatedGenerations(path)
	if err != nil {
		return err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	for _, g := range gens {
		if g.t.Before(cutoff) {
			if err := os.Remove(g.file); err != nil {
				return err
			}
		}
	}
	return nil
}

// LogSourceStatus is one log source's rotation summary — `ovcp logs status`'s
// per-row payload.
type LogSourceStatus struct {
	Name        string
	Path        string
	CurrentSize int64
	Generations int
	Oldest      time.Time // zero if no rotations yet
	Newest      time.Time
}

// LogStatusFor reports path's current size and rotation history. A missing
// current file (never written, or just rotated) reports size 0, not an error.
func LogStatusFor(name, path string) LogSourceStatus {
	st := LogSourceStatus{Name: name, Path: path}
	if fi, err := os.Stat(path); err == nil {
		st.CurrentSize = fi.Size()
	}
	gens, _ := rotatedGenerations(path)
	st.Generations = len(gens)
	if len(gens) > 0 {
		st.Oldest, st.Newest = gens[0].t, gens[len(gens)-1].t
	}
	return st
}
