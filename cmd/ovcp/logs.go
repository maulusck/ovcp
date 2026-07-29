package main

import (
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
)

var (
	logsOps      = []string{"config", "rotate", "status"}
	logConfigOps = []string{"get", "set"}
)

// logSource pairs a display name with its file path — a fixed, ordered list
// (not a map) so `logs status`'s rows print in the same order every time.
type logSource struct{ name, path string }

// logSources builds one entry per controller.LogNames. status (the live
// client-list file, /run/ovcp/status) is excluded — rewritten in place
// already, never grows, and isn't a log.
func logSources(dataDir string) []logSource {
	ld := dataPaths(dataDir).LogsDir
	out := make([]logSource, len(controller.LogNames))
	for i, name := range controller.LogNames {
		out[i] = logSource{name, filepath.Join(ld, name+".log")}
	}
	return out
}

// logPaths is logSources' paths alone — what RotateLogs takes.
func logPaths(dataDir string) []string {
	var paths []string
	for _, src := range logSources(dataDir) {
		paths = append(paths, src.path)
	}
	return paths
}

// loadLogConfig/saveLogConfig round-trip controller.LogConfig through the
// store's settings table under "log_config" — schema-free, so an install
// without that key yet just gets DefaultLogConfig.
func loadLogConfig(s *store.Store) controller.LogConfig {
	return store.LoadJSON(s, "log_config", controller.DefaultLogConfig())
}

func saveLogConfig(s *store.Store, cfg controller.LogConfig) error {
	return store.SaveJSON(s, "log_config", cfg)
}

var logConfigBodies = map[string]func(fs *flag.FlagSet) func(ctx *cliContext){
	"get": cmdLogsConfigGet, "set": cmdLogsConfigSet,
}

// cmdLogs wraps config get/set, a one-shot rotate (what cron should call),
// and a status summary. No dry-run or prune subcommand — rotation is a
// plain idempotent copytruncate, and RetentionDays is the prune policy.
func cmdLogs(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "logs", logsOps, logsOpDesc)
		switch op {
		case "config":
			configOp("logs config", logConfigOps, configOpDesc, logConfigBodies)(ctx, rest)
		case "rotate":
			rfs := newFlags("logs rotate")
			subUsage(rfs, "logs rotate")
			rfs.Parse(rest)
			cmdLogsRotate(ctx)
		case "status":
			sfs := newFlags("logs status")
			subUsage(sfs, "logs status")
			sfs.Parse(rest)
			cmdLogsStatus(ctx)
		}
	}
}

func printLogConfigText(c controller.LogConfig) {
	fmt.Println("enabled:          ", boolText(c.Enabled))
	fmt.Println("retention-days:   ", c.RetentionDays)
	fmt.Println("keep-uncompressed:", c.KeepUncompressed)
}

func cmdLogsConfigGet(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		output(loadLogConfig(s), printLogConfigText)
	}
}

// cmdLogsConfigSet: same "empty means unchanged" idiom every config set
// uses, except 0 is a real value here (RetentionDays: 0 = keep forever), so
// the "unchanged" sentinel is -1, not 0.
func cmdLogsConfigSet(fs *flag.FlagSet) func(ctx *cliContext) {
	enabled := fs.String("enabled", "", "on|off: run the daily internal rotation (unchanged if omitted)")
	retentionDays := fs.Int("retention-days", -1, "delete rotated logs older than N days, 0 = keep forever (unchanged if omitted)")
	keepUncompressed := fs.Int("keep-uncompressed", -1, "newest N rotations stay uncompressed, gzip the rest (unchanged if omitted)")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		cfg := loadLogConfig(s)
		if *enabled != "" {
			on, err := parseBoolArg(*enabled)
			die(err)
			cfg.Enabled = on
		}
		if *retentionDays != -1 {
			cfg.RetentionDays = *retentionDays
		}
		if *keepUncompressed != -1 {
			cfg.KeepUncompressed = *keepUncompressed
		}
		die(saveLogConfig(s, cfg))
		s.Audit("cli", "log_config_change", "")
		output(cfg, func(c controller.LogConfig) { printLogConfigText(c); fmt.Println("saved") })
	}
}

// cmdLogsRotate is what an operator's own cron should call if they've
// disabled the internal ticker — pure path-based copytruncate, correct
// whether or not `ovcp serve` is currently running.
func cmdLogsRotate(ctx *cliContext) {
	s := ctx.openStore()
	defer s.Close()
	die(controller.RotateLogs(logPaths(ctx.dataDir), loadLogConfig(s)))
	s.Audit("cli", "log_rotate", "")
	output(msg("rotated"), printMsg)
}

func cmdLogsStatus(ctx *cliContext) {
	s := ctx.openStore()
	defer s.Close()
	cfg := loadLogConfig(s)
	var rows []controller.LogSourceStatus
	for _, src := range logSources(ctx.dataDir) {
		rows = append(rows, controller.LogStatusFor(src.name, src.path))
	}
	output(rows, func(rows []controller.LogSourceStatus) { printLogStatusText(rows, cfg) })
}

// runLogRotateTicker rotates the 3 flat logs once a day, gated by
// log_config.Enabled so `logs config -enabled=off` genuinely turns it off.
func runLogRotateTicker(s *store.Store, dataDir string, stop <-chan struct{}) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			cfg := loadLogConfig(s)
			if !cfg.Enabled {
				continue
			}
			if err := controller.RotateLogs(logPaths(dataDir), cfg); err != nil {
				slog.Warn("log rotation failed", "err", err)
			}
		}
	}
}

func printLogStatusText(rows []controller.LogSourceStatus, cfg controller.LogConfig) {
	for _, r := range rows {
		age := "no rotations yet"
		if !r.Oldest.IsZero() {
			age = fmt.Sprintf("oldest %s, newest %s", r.Oldest.Format(time.RFC3339), r.Newest.Format(time.RFC3339))
		}
		fmt.Printf("%-8s %8d bytes  %d generations  %s\n", r.Name, r.CurrentSize, r.Generations, age)
	}
	fmt.Printf("rotation: %s (retention %dd, keep %d uncompressed)\n", boolText(cfg.Enabled), cfg.RetentionDays, cfg.KeepUncompressed)
}
