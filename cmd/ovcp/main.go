// ovcp — OpenVPN Control Panel. One static binary.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"os/signal"
	"syscall"

	"github.com/ovcp/ovcp/internal/api"
	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/telegram"
	"github.com/ovcp/ovcp/internal/upstream"
	"github.com/ovcp/ovcp/web"
)

var version = "dev"

// buildTarget is the Makefile TARGET/Containerfile arch-libc this binary was
// built for ("host" for native). Set via -X main.buildTarget=...; never guessed at runtime.
var buildTarget = "host"

// logLevel backs the default logger; "ovcp debug on|off" flips it at
// runtime via the control socket, no restart needed.
var logLevel = new(slog.LevelVar)

// ANSI color codes, the one place any of them is spelled out as a number;
// the log-level colorizer below and commands.go's paint() both build on these.
const (
	ansiCyan   = "36"
	ansiGreen  = "32"
	ansiYellow = "33"
	ansiRed    = "31"
)

// ansi wraps s in color code (e.g. ansiGreen); caller decides whether color
// is wanted (see colorOK) — this is just the escape-sequence primitive.
func ansi(code, s string) string { return "\x1b[" + code + "m" + s + "\x1b[0m" }

var logLevelColor = map[string]string{
	"level=DEBUG": ansi(ansiCyan, "level=DEBUG"),
	"level=INFO":  ansi(ansiGreen, "level=INFO"),
	"level=WARN":  ansi(ansiYellow, "level=WARN"),
	"level=ERROR": ansi(ansiRed, "level=ERROR"),
}

// noColor is the single on/off switch for every ANSI escape ovcp ever writes.
// Set from $NO_COLOR or -no-color in main, before anything prints.
var noColor = os.Getenv("NO_COLOR") != ""

// colorOK reports whether f may receive ANSI escapes: colors aren't off and
// f is an actual terminal, not a pipe/file/journal.
func colorOK(f *os.File) bool {
	return !noColor && term.IsTerminal(int(f.Fd()))
}

// colorStderr colorizes slog.TextHandler's "level=X" token by wrapping stderr.
type colorStderr struct{}

func (colorStderr) Write(p []byte) (int, error) {
	out := p
	for tag, colored := range logLevelColor {
		if i := bytes.Index(p, []byte(tag)); i >= 0 {
			out = append(append(append([]byte{}, p[:i]...), colored...), p[i+len(tag):]...)
			break
		}
	}
	_, err := os.Stderr.Write(out)
	return len(p), err
}

// jsonOut is ovcp's one output-format switch (slog's wire format for
// `serve`, output()'s JSON branch elsewhere). $OVCP_JSON seeds it; -json can still turn it on.
var jsonOut = os.Getenv("OVCP_JSON") != ""

func logWriter() io.Writer {
	if jsonOut || !colorOK(os.Stderr) {
		return os.Stderr
	}
	return colorStderr{}
}

// newLogHandler is the one place that picks slog's wire format, reused by
// main's initial logger and runServe's tee-to-file reconfigure.
func newLogHandler(w io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{Level: logLevel}
	if jsonOut {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// cliContext bundles the runtime dependencies command bodies need. Built
// once in main() after flag.Parse and passed explicitly (not closed over),
// so commands stays a plain package-level var usable before Parse runs (flag.Usage needs it during Parse, for -h).
type cliContext struct {
	dataDir string
	p       *pki.PKI
}

// openStore is the one gateway every stateful command passes through — the
// one place ensureSkeleton needs to be called from.
func (ctx *cliContext) openStore() *store.Store {
	die(ensureSkeleton(ctx.dataDir))
	s, err := store.Open(filepath.Join(ctx.dataDir, "ovcp.db"))
	die(err)
	// CLI-triggered audits (ca_rotate has no API path at all) still need to
	// reach Telegram — Notify() is a bare outbound call, safe here unlike
	// slog logging, which stays daemon-only to keep -json/automation stderr clean.
	s.OnAudit(telegram.New(s, ctx.p, nil, nil, nil).OnAudit)
	return s
}

// globalFlags registers ovcp's flags that precede the command name — used by
// both main's real parsing and completeArgs's throwaway FlagSet, so the two can't drift.
func globalFlags(fs *flag.FlagSet) (dataDir *string, noColor, jsonOut, debug *bool) {
	dataDir = fs.String("data", cmp.Or(os.Getenv("OVCP_DATA"), "/var/lib/ovcp"), "data directory")
	noColor = fs.Bool("no-color", false, "disable ANSI colors (also: $NO_COLOR)")
	jsonOut = fs.Bool("json", false, "JSON output: command results, or log lines for serve (also: $OVCP_JSON)")
	debug = fs.Bool("debug", false, "debug-level logging for this invocation")
	return
}

func main() {
	flag.Usage = func() { fmt.Fprintln(os.Stderr, helpText()) }
	dataDir, noColorFlag, jsonOutFlag, debugFlag := globalFlags(flag.CommandLine)
	flag.Parse()
	noColor = noColor || *noColorFlag
	jsonOut = jsonOut || *jsonOutFlag
	if *debugFlag {
		logLevel.Set(slog.LevelDebug)
	}
	slog.SetDefault(slog.New(newLogHandler(logWriter())))
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}

	// hidden: shell completion stubs call this, not humans. Kept out of the
	// commands table so it never shows up in -h or its own completion.
	if args[0] == "__complete" {
		fmt.Println(strings.Join(completeArgs(args[1:]), "\n"))
		return
	}

	ctx := &cliContext{dataDir: *dataDir, p: pki.New(dataPaths(*dataDir).PKIDir)}

	for _, c := range commands {
		if c.name == args[0] || c.alias == args[0] {
			fs := newFlags(c.name)
			// sub-op flags (user/backup/telegram) live on FlagSets created inside
			// the closure, so they don't exist yet for -h's default printer to find.
			fs.Usage = func() {
				if c.sub != nil {
					fmt.Fprintln(os.Stderr, opsUsage(c.name, c.sub, c.subDesc))
					return
				}
				fmt.Fprintf(os.Stderr, "usage: ovcp %s %s\n", c.name, c.desc)
				fs.PrintDefaults()
			}
			body := c.run(fs) // registers flags on fs
			fs.Parse(args[1:])
			body(ctx)
			return
		}
	}
	usage()
}

func runServe(dataDir, listen, sock, ctrl string, p *pki.PKI, s *store.Store) {
	pp := dataPaths(dataDir)
	// tee ovcp's own log to a file (alongside stderr/journal) so the UI can
	// tail it; unbounded growth, same as openvpn.log — no rotation here either.
	if lf, err := os.OpenFile(pp.OvcpLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		slog.SetDefault(slog.New(newLogHandler(io.MultiWriter(logWriter(), lf))))
	}
	if os.Geteuid() != 0 {
		slog.Warn("not root; ovcp owns the PKI and starts openvpn, both need root")
	}

	ovVersion, ovPath, _ := controller.OpenVPNVersion() // both "" if not found — advisory only
	sup := newSupervisor(dataDir, ovPath)
	dnsVersion, dnsPath, _ := controller.DnsmasqVersion() // same advisory-only treatment
	dnsGid := dnsGID(dnsRunAsGroup())
	nftVersion, nftPath, _ := controller.NftablesVersion()
	upstreamsEnabled := nftPath != "" && os.Getenv("OVCP_UPSTREAMS_ENABLED") != "false"
	dnsSup := newDNSSupervisor(pp, dnsPath, s)
	mgmt := controller.NewClient(sock, statusPath(sock))
	tg := telegram.New(s, p, sup, dnsSup, mgmt)
	// audits fire for CLI commands too, but only the running daemon owns
	// ovcp.log/Telegram — logging/notifying there would just hit a bare CLI's stderr.
	s.OnAudit(func(actor, action, detail string) {
		slog.Info("audit", "actor", actor, "action", action, "detail", detail)
		tg.OnAudit(actor, action, detail)
	})
	sup.OnCrashLoopGiveUp = func(streak int) {
		tg.Notify(fmt.Sprintf("⚠️ openvpn crash-looping (%dx), giving up auto-restart", streak))
	}
	dnsSup.OnCrashLoopGiveUp = func(streak int) {
		tg.Notify(fmt.Sprintf("⚠️ dnsmasq crash-looping (%dx), giving up auto-restart", streak))
	}
	// shared by DefaultRemote and EnsureAdminTLS below — one definition, no cached copy.
	remoteCN := func() string { return adminCertCN(dataDir) }
	srv := &api.Server{
		Store: s, Auth: auth.NewService(s), PKI: p,
		Mgmt:             mgmt,
		VPN:              sup,
		Telegram:         tg,
		DataDir:          dataDir,
		ConfigPath:       pp.ServerConf,
		TLSCrypt:         pp.TLSCrypt,
		ServerCert:       pp.ServerCert,
		ServerKey:        pp.ServerKey,
		DefaultRemote:    remoteCN,
		UI:               web.Dist(),
		DebugLevel:       logLevel,
		Version:          version,
		BuildTarget:      buildTarget,
		OpenVPNVersion:   ovVersion,
		OpenVPNPath:      ovPath,
		DnsmasqVersion:   dnsVersion,
		DnsmasqPath:      dnsPath,
		UpstreamsEnabled: upstreamsEnabled,
		NftVersion:       nftVersion,
		NftPath:          nftPath,
		CertsHostsPath:   pp.CertsHosts,
		CustomHostsPath:  pp.CustomHosts,
		DNSGroupGID:      dnsGid,
		DNS:              dnsSup,
		PollInterval:     time.Duration(statusInterval()) * time.Second,
	}

	die(preflight(dataDir))
	// render server.conf from persisted settings (paths are controller-owned)
	cfg := srv.LoadConfig()
	fillPaths(&cfg, dataDir, sock)
	raw, _ := json.Marshal(cfg)
	die(s.SetSetting("vpn_config", string(raw)))
	die(cfg.WriteAtomic(srv.ConfigPath))
	if upstreamsEnabled {
		if err := upstream.Apply(api.LoadUpstreamConfig(s), cfg.Subnet); err != nil {
			slog.Warn("upstream apply", "err", err)
		}
	}

	// unlike DefaultRemote, this CN is a one-time snapshot: EnsureAdminTLS
	// only re-runs on the next serve restart.
	crt, key, err := api.EnsureAdminTLS(filepath.Join(dataDir, "admin-tls"), remoteCN())
	die(err)
	// ErrorLog: routes net/http's own logging (panics, TLS errors) through slog too, not bare stderr.
	hs := &http.Server{Handler: srv.Handler(), ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError)}
	// IP_FREEBIND lets us bind the VPN-side address (e.g. 10.8.0.1) before
	// tun0 exists — the kernel already solves this, no retry loop needed.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, unix.IP_FREEBIND, 1)
		})
	}}
	for _, addr := range strings.Split(listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		die(err)
		go func(a string, l net.Listener) {
			if err := hs.ServeTLS(l, crt, key); err != http.ErrServerClosed {
				die(err)
			}
		}(addr, ln)
	}

	// bring the worker up as a reaped foreground child, and expose the control
	// socket so vpn/status/kill/stats -follow can drive/query us — see ServeControl.
	ctl, err := controller.ServeControl(ctrl, sup, dnsSup, mgmt, logLevel, tg)
	die(err)
	defer ctl.Close()
	// AUTOSTART only gates the boot-time call below; `ovcp vpn|dns start`
	// (CLI or web UI) always works regardless, for both workers alike.
	if os.Getenv("OVCP_OPENVPN_AUTOSTART") != "false" {
		if err := sup.Start(); err != nil {
			slog.Warn("openvpn start", "err", err)
		}
	}
	if os.Getenv("OVCP_DNSMASQ_AUTOSTART") != "false" {
		if err := dnsSup.Start(); err != nil {
			slog.Warn("dnsmasq start", "err", err)
		}
	}
	if tg.Status().TokenSet {
		if err := tg.Start(); err != nil {
			slog.Warn("telegram start", "err", err)
		}
	}
	slog.Info("ovcp started", "version", version, "listen", listen)

	// periodic connected-clients poll: refreshes certs.hosts (Records tab)
	// every tick and samples traffic history (Stats tab) every 12th tick —
	// runs independently of the UI's own poll so both exist with no browser open.
	samplerStop := make(chan struct{})
	go srv.RunSampler(samplerStop)
	expiryStop := make(chan struct{})
	go runExpirySweepTicker(s, p, tg, expiryStop)
	logRotateStop := make(chan struct{})
	go runLogRotateTicker(s, dataDir, logRotateStop)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(samplerStop)
	close(expiryStop)
	close(logRotateStop)
	tg.Stop()
	ctl.Close()
	if err := sup.Stop(); err != nil {
		slog.Warn("openvpn stop", "err", err)
	}
	if err := dnsSup.Stop(); err != nil {
		slog.Warn("dnsmasq stop", "err", err)
	}
	if upstreamsEnabled {
		if err := upstream.Teardown(); err != nil {
			slog.Warn("upstream teardown", "err", err)
		}
	}
	hs.Close()
	slog.Info("ovcp stopped", "uptime", time.Since(controller.ProcessStartedAt).Round(time.Second))
}

// sockPath resolves a unix socket path: env var override, else the default —
// the one place either socket's env-var-vs-default precedence is decided.
func sockPath(env, def string) string { return cmp.Or(os.Getenv(env), def) }

// ctrlSock is the serve control socket path (CLI ↔ serve for vpn ops).
func ctrlSock() string { return sockPath("OVCP_CTRL_SOCK", "/run/ovcp/control.sock") }

// mgmtSock is the openvpn management socket path (CLI/serve ↔ openvpn).
func mgmtSock() string { return sockPath("OVCP_MGMT_SOCK", "/run/ovcp/mgmt.sock") }

// ctrlFlag/mgmtFlag register the -ctrl/-mgmt flags every command shares —
// CLI flag > env var > hardcoded path, decided once instead of at every
// call site. note appends command-specific help text (e.g. stats' "-follow only").
func ctrlFlag(fs *flag.FlagSet, note string) *string {
	return fs.String("ctrl", ctrlSock(), "serve control socket"+note)
}

func mgmtFlag(fs *flag.FlagSet) *string {
	return fs.String("mgmt", mgmtSock(), "mgmt socket")
}

// newSupervisor wires the single openvpn worker controller from data paths.
// bin is the resolved openvpn path (from controller.OpenVPNVersion, so the
// PATH lookup happens exactly once); empty means "not found on PATH".
func newSupervisor(dataDir, bin string) *controller.Supervisor {
	pp := dataPaths(dataDir)
	return &controller.Supervisor{
		Name:    "openvpn",
		Bin:     bin,
		Args:    []string{"--config", pp.ServerConf},
		LogPath: pp.OpenVPNLog,
	}
}

// dnsRunAsUser/dnsRunAsGroup: dnsmasq's own drop-to account, independently
// configurable from openvpn's (OVCP_OPENVPN_USER/GROUP) — same shape,
// same defaults, but its own knob, not silently shared.
func dnsRunAsUser() string  { return cmp.Or(os.Getenv("OVCP_DNSMASQ_USER"), "nobody") }
func dnsRunAsGroup() string { return cmp.Or(os.Getenv("OVCP_DNSMASQ_GROUP"), "nogroup") }

// buildDnsmasqArgs assembles dnsmasq's argv. --hostsdir auto-reloads on
// change; --bind-dynamic tolerates serverIP not existing yet; --log-facility=-
// logs to stderr (Supervisor's inherited fd) instead of dnsmasq opening LogPath itself.
func buildDnsmasqArgs(user, group string, serverIP net.IP, dnsDir string, blockInternet bool) []string {
	args := []string{
		"-k",
		"--user=" + user,
		"--group=" + group,
		"--bind-dynamic",
		"--listen-address=" + serverIP.String(),
		"--hostsdir=" + dnsDir,
		"--log-queries",
		"--log-facility=-",
	}
	if blockInternet {
		// --no-resolv alone leaves zero upstreams configured, so dnsmasq treats
		// every non-local query as a config error ("REFUSED (EDE: not ready)");
		// --server=/#/ marks all domains local-only instead, for a clean NXDOMAIN.
		args = append(args, "--no-resolv", "--server=/#/")
	}
	return args
}

// warnMissingInotify logs once if bin's dnsmasq build lacks inotify — a
// hard requirement for --hostsdir to auto-reload without a restart.
func warnMissingInotify(bin string) {
	if bin == "" {
		return
	}
	out, _ := exec.Command(bin, "--version").Output()
	if !strings.Contains(string(out), "inotify") {
		slog.Warn("dnsmasq was built without inotify support; hosts file changes need `ovcp dns restart` to apply")
	}
}

// newDNSSupervisor wires the dnsmasq worker. PreStart recomputes Args from
// the current persisted config on every (re)start, so a Subnet or
// block-internet change never leaves a running dnsmasq stale.
func newDNSSupervisor(pp paths, bin string, s *store.Store) *controller.Supervisor {
	warnMissingInotify(bin)
	return &controller.Supervisor{
		Name: "dnsmasq",
		Bin:  bin,
		PreStart: func() []string {
			raw, _ := s.GetSetting("vpn_config")
			ip, err := ovpnconf.Load(raw).ServerTunIP()
			if err != nil {
				slog.Warn("dnsmasq: server tun IP", "err", err)
				ip = net.IPv4zero
			}
			return buildDnsmasqArgs(dnsRunAsUser(), dnsRunAsGroup(), ip, pp.DNSDir, api.LoadDNSConfig(s).BlockInternet)
		},
		LogPath: pp.DnsmasqLog,
	}
}

// dnsGID resolves dnsmasq's drop-to group to a gid, so the hosts files can
// be chgrp'd to it — group-scoped, tighter than the pki dir's world-traversal
// precedent. -1 (not found) means "leave the file's group alone".
func dnsGID(group string) int {
	g, err := user.LookupGroup(group)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return gid
}

// refreshCertsHostsCLI regenerates certs.hosts after a CLI-side cert change
// (issue, revoke, include, exclude) — no running api.Server to do it via, so
// this builds a bare one to reuse RefreshCertsHosts. Callers reach it via ctx.openStore() first, skeleton already exists.
func refreshCertsHostsCLI(dataDir string, s *store.Store) {
	live, _ := controller.Clients(ctrlSock())
	pp := dataPaths(dataDir)
	gid := dnsGID(dnsRunAsGroup())
	srv := &api.Server{Store: s, CertsHostsPath: pp.CertsHosts, DNSGroupGID: gid,
		DefaultRemote: func() string { return adminCertCN(dataDir) }}
	if err := srv.RefreshCertsHosts(live); err != nil {
		slog.Warn("certs.hosts refresh failed", "err", err)
	}
}

type paths struct {
	PKIDir                                                   string
	CACert, ServerCert, ServerKey, CRL, TLSCrypt, ServerConf string
	LogsDir, OpenVPNLog, OvcpLog, DnsmasqLog                 string
	DNSDir, CertsHosts, CustomHosts                          string
}

func dataPaths(dataDir string) paths {
	pd := filepath.Join(dataDir, "pki")
	ld := filepath.Join(dataDir, "logs")
	dd := filepath.Join(dataDir, "dns")
	return paths{
		PKIDir: pd,
		CACert: filepath.Join(pd, "ca.crt"), ServerCert: filepath.Join(pd, "server.crt"),
		ServerKey: filepath.Join(pd, "server.key"), CRL: filepath.Join(pd, "crl.pem"),
		TLSCrypt:    filepath.Join(pd, "tls-crypt.key"),
		ServerConf:  filepath.Join(dataDir, "server.conf"),
		LogsDir:     ld,
		OpenVPNLog:  filepath.Join(ld, "openvpn.log"),
		OvcpLog:     filepath.Join(ld, "ovcp.log"),
		DnsmasqLog:  filepath.Join(ld, "dnsmasq.log"),
		DNSDir:      dd,
		CertsHosts:  filepath.Join(dd, "certs.hosts"),
		CustomHosts: filepath.Join(dd, "custom.hosts"),
	}
}

// Every $OVCP_DATA permission ovcp sets — ensureSkeleton below is the only place they're applied.
const (
	modeDataDir = 0o751 // root:root — world-traverse only, nothing listable/readable without a file's own grant
	modePKIDir  = 0o701 // root:root — same trick; ca.crt/crl.pem (0644) are the public bits behind it
	modeLogsDir = 0o750 // root:root — no unprivileged process opens into it directly (fds inherited pre-exec)
	modeDNSDir  = 0o750 // root:dnsGID — group-scoped, confidential hosts content, not world-readable
	modeDNSFile = 0o640 // root:dnsGID
)

// ensureSkeleton creates/repairs the whole tree above. Idempotent; called by
// every command that touches the data dir, via cliContext.openStore.
func ensureSkeleton(dataDir string) error {
	pp := dataPaths(dataDir)
	if err := os.MkdirAll(dataDir, modeDataDir); err != nil {
		return err
	}
	if err := os.Chmod(dataDir, modeDataDir); err != nil { // MkdirAll no-ops the mode if dataDir already exists
		return err
	}
	if err := os.MkdirAll(pp.PKIDir, modePKIDir); err != nil {
		return err
	}
	if err := os.MkdirAll(pp.LogsDir, modeLogsDir); err != nil {
		return err
	}
	gid := dnsGID(dnsRunAsGroup())
	if err := os.MkdirAll(pp.DNSDir, modeDNSDir); err != nil {
		return err
	}
	os.Chown(pp.DNSDir, -1, gid)
	for _, f := range []string{pp.CertsHosts, pp.CustomHosts} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			if err := os.WriteFile(f, nil, modeDNSFile); err != nil {
				return err
			}
		}
		os.Chown(f, -1, gid)
	}
	return nil
}

// issueCert issues a cert under the CA, optionally password-protecting the
// key. Shared by the issue and export CLI commands.
func issueCert(p *pki.PKI, kind pki.CertKind, cn string, days int, pass []byte, keyPass string) (*pki.IssuedCert, error) {
	ic, err := p.Issue(kind, cn, days, pass)
	if err != nil {
		return nil, err
	}
	if keyPass != "" {
		if ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, keyPass); err != nil {
			return nil, err
		}
	}
	return ic, nil
}

// writeServerCert persists a freshly issued server cert+key; shared by init
// and `certificate renew` (CLI), takes effect on next `vpn restart`.
// Delegates to api.Server.WriteServerCert via a bare, HTTP-less instance.
func writeServerCert(pp paths, s *store.Store, ic *pki.IssuedCert) error {
	return (&api.Server{ServerCert: pp.ServerCert, ServerKey: pp.ServerKey, Store: s}).WriteServerCert(ic)
}

// fillPaths sets the server-owned path fields on a config.
func fillPaths(cfg *ovpnconf.Config, dataDir, sock string) {
	pp := dataPaths(dataDir)
	cfg.CACert, cfg.ServerCert, cfg.ServerKey = pp.CACert, pp.ServerCert, pp.ServerKey
	cfg.CRL, cfg.TLSCrypt = pp.CRL, pp.TLSCrypt
	cfg.MgmtSocket = sock
	cfg.StatusLog = statusPath(sock)
	cfg.StatusInterval = statusInterval()
	cfg.ServerCN = adminCertCN(dataDir)
}

// statusPath sits beside the mgmt/control sockets in /run/ovcp, not under
// $OVCP_DATA/logs — it's live state rewritten forever, not a log, and
// keeping it out of logs/ keeps it out of any external logrotate glob there.
func statusPath(sock string) string {
	return filepath.Join(filepath.Dir(sock), "status")
}

// statusInterval reads OVCP_STATUS_INTERVAL, clamped to [1,60]; unset,
// unparseable, or out of range falls back to 3 with a warning, never a
// hard failure — a bad env var must not stop ovcp from starting.
func statusInterval() int {
	const def = 3
	v := os.Getenv("OVCP_STATUS_INTERVAL")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 60 {
		slog.Warn("OVCP_STATUS_INTERVAL invalid, using default", "value", v, "default", def)
		return def
	}
	return n
}

// preflight verifies init artifacts exist, with an actionable error.
func preflight(dataDir string) error {
	pp := dataPaths(dataDir)
	var missing []string
	for _, f := range []string{pp.CACert, pp.ServerCert, pp.ServerKey, pp.TLSCrypt} {
		if _, err := os.Stat(f); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not initialized, missing:\n  %s\nrun: ovcp init -server-cn <public-hostname>",
			strings.Join(missing, "\n  "))
	}
	return nil
}

// adminCertCN: OVCP_SERVER_CN env, else the VPN server cert's CN.
func adminCertCN(dataDir string) string {
	if v := os.Getenv("OVCP_SERVER_CN"); v != "" {
		return v
	}
	data, err := os.ReadFile(dataPaths(dataDir).ServerCert)
	if err != nil {
		return ""
	}
	if block, _ := pem.Decode(data); block != nil {
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			return c.Subject.CommonName
		}
	}
	return ""
}

// loadOrCreateTLSCrypt loads the tls-crypt key at path, generating and
// persisting one if it doesn't exist yet.
func loadOrCreateTLSCrypt(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	}
	k, err := pki.GenTLSCryptKey()
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, k, 0o600)
}

// newFlags: every command's FlagSet, named after its dispatch value, so -h
// and unknown flags behave the same everywhere.
func newFlags(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}

// requirePositive dies with an actionable error on a zero/negative validity
// period (silently issues an already-expired cert/CA otherwise).
func requirePositive(n int, flag string) {
	if n <= 0 {
		die(fmt.Errorf("-%s must be positive", flag))
	}
}

// die is the one exit path every command's fatal error routes through,
// matching jsonErr's {"error":..} shape on the web API. Flag-parsing errors
// bypass this, straight from stdlib flag: always plain text on stderr.
func die(err error) {
	if err == nil {
		return
	}
	if jsonOut {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(1)
}

// usage: no args or unknown command — same text as -h, but exit 2.
func usage() {
	flag.Usage()
	os.Exit(2)
}
