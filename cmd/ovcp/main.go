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
	"runtime"
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
	// dnsmasq chdir()s before reading --hostsdir: paths handed on must be absolute.
	if abs, err := filepath.Abs(*dataDir); err == nil {
		*dataDir = abs
	}
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
			dropRoot(*dataDir)
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

	ovVersion, ovPath, _ := controller.OpenVPNVersion() // both "" if not found — advisory only
	sup := newSupervisor(dataDir, ovPath)
	dnsVersion, dnsPath, _ := controller.DnsmasqVersion() // same advisory-only treatment
	nftVersion, nftPath, _ := controller.NftablesVersion()
	upstreamsEnabled := upstream.Enabled(nftPath)
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
		DNS:              dnsSup,
		PollInterval:     time.Duration(statusInterval()) * time.Second,
	}

	die(preflight(dataDir))
	// render server.conf from persisted settings (paths are controller-owned)
	cfg := srv.LoadConfig()
	fillPaths(&cfg, dataDir, sock)
	perCNActive := upstreamsEnabled && api.UpstreamAuthActive(s)
	cfg.ManagementClientAuth = perCNActive
	die(srv.SaveConfig(cfg))
	die(cfg.WriteAtomic(srv.ConfigPath))
	srv.ReconcileUpstreams() // same path every other upstream-mutating op uses; no-ops if disabled
	// Always wired: inert unless management-client-auth is actually in the
	// running server.conf — a later first PerCN assign then only needs
	// `vpn restart`, not a full serve restart, to pick it up.
	mgmt.OnClientEstablished = srv.OnClientEstablished
	mgmt.OnClientDisconnect = srv.OnClientDisconnect
	sup.OnExit = srv.OnVPNExit

	// unlike DefaultRemote, this CN is a one-time snapshot: EnsureAdminTLS
	// only re-runs on the next serve restart.
	crt, key, err := api.EnsureAdminTLS(filepath.Join(dataDir, "admin-tls"), remoteCN())
	die(err)
	// ErrorLog: routes net/http's own logging (panics, TLS errors) through slog too, not bare stderr.
	hs := &http.Server{Handler: srv.Handler(), ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError)}
	// IP_FREEBIND lets us bind the VPN-side address (e.g. 10.8.0.1) before
	// the tunnel interface exists — the kernel already solves this, no retry loop needed.
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
	ctl, err := controller.ServeControl(ctrl, controller.ControlDeps{
		VPN: sup, DNS: dnsSup, Mgmt: mgmt, Level: logLevel, Telegram: tg,
		UpstreamRewrite: srv.RewriteConnectedClientRule,
		UpstreamReapply: func() error {
			srv.ReconcileUpstreams()
			if upstreamsEnabled && api.UpstreamAuthActive(s) {
				return mgmt.ConnectRetry(mgmt.Timeout)
			}
			return nil
		},
	})
	die(err)
	defer ctl.Close()
	// AUTOSTART only gates the boot-time call below; `ovcp vpn|dns start`
	// (CLI or web UI) always works regardless, for both workers alike.
	if w := controller.RoutingPrereqsWarning(upstreamsEnabled); w != "" {
		slog.Warn(w)
	}
	if os.Getenv("OVCP_OPENVPN_AUTOSTART") != "false" {
		if err := sup.Start(); err != nil {
			slog.Warn("openvpn start", "err", err)
		}
	}
	if perCNActive {
		// Not fatal: openvpn stays holding until this succeeds, refusing
		// every client rather than admitting any ungoverned — samplerTick's
		// own passive Connect() keeps retrying, self-healing without a restart.
		if err := mgmt.ConnectRetry(mgmt.Timeout); err != nil {
			slog.Error("mgmt connect (per-CN routing): openvpn will refuse all clients until this recovers", "err", err)
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

// buildDnsmasqArgs assembles dnsmasq's argv. --hostsdir auto-reloads on
// change; --bind-dynamic tolerates serverIP not existing yet; --log-facility=-
// logs to stderr (Supervisor's inherited fd) instead of dnsmasq opening LogPath itself.
// --user=root keeps dnsmasq in ovcp's identity (it only switches users as root).
func buildDnsmasqArgs(serverIP net.IP, dnsDir string, blockInternet bool) []string {
	args := []string{
		"-k",
		"--user=root",
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
			return buildDnsmasqArgs(ip, pp.DNSDir, api.LoadDNSConfig(s).BlockInternet)
		},
		LogPath: pp.DnsmasqLog,
	}
}

// dropCaps is all ovcp keeps of root: tun and nft, and dnsmasq's port 53.
var dropCaps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE}

// dropRoot re-runs a root invocation as $OVCP_USER (default ovcp) in place,
// holding only the dropCaps it was given; openvpn, dnsmasq and nft inherit
// them. OVCP_USER=root stays root.
func dropRoot(dataDir string) {
	name := cmp.Or(os.Getenv("OVCP_USER"), "ovcp")
	if os.Geteuid() != 0 || name == "root" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		die(fmt.Errorf("%w: create that system account, or set OVCP_USER=root", err))
	}
	uid, err := strconv.Atoi(u.Uid)
	die(err)
	gid, err := strconv.Atoi(u.Gid)
	die(err)
	for _, d := range []string{dataDir, filepath.Dir(ctrlSock()), filepath.Dir(mgmtSock())} {
		die(mkdirOwned(d, uid, gid))
	}
	exe, err := os.Executable()
	die(err)

	runtime.LockOSThread() // capabilities are per thread: set them here, exec from here
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var c [2]unix.CapUserData
	die(unix.Capget(&hdr, &c[0]))
	var keep uint32
	for _, cp := range dropCaps {
		keep |= c[0].Permitted & (1 << cp)
	}
	die(unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0))
	die(syscall.Setgroups(nil))
	die(syscall.Setgid(gid))
	die(syscall.Setuid(uid))
	c = [2]unix.CapUserData{{Effective: keep, Permitted: keep, Inheritable: keep}}
	die(unix.Capset(&hdr, &c[0]))
	for _, cp := range dropCaps {
		if keep&(1<<cp) != 0 {
			die(unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, cp, 0, 0))
		}
	}
	die(fmt.Errorf("exec %s as %s: %w", exe, name, syscall.Exec(exe, os.Args, os.Environ())))
}

// mkdirOwned creates dir for uid:gid; an existing dir is left as it is. The
// chown goes through the new dir's own fd, so nothing done to the path in
// the meantime can redirect it.
func mkdirOwned(dir string, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	switch err := unix.Mkdirat(int(parent.Fd()), filepath.Base(dir), 0o700); err {
	case nil:
	case unix.EEXIST:
		return nil
	default:
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(dir), unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchown(fd, uid, gid)
}

// refreshCertsHostsCLI regenerates certs.hosts after a CLI-side cert change
// (issue, revoke, include, exclude) — no running api.Server to do it via, so
// this builds a bare one to reuse RefreshCertsHosts. Callers reach it via ctx.openStore() first, skeleton already exists.
func refreshCertsHostsCLI(dataDir string, s *store.Store) {
	live, _ := controller.Clients(ctrlSock())
	pp := dataPaths(dataDir)
	srv := &api.Server{Store: s, CertsHostsPath: pp.CertsHosts,
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

// ensureSkeleton creates/repairs the tree, all 0700 and private to ovcp's
// account. Idempotent; every command touching the data dir reaches it via
// cliContext.openStore.
func ensureSkeleton(dataDir string) error {
	pp := dataPaths(dataDir)
	for _, d := range []string{dataDir, pp.PKIDir, pp.LogsDir, pp.DNSDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil { // MkdirAll no-ops the mode on an existing dir
			return err
		}
	}
	for _, f := range []string{pp.CertsHosts, pp.CustomHosts} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
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
