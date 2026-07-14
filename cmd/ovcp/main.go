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
	"path/filepath"
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
	"github.com/ovcp/ovcp/web"
)

var version = "dev"

// logLevel backs the default logger; "ovcp debug on|off" flips it at
// runtime via the control socket, no restart needed.
var logLevel = new(slog.LevelVar)

// ANSI color codes, the one place any of them is spelled out as a number —
// both the log-level colorizer below and commands.go's paint() build on
// these instead of repeating "31"/"32"/etc.
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

// noColor is the single on/off switch for every ANSI escape ovcp ever
// writes — log level tags and the `-json`-adjacent table commands alike.
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

// logJSON switches slog's default handler to JSON lines, for log
// shippers/parsers. Set from -log-json in main; also makes logWriter skip
// colorStderr, whose "level=X" byte-matching doesn't exist in JSON output.
var logJSON bool

func logWriter() io.Writer {
	if logJSON || !colorOK(os.Stderr) {
		return os.Stderr
	}
	return colorStderr{}
}

// newLogHandler is the one place that picks slog's wire format, reused by
// main's initial logger and runServe's tee-to-file reconfigure.
func newLogHandler(w io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{Level: logLevel}
	if logJSON {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// cliContext bundles the runtime dependencies command bodies need. Built
// once in main(), after flag.Parse, and passed explicitly rather than
// closed over, so the commands table itself (name/usage/sub/run) stays a
// plain package-level var usable before Parse runs (flag.Usage needs it
// during Parse, for -h).
type cliContext struct {
	dataDir   string
	p         *pki.PKI
	openStore func() *store.Store
}

func main() {
	flag.Usage = func() { fmt.Fprintln(os.Stderr, helpText()) }
	dataDir := flag.String("data", cmp.Or(os.Getenv("OVCP_DATA"), "/var/lib/ovcp"), "data directory")
	noColorFlag := flag.Bool("no-color", false, "disable ANSI colors (also: $NO_COLOR)")
	logJSONFlag := flag.Bool("log-json", false, "emit logs as JSON lines instead of text (for log shippers)")
	flag.Parse()
	noColor = noColor || *noColorFlag
	logJSON = *logJSONFlag
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

	ctx := &cliContext{dataDir: *dataDir, p: pki.New(filepath.Join(*dataDir, "pki"))}
	ctx.openStore = func() *store.Store {
		s, err := store.Open(filepath.Join(ctx.dataDir, "ovcp.db"))
		die(err)
		return s
	}

	for _, c := range commands {
		if c.name == args[0] {
			fs := newFlags(c.name)
			body := c.run(fs) // registers flags on fs
			fs.Parse(args[1:])
			body(ctx)
			return
		}
	}
	usage()
}

func runServe(dataDir, listen, sock string, p *pki.PKI) {
	pp := dataPaths(dataDir)
	// tee ovcp's own log to a file (alongside stderr/journal) so the UI can
	// tail it; unbounded growth, same as openvpn.log — no rotation here either.
	os.MkdirAll(pp.LogsDir, 0o750)
	if lf, err := os.OpenFile(pp.OvcpLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		slog.SetDefault(slog.New(newLogHandler(io.MultiWriter(logWriter(), lf))))
	}
	if os.Geteuid() != 0 {
		slog.Warn("not root; ovcp owns the PKI and starts openvpn, both need root")
	}
	s, err := store.Open(filepath.Join(dataDir, "ovcp.db"))
	die(err)
	defer s.Close()

	sup := newSupervisor(dataDir)
	srv := &api.Server{
		Store: s, Auth: auth.NewService(s), PKI: p,
		Mgmt:       controller.NewClient(sock),
		VPN:        sup,
		DataDir:    dataDir,
		ConfigPath: pp.ServerConf,
		TLSCrypt:   pp.TLSCrypt,
		ServerCert: pp.ServerCert,
		ServerKey:  pp.ServerKey,
		UI:         web.Dist(),
		DebugLevel: logLevel,
		Version:    version,
	}
	srv.DefaultRemote = adminCertCN(dataDir)

	die(preflight(dataDir))
	// render server.conf from persisted settings (paths are controller-owned)
	cfg := srv.LoadConfig()
	fillPaths(&cfg, dataDir, sock)
	raw, _ := json.Marshal(cfg)
	die(s.SetSetting("server_config", string(raw)))
	die(cfg.WriteAtomic(srv.ConfigPath))

	crt, key, err := api.EnsureAdminTLS(filepath.Join(dataDir, "admin-tls"), adminCertCN(dataDir))
	die(err)
	hs := &http.Server{Handler: srv.Handler()}
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

	// bring the worker up as a reaped foreground child, and expose the
	// control socket so `ovcp vpn <op>` can drive it while we run.
	ctl, err := controller.ServeControl(ctrlSock(), sup, logLevel)
	die(err)
	defer ctl.Close()
	if err := sup.Start(); err != nil {
		slog.Warn("openvpn start", "err", err)
	}
	slog.Info("ovcp started", "version", version, "listen", listen)

	// periodic connected-clients/traffic snapshot for the Stats tab; runs
	// independently of the UI's own poll so history exists with no browser open.
	statsStop := make(chan struct{})
	go srv.RunStatsSampler(statsStop)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(statsStop)
	ctl.Close()
	if err := sup.Stop(); err != nil {
		slog.Warn("openvpn stop", "err", err)
	}
	hs.Close()
}

// ctrlSock is the serve control socket path (CLI ↔ serve for vpn ops).
func ctrlSock() string {
	return cmp.Or(os.Getenv("OVCP_CTRL_SOCK"), "/run/ovcp/control.sock")
}

// mgmtSock is the openvpn management socket path (CLI/serve ↔ openvpn).
func mgmtSock() string {
	return cmp.Or(os.Getenv("OVCP_MGMT_SOCK"), "/run/ovcp/mgmt.sock")
}

// newSupervisor wires the single openvpn worker controller from data paths.
func newSupervisor(dataDir string) *controller.Supervisor {
	pp := dataPaths(dataDir)
	return &controller.Supervisor{
		ConfigPath: pp.ServerConf,
		LogPath:    pp.OpenVPNLog,
	}
}

type paths struct {
	CACert, ServerCert, ServerKey, CRL, TLSCrypt, ServerConf string
	LogsDir, OpenVPNLog, OvcpLog, StatusLog                  string
}

func dataPaths(dataDir string) paths {
	pd := filepath.Join(dataDir, "pki")
	ld := filepath.Join(dataDir, "logs")
	return paths{
		CACert: filepath.Join(pd, "ca.crt"), ServerCert: filepath.Join(pd, "server.crt"),
		ServerKey: filepath.Join(pd, "server.key"), CRL: filepath.Join(pd, "crl.pem"),
		TLSCrypt:   filepath.Join(pd, "tls-crypt.key"),
		ServerConf: filepath.Join(dataDir, "server.conf"),
		LogsDir:    ld,
		OpenVPNLog: filepath.Join(ld, "openvpn.log"),
		OvcpLog:    filepath.Join(ld, "ovcp.log"),
		StatusLog:  filepath.Join(ld, "status.log"),
	}
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

// certFrom is the store row for a freshly issued cert — every issue path here writes this same shape.
func certFrom(ic *pki.IssuedCert, kind string) store.Cert {
	return store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: kind,
		CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter}
}

// writeServerCert persists a freshly issued server cert+key to the paths
// `serve` reads and records it in the store. Shared by init (first issue)
// and renew-server (reissue in place); takes effect on the next `vpn restart`.
func writeServerCert(pp paths, s *store.Store, ic *pki.IssuedCert) error {
	if err := os.WriteFile(pp.ServerCert, ic.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(pp.ServerKey, ic.KeyPEM, 0o600); err != nil {
		return err
	}
	return s.ReplaceCert(certFrom(ic, "server"))
}

// fillPaths sets the server-owned path fields on a config.
func fillPaths(cfg *ovpnconf.Config, dataDir, sock string) {
	pp := dataPaths(dataDir)
	cfg.CACert, cfg.ServerCert, cfg.ServerKey = pp.CACert, pp.ServerCert, pp.ServerKey
	cfg.CRL, cfg.TLSCrypt = pp.CRL, pp.TLSCrypt
	cfg.MgmtSocket = sock
	cfg.StatusLog = pp.StatusLog
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

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// usage: no args or unknown command — same text as -h, but exit 2.
func usage() {
	flag.Usage()
	os.Exit(2)
}
