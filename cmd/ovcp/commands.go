package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"rsc.io/qr"

	"github.com/ovcp/ovcp/internal/api"
	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/backup"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/telegram"
)

// command is one ovcp subcommand: its help text, its fixed set of
// subcommands/ops (if any, for `usage: ovcp X a|b|c` errors and shell
// completion), and run — which registers the command's flags on fs (no
// side effects) and returns the closure that actually executes once fs is
// parsed. Splitting registration from execution lets completion ask "what
// flags does this command have" by calling run(fs) and reading fs back via
// VisitAll, without duplicating the flag list or running anything.
//
// commands is the single source of truth for the CLI surface — dispatch in
// main(), the -h text (helpText), and `ovcp __complete` (completeArgs) all
// read this same table, so adding/renaming a command or a flag means
// editing it in exactly one place.
type command struct {
	name  string
	usage string
	sub   []string
	run   func(fs *flag.FlagSet) func(ctx *cliContext)
}

// flagNames registers c's flags on a throwaway FlagSet (same code path as
// real parsing, just never Parse'd or executed) and reads the names back.
func (c command) flagNames() []string {
	fs := newFlags(c.name)
	c.run(fs)
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, "-"+f.Name) })
	return names
}

// opArg validates fs's first positional argument against ops (the
// "usage: ovcp NAME op1|op2|..." error every op-dispatched command shares)
// and returns it along with everything after it, for the caller to parse
// with its own FlagSet. Op-dispatched commands must never register flags
// on fs itself: main()'s dispatch loop calls fs.Parse before the op is even
// known, and flag.Parse stops scanning at the first non-flag token — a flag
// placed after the op (ovcp NAME op -flag value, the usual shell-command
// order) would silently never be parsed otherwise.
func opArg(fs *flag.FlagSet, name string, ops []string) (op string, rest []string) {
	args := fs.Args()
	if len(args) < 1 || !slices.Contains(ops, args[0]) {
		die(fmt.Errorf("usage: ovcp %s %s", name, strings.Join(ops, "|")))
	}
	return args[0], args[1:]
}

var (
	vpnOps      = []string{"start", "stop", "restart", "reconnect", "status"}
	userOps     = []string{"add", "list", "del", "disable", "enable", "passwd", "totp"}
	backupOps   = []string{"create", "restore"}
	debugOps    = []string{"on", "off"}
	telegramOps = []string{"token", "start", "stop", "restart", "status"}
)

var commands = []command{
	{name: "init", usage: "-server-cn HOST [-admin NAME]   one-shot setup: CA, server cert, tls-crypt, config, admin user", run: cmdInit},
	{name: "issue", usage: "-cn NAME [-kind client|server] [-days N] [-out PREFIX] [-key-pass PW]", run: cmdIssue},
	{name: "revoke", usage: "-serial HEX   revoke + regenerate CRL", run: cmdRevoke},
	{name: "rotate-ca", usage: "re-encrypt the CA key under a new passphrase", run: cmdRotateCA},
	{name: "renew-server", usage: "[-days N] [-server-cn CN]   reissue the openvpn server cert (needs vpn restart)", run: cmdRenewServer},
	{name: "custom-opts", usage: "edit raw server.conf directives in $EDITOR (fallback vi)", run: cmdCustomOpts},
	{name: "backup", usage: "create [-out FILE] | restore [-force] FILE   encrypted export/import: CA, CRL, tls-crypt, config, database", sub: backupOps, run: cmdBackup},
	{name: "list", usage: "[-status all|active|revoked] [-kind all|client|server] [-sort cn|kind|expiry|serial] [-desc]   list certificates", run: cmdList},
	{name: "export", usage: "-cn NAME [-remote HOST] [-port N] [-proto udp|tcp] [-server-cn CN] [-out PREFIX] [-key-pass PW] [-split-tunnel] [-custom-opts OPTS|-]", run: cmdExport},
	{name: "status", usage: "VPN process + connected clients", run: cmdStatus},
	{name: "stats", usage: "[-cn NAME] [-follow] [-interval N]   traffic history, or a live top-like follow view (-follow ignores -json)", run: cmdStats},
	{name: "kill", usage: "-cn NAME   disconnect client", run: cmdKill},
	{name: "vpn", usage: "start|stop|restart|reconnect|status   manage/inspect the openvpn worker", sub: vpnOps, run: cmdVPN},
	{name: "debug", usage: "on|off   toggle verbose logging on a running serve (no restart)", sub: debugOps, run: cmdDebug},
	{name: "telegram", usage: "token -admin ID|@user | start|stop|restart|status   notify+control bot", sub: telegramOps, run: cmdTelegram},
	{name: "user", usage: "add|list|del|disable|enable|passwd|totp[-off]", sub: userOps, run: cmdUser},
	{name: "audit", usage: "last 50 audit entries", run: cmdAudit},
	{name: "serve", usage: "[-listen ADDR] [-mgmt PATH] [-ctrl PATH]   run admin UI + API", run: cmdServe},
	{name: "version", usage: "print version", run: cmdVersion},
	{name: "completion", usage: "bash|zsh|fish   print a shell completion script", sub: []string{"bash", "zsh", "fish"}, run: cmdCompletion},
}

// helpText renders the commands table as the -h/usage screen.
func helpText() string {
	var b strings.Builder
	b.WriteString("ovcp <command>\n")
	tw := tabwriter.NewWriter(&b, 0, 4, 3, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.usage)
	}
	tw.Flush()
	b.WriteString("\n-data DIR overrides $OVCP_DATA (default /var/lib/ovcp); must come before\n")
	b.WriteString("the command, e.g. ovcp -data /tmp/ovcp init ...\n")
	b.WriteString("-no-color disables ANSI colors; -debug turns on debug-level logging.\n")
	b.WriteString("-json switches every command to JSON output (JSON log lines for serve);\n")
	b.WriteString("all three go before the command, e.g. ovcp -json list.\n")
	b.WriteString("Full guide: ovcp(8).")
	return b.String()
}

type versionOut struct {
	Version        string `json:"version"`
	OpenVPNVersion string `json:"openvpnVersion,omitempty"`
	OpenVPNPath    string `json:"openvpnPath,omitempty"`
}

func cmdVersion(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		out := versionOut{Version: version}
		if v, p, ok := controller.OpenVPNVersion(); ok {
			out.OpenVPNVersion, out.OpenVPNPath = v, p
		}
		output(out, func(o versionOut) {
			fmt.Println("ovcp", o.Version)
			if o.OpenVPNVersion == "" {
				fmt.Println("openvpn: not found on PATH")
			} else {
				fmt.Printf("openvpn %s (%s)\n", o.OpenVPNVersion, o.OpenVPNPath)
			}
		})
	}
}

func cmdIssue(fs *flag.FlagSet) func(ctx *cliContext) {
	cn := fs.String("cn", "", "common name (required)")
	kindS := fs.String("kind", "client", "client|server")
	days := fs.Int("days", 365, "validity (days)")
	out := fs.String("out", "", "write key+cert to files with this prefix (server certs)")
	keyPass := fs.String("key-pass", "", "encrypt private key with this password (client certs)")
	return func(ctx *cliContext) {
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		requirePositive(*days, "days")
		kind := pki.KindClient
		if *kindS == "server" {
			kind = pki.KindServer
		}
		if kind == pki.KindServer && *keyPass != "" {
			die(fmt.Errorf("-key-pass is client-only: an encrypted server key can't be unlocked non-interactively when openvpn starts"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := issueCert(ctx.p, kind, *cn, *days, pass, *keyPass)
		die(err)
		s := ctx.openStore()
		defer s.Close()
		die(s.AddCert(store.CertFrom(ic, *kindS)))
		s.Audit("cli", "issue", fmt.Sprintf("cn=%s kind=%s serial=%s", *cn, *kindS, ic.SerialHex))
		o := issueOut{Serial: ic.SerialHex}
		if *out != "" {
			die(os.WriteFile(*out+".crt", ic.CertPEM, 0o644))
			die(os.WriteFile(*out+".key", ic.KeyPEM, 0o600))
			o.CertFile, o.KeyFile = *out+".crt", *out+".key"
		} else {
			o.CertPEM, o.KeyPEM = string(ic.CertPEM), string(ic.KeyPEM)
		}
		output(o, func(o issueOut) {
			if o.CertFile != "" {
				fmt.Println("wrote", o.CertFile, o.KeyFile)
			} else {
				fmt.Print(o.CertPEM, o.KeyPEM)
			}
			fmt.Fprintln(os.Stderr, "serial:", o.Serial)
		})
	}
}

// issueOut is `issue -json`'s shape: the PEM bytes inline (no -out), or the
// paths they were written to instead.
type issueOut struct {
	Serial   string `json:"serial"`
	CertPEM  string `json:"cert,omitempty"`
	KeyPEM   string `json:"key,omitempty"`
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

func cmdRevoke(fs *flag.FlagSet) func(ctx *cliContext) {
	serial := fs.String("serial", "", "serial (hex, required)")
	return func(ctx *cliContext) {
		if *serial == "" {
			die(fmt.Errorf("-serial required"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		s := ctx.openStore()
		defer s.Close()
		die(s.Revoke(*serial, time.Now()))
		rev, err := s.RevokedCerts()
		die(err)
		entries := make([]pki.RevokedEntry, len(rev))
		for i, c := range rev {
			entries[i] = pki.RevokedEntry{SerialHex: c.Serial, RevokedAt: *c.RevokedAt}
		}
		die(ctx.p.RegenCRL(entries, pass))
		s.Audit("cli", "revoke", "serial="+*serial)
		output(revokeOut{*serial, ctx.p.CRLPath()}, func(o revokeOut) {
			fmt.Println("revoked; CRL regenerated:", o.CRLPath)
		})
	}
}

type revokeOut struct {
	Serial  string `json:"serial"`
	CRLPath string `json:"crlPath"`
}

// paint wraps s in ANSI color code (e.g. ansiGreen) unless colors are off;
// one function so every command colors output the same way.
func paint(code, s string) string {
	if !colorOK(os.Stdout) {
		return s
	}
	return ansi(code, s)
}

func red(s string) string    { return paint(ansiRed, s) }
func green(s string) string  { return paint(ansiGreen, s) }
func yellow(s string) string { return paint(ansiYellow, s) }

// output is the one place every command's JSON branch lives: JSON-encode
// rows, or hand them to the command's own text renderer. Reads the global
// -json flag directly — no command declares its own copy.
func output[T any](rows T, text func(T)) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		die(enc.Encode(rows))
		return
	}
	text(rows)
}

// outcome is the generic {"message":"..."} JSON shape for commands whose
// only output is a confirmation line. Commands with real structured data
// (certOut, statusOut, ControlResult, ...) keep their own richer type.
type outcome struct {
	Message string `json:"message"`
}

func msg(format string, a ...any) outcome { return outcome{fmt.Sprintf(format, a...)} }

// printMsg is outcome's default text renderer — msg(...) + output() with no
// custom formatting, the common case.
func printMsg(o outcome) { fmt.Println(o.Message) }

// progress prints a human-progress line, suppressed under -json so
// multi-step commands (init, backup) don't interleave prose with the
// single JSON object output() prints at the end.
func progress(format string, a ...any) {
	if !jsonOut {
		fmt.Printf(format, a...)
	}
}

// sortByFlag sorts rows in place by the named field (string-keyed getters,
// so time fields sort correctly too via RFC3339's lexicographic order).
// An empty key is a no-op ("no -sort = today's order"); an unrecognized one
// is an error, not a silent no-op — a typo'd flag must never look like
// "sort worked, this just happens to be the natural order."
func sortByFlag[T any](rows []T, getters map[string]func(T) string, key string, desc bool) error {
	if key == "" {
		return nil
	}
	get, ok := getters[key]
	if !ok {
		keys := make([]string, 0, len(getters))
		for k := range getters {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return fmt.Errorf("-sort must be one of: %s", strings.Join(keys, "|"))
	}
	slices.SortFunc(rows, func(a, b T) int {
		c := strings.Compare(get(a), get(b))
		if desc {
			c = -c
		}
		return c
	})
	return nil
}

var certSortGetters = map[string]func(store.Cert) string{
	"cn":     func(c store.Cert) string { return c.CN },
	"kind":   func(c store.Cert) string { return c.Kind },
	"expiry": func(c store.Cert) string { return c.NotAfter.Format(time.RFC3339) },
	"serial": func(c store.Cert) string { return c.Serial },
}

var userSortGetters = map[string]func(store.User) string{
	"username": func(u store.User) string { return u.Username },
	"role":     func(u store.User) string { return u.Role },
	"created":  func(u store.User) string { return u.CreatedAt.Format(time.RFC3339) },
}

// certStatus classifies a cert for both the text and -json list output.
func certStatus(c store.Cert) string {
	switch {
	case c.RevokedAt != nil:
		return "REVOKED"
	case time.Now().After(c.NotAfter):
		return "expired"
	case time.Until(c.NotAfter) <= store.ExpiryWarnDays*24*time.Hour:
		return "expiring"
	default:
		return "valid"
	}
}

// certOut is what `list -json` prints: the fields a script wants, none of
// the raw PEM bytes store.Cert also carries.
type certOut struct {
	Status   string    `json:"status"`
	Kind     string    `json:"kind"`
	CN       string    `json:"cn"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"expires"`
}

func cmdList(fs *flag.FlagSet) func(ctx *cliContext) {
	status := fs.String("status", "all", "all|active|revoked")
	kind := fs.String("kind", "all", "all|client|server")
	sortBy := fs.String("sort", "", "cn|kind|expiry|serial (default: issued order)")
	desc := fs.Bool("desc", false, "reverse sort order")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		certs, err := s.ListCerts()
		die(err)
		var out []store.Cert
		for _, c := range certs {
			if *status == "active" && c.RevokedAt != nil {
				continue
			}
			if *status == "revoked" && c.RevokedAt == nil {
				continue
			}
			if *kind != "all" && c.Kind != *kind {
				continue
			}
			out = append(out, c)
		}
		die(sortByFlag(out, certSortGetters, *sortBy, *desc))
		rows := []certOut{}
		for _, c := range out {
			rows = append(rows, certOut{certStatus(c), c.Kind, c.CN, c.Serial, c.NotAfter})
		}
		output(rows, func(rows []certOut) {
			for _, c := range rows {
				st := fmt.Sprintf("%-8s", c.Status) // pad first: color codes must not count toward width
				switch c.Status {
				case "REVOKED", "expired":
					st = red(st)
				case "expiring":
					st = yellow(st)
				case "valid":
					st = green(st)
				}
				fmt.Printf("%s %-10s %-24s expires %s  %s\n",
					st, c.Kind, c.CN, c.NotAfter.Format("2006-01-02"), c.Serial)
			}
		})
	}
}

func cmdExport(fs *flag.FlagSet) func(ctx *cliContext) {
	cn := fs.String("cn", "", "client CN (issues fresh cert, required)")
	remote := fs.String("remote", "", "server host clients connect to (default: OVCP_SERVER_CN / server cert CN)")
	port := fs.Int("port", 0, "server port (default: the configured server port)")
	proto := fs.String("proto", "", "udp|tcp (default: the configured server proto)")
	serverCN := fs.String("server-cn", "", "verify-x509-name value")
	out := fs.String("out", "", "write bundle to this file with .ovpn appended (prefix, like issue)")
	keyPass := fs.String("key-pass", "", "encrypt embedded private key with this password")
	splitTunnel := fs.Bool("split-tunnel", false, "keep the client's own default route (needs server redirect on)")
	customOpts := fs.String("custom-opts", "", "custom client directives: comma-separated, a file via $(cat FILE), or - for $EDITOR")
	return func(ctx *cliContext) {
		if *remote == "" {
			*remote = adminCertCN(ctx.dataDir)
		}
		if *serverCN == "" {
			*serverCN = adminCertCN(ctx.dataDir)
		}
		if *cn == "" || *remote == "" {
			die(fmt.Errorf("-cn required; -remote required (no server CN found)"))
		}
		s := ctx.openStore()
		defer s.Close()
		raw, _ := s.GetSetting("server_config")
		cfg := ovpnconf.Load(raw)
		if *port != 0 {
			cfg.Port = *port
		}
		if *proto != "" {
			cfg.Proto = *proto
		}
		if *splitTunnel && !cfg.CanSplitTunnel() {
			die(ovpnconf.ErrNoRedirect)
		}
		var extra string
		switch *customOpts {
		case "":
		case "-":
			extra = editText("")
		default:
			extra = commaOrLines(*customOpts)
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := issueCert(ctx.p, pki.KindClient, *cn, 365, pass, *keyPass)
		die(err)
		die(s.AddCert(store.CertFrom(ic, "client")))
		s.Audit("cli", "issue", "cn="+*cn+" (export)")
		caPEM, err := ctx.p.CACertPEM()
		die(err)
		tc, err := loadOrCreateTLSCrypt(filepath.Join(ctx.dataDir, "pki", "tls-crypt.key"))
		die(err)
		bundle, err := pki.RenderOVPN(pki.BundleParams{
			Remote: *remote, Port: cfg.Port, Proto: cfg.Proto, ServerCN: *serverCN,
			CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
			TLSCrypt: tc, Cipher: cfg.Cipher, SplitTunnel: *splitTunnel, Extra: extra,
		})
		die(err)
		o := exportOut{Serial: ic.SerialHex}
		if *out != "" {
			die(os.WriteFile(*out+".ovpn", bundle, 0o644))
			o.File = *out + ".ovpn"
		} else {
			o.Bundle = string(bundle)
		}
		output(o, func(o exportOut) {
			if o.File != "" {
				fmt.Println("wrote", o.File)
			} else {
				fmt.Print(o.Bundle)
			}
			fmt.Fprintln(os.Stderr, "serial:", o.Serial)
		})
	}
}

// exportOut is `export -json`'s shape: the .ovpn bundle inline (no -out),
// or the path it was written to instead.
type exportOut struct {
	Serial string `json:"serial"`
	Bundle string `json:"bundle,omitempty"`
	File   string `json:"file,omitempty"`
}

func cmdInit(fs *flag.FlagSet) func(ctx *cliContext) {
	caCN := fs.String("ca-cn", "OVCP CA", "CA common name")
	serverCN := fs.String("server-cn", "", "server cert CN / public hostname (required)")
	years := fs.Int("ca-years", 10, "CA validity")
	days := fs.Int("server-days", 825, "server cert validity (days)")
	admin := fs.String("admin", "admin", "initial admin username ('' to skip)")
	mgmt := fs.String("mgmt", mgmtSock(), "mgmt socket")
	return func(ctx *cliContext) {
		if *serverCN == "" {
			die(fmt.Errorf("-server-cn required (public hostname clients connect to)"))
		}
		requirePositive(*years, "ca-years")
		requirePositive(*days, "server-days")
		pp := dataPaths(ctx.dataDir)
		s := ctx.openStore()
		defer s.Close()

		out := initOut{CACert: pp.CACert, ServerCert: pp.ServerCert, TLSCrypt: pp.TLSCrypt, ServerConf: pp.ServerConf,
			AdminUIURL: "https://" + cmp.Or(os.Getenv("OVCP_LISTEN"), "127.0.0.1:8443")}

		// 1) CA
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", true)
		switch err := ctx.p.InitCA(*caCN, *years, pass); err {
		case nil:
			s.Audit("system", "ca_init", "cn="+*caCN)
			progress("[1/5] CA initialized: %s\n", pp.CACert)
		case pki.ErrCAExists:
			if err := ctx.p.CheckPassphrase(pass); err != nil {
				die(fmt.Errorf("existing CA: %w", err))
			}
			progress("[1/5] CA exists, passphrase ok\n")
		default:
			die(err)
		}

		// 2) server certificate
		if _, err := os.Stat(pp.ServerCert); err == nil {
			progress("[2/5] server cert exists: %s\n", pp.ServerCert)
		} else {
			ic, err := ctx.p.Issue(pki.KindServer, *serverCN, *days, pass)
			die(err)
			die(writeServerCert(pp, s, ic))
			s.Audit("system", "issue", "cn="+*serverCN+" kind=server (init)")
			progress("[2/5] server cert issued: %s\n", pp.ServerCert)
		}

		// 3) tls-crypt
		_, err := loadOrCreateTLSCrypt(pp.TLSCrypt)
		die(err)
		progress("[3/5] tls-crypt key: %s\n", pp.TLSCrypt)

		// 4) server.conf from defaults
		cfg := ovpnconf.Default()
		fillPaths(&cfg, ctx.dataDir, *mgmt)
		raw, _ := json.Marshal(cfg)
		die(s.SetSetting("server_config", string(raw)))
		die(cfg.WriteAtomic(pp.ServerConf))
		progress("[4/5] server config: %s\n", pp.ServerConf)

		// 5) admin user
		if *admin != "" {
			out.Admin = *admin
			if _, err := s.GetUser(*admin); err == nil {
				progress("[5/5] admin user exists: %s\n", *admin)
			} else {
				// context for readSecret's otherwise-ambiguous "Password:" prompt —
				// only when a prompt is actually about to happen (no env override).
				if os.Getenv("OVCP_USER_PASSWORD") == "" {
					fmt.Fprintf(os.Stderr, "create admin user %q\n", *admin)
				}
				pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
				h, err := auth.HashPassword(pw)
				die(err)
				_, err = s.AddUser(*admin, h, "admin")
				die(err)
				s.Audit("system", "user_add", "name="+*admin+" role=admin (init)")
				progress("[5/5] admin user created: %s\n", *admin)
			}
		} else {
			progress("[5/5] admin user skipped\n")
		}
		output(out, func(o initOut) {
			fmt.Println("\ndone. start the server:  ovcp serve")
			fmt.Println("admin UI:               ", o.AdminUIURL)
		})
	}
}

// initOut is `init -json`'s shape: the artifact paths init produced, and
// where to reach the admin UI. The per-step [N/5] lines are progress prose,
// suppressed under -json (see progress()) — this is the one result.
type initOut struct {
	CACert     string `json:"caCert"`
	ServerCert string `json:"serverCert"`
	TLSCrypt   string `json:"tlsCrypt"`
	ServerConf string `json:"serverConf"`
	Admin      string `json:"admin,omitempty"`
	AdminUIURL string `json:"adminUIURL"`
}

func cmdServe(fs *flag.FlagSet) func(ctx *cliContext) {
	listen := fs.String("listen", cmp.Or(os.Getenv("OVCP_LISTEN"), "127.0.0.1:8443"), "admin UI listen addr(s), comma-separated")
	mgmt := fs.String("mgmt", mgmtSock(), "mgmt socket")
	ctrl := fs.String("ctrl", ctrlSock(), "serve control socket")
	return func(ctx *cliContext) {
		runServe(ctx.dataDir, *listen, *mgmt, *ctrl, ctx.p)
	}
}

// statusOut is what `status -json` prints: process state + connected
// clients in one object, since scripts want both without screen-scraping.
type statusOut struct {
	Running    bool                   `json:"running"`
	Pid        int                    `json:"pid,omitempty"`
	Uptime     string                 `json:"uptime,omitempty"`     // openvpn child, empty if not running
	OvcpUptime string                 `json:"ovcpUptime,omitempty"` // serve process, empty if unreachable
	Error      string                 `json:"error,omitempty"`
	Clients    []controller.VPNClient `json:"clients"`
}

// fmtUptime renders a Go duration string ("3h2m1s"), or "" for the zero
// time (not running / not known) — stdlib formatting is plenty for a
// status line, no need for a custom "3h 2m" pretty-printer.
func fmtUptime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return time.Since(t).Round(time.Second).String()
}

// printStatusText renders the one statusOut a status run ends up with,
// whichever of the unknown/stopped/unavailable/running states it hit.
func printStatusText(st statusOut) {
	switch {
	case st.Error != "" && !st.Running:
		fmt.Println("OpenVPN: unknown —", st.Error)
	case !st.Running:
		fmt.Println(red("OpenVPN: stopped"))
	case st.Error != "":
		fmt.Printf("OpenVPN: running (pid %d, up %s)\n", st.Pid, st.Uptime)
		fmt.Println("Clients: unavailable —", st.Error)
	default:
		fmt.Println(green(fmt.Sprintf("OpenVPN: running (pid %d, up %s)", st.Pid, st.Uptime)))
		fmt.Printf("Clients: %d connected\n", len(st.Clients))
		for _, c := range st.Clients {
			fmt.Printf("  %-20s %-22s %-12s rx %d tx %d since %s\n",
				c.CN, c.RealAddress, c.VirtualAddress, c.BytesRecv, c.BytesSent,
				c.ConnectedSince.Format(time.RFC3339))
		}
	}
	if st.OvcpUptime != "" {
		fmt.Println("ovcp: up", st.OvcpUptime)
	}
}

func cmdStatus(fs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := fs.String("ctrl", ctrlSock(), "serve control socket")
	return func(ctx *cliContext) {
		st := statusOut{Clients: []controller.VPNClient{}}
		// process line first (from serve); if serve/openvpn is down, there
		// are no clients to list, so stop here.
		r, err := controller.Control(*ctrl, "status")
		switch {
		case err != nil:
			st.Error = err.Error()
		case r.Pid == 0:
			// running=false, no clients: nothing more to check, but serve
			// answered so it's up even with the tunnel down
			st.OvcpUptime = fmtUptime(r.ServeStartedAt)
		default:
			st.Running, st.Pid = true, r.Pid
			st.Uptime = fmtUptime(r.StartedAt)
			st.OvcpUptime = fmtUptime(r.ServeStartedAt)
			// via serve's control socket, not a second dial to openvpn's own
			// mgmt socket — openvpn only ever serves one connected mgmt
			// client, and serve (still running, just proven above) already
			// holds that slot for its whole life.
			if cl, err := controller.Clients(*ctrl); err != nil {
				st.Error = err.Error()
			} else {
				st.Clients = cl
			}
		}
		output(st, printStatusText)
	}
}

func cmdKill(fs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := fs.String("ctrl", ctrlSock(), "serve control socket")
	cn := fs.String("cn", "", "client CN (required)")
	return func(ctx *cliContext) {
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		die(controller.Kill(*ctrl, *cn))
		s := ctx.openStore()
		defer s.Close()
		s.Audit("cli", "kill", "cn="+*cn)
		output(msg("killed %s", *cn), printMsg)
	}
}

func cmdVPN(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "vpn", vpnOps)
		ofs := newFlags("vpn " + op)
		ctrl := ofs.String("ctrl", ctrlSock(), "serve control socket")
		ofs.Parse(rest)
		r, err := controller.Control(*ctrl, op)
		die(err)
		if op != "status" { // status is read-only, don't audit
			s := ctx.openStore()
			s.Audit("cli", "vpn_"+op, fmt.Sprintf("pid=%d", r.Pid))
			s.Close()
		}
		output(r, func(r controller.ControlResult) { printVPNText(op, r) })
	}
}

// printVPNText renders vpn's ControlResult per op — the human phrasing each
// op already had, now driven off the same struct -json emits.
func printVPNText(op string, r controller.ControlResult) {
	switch {
	case op == "status" && r.Pid == 0:
		fmt.Println("vpn stopped")
	case op == "status":
		fmt.Printf("vpn running (pid %d)\n", r.Pid)
	case op == "start" && !r.Changed:
		fmt.Printf("vpn already started (pid %d)\n", r.Pid)
	case op == "start":
		fmt.Printf("vpn started (pid %d)\n", r.Pid)
	case op == "stop" && !r.Changed:
		fmt.Println("vpn already stopped")
	case op == "stop":
		fmt.Println("vpn stopped")
	case op == "restart":
		fmt.Printf("vpn restarted (pid %d)\n", r.Pid)
	case op == "reconnect":
		fmt.Printf("vpn reconnect sent (pid %d)\n", r.Pid)
	}
}

func cmdRenewServer(fs *flag.FlagSet) func(ctx *cliContext) {
	days := fs.Int("days", 825, "validity (days)")
	serverCNFlag := fs.String("server-cn", "", "server CN (default: current server cert's CN / OVCP_SERVER_CN)")
	return func(ctx *cliContext) {
		requirePositive(*days, "days")
		serverCN := *serverCNFlag
		if serverCN == "" {
			serverCN = adminCertCN(ctx.dataDir)
		}
		if serverCN == "" {
			die(fmt.Errorf("no server certificate found; pass -server-cn (e.g. right after a backup restore) or run ovcp init first"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := ctx.p.Issue(pki.KindServer, serverCN, *days, pass)
		die(err)
		s := ctx.openStore()
		defer s.Close()
		die(writeServerCert(dataPaths(ctx.dataDir), s, ic))
		s.Audit("cli", "renew_server", "cn="+serverCN+" serial="+ic.SerialHex)
		output(renewOut{serverCN, ic.SerialHex}, func(o renewOut) {
			fmt.Println("server cert renewed:", o.Serial)
			fmt.Println("run `ovcp vpn restart` to apply")
		})
	}
}

type renewOut struct {
	ServerCN string `json:"serverCN"`
	Serial   string `json:"serial"`
}

// commaOrLines: comma list → one directive per line; no-op without a comma,
// so $(cat FILE) passes through unchanged.
// ponytail: assumes no directive needs a literal comma — openvpn's own
// syntax never does. Use -custom-opts - (editor) if one ever does.
func commaOrLines(s string) string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.Join(parts, "\n")
}

// editText opens initial in $EDITOR (fallback vi) and returns what was saved
// — same idiom as `git commit`/`crontab -e`.
func editText(initial string) string {
	tmp := filepath.Join(os.TempDir(), "ovcp-edit.conf")
	die(os.WriteFile(tmp, []byte(initial), 0o600))
	defer os.Remove(tmp)
	editor := cmp.Or(os.Getenv("EDITOR"), "vi")
	cmd := exec.Command(editor, tmp)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	die(cmd.Run())
	out, err := os.ReadFile(tmp)
	die(err)
	return string(out)
}

// cmdCustomOpts edits the server config's raw extra directives in $EDITOR.
func cmdCustomOpts(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		raw, _ := s.GetSetting("server_config")
		cfg := ovpnconf.Load(raw)
		cfg.Extra = editText(cfg.Extra)
		enc, _ := json.Marshal(cfg)
		die(s.SetSetting("server_config", string(enc)))
		die(cfg.WriteAtomic(dataPaths(ctx.dataDir).ServerConf))
		s.Audit("cli", "config_change", "custom options")
		output(msg("saved; run `ovcp vpn restart` to apply"), printMsg)
	}
}

func cmdRotateCA(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		oldPass := readSecret("Current CA passphrase", "OVCP_CA_PASSPHRASE", false)
		newPass := readSecret("New CA passphrase", "OVCP_CA_NEW_PASSPHRASE", true)
		die(ctx.p.Rotate(oldPass, newPass))
		s := ctx.openStore()
		defer s.Close()
		s.Audit("cli", "ca_rotate", "")
		output(msg("CA passphrase rotated"), printMsg)
	}
}

// cmdBackup and cmdUser take no top-level flags: opArg's rest is fed to a
// fresh FlagSet per op, same as vpn/debug/telegram.
func cmdBackup(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "backup", backupOps)
		switch op {
		case "create":
			cfs := newFlags("backup create")
			out := cfs.String("out", "", "output file (default: ovcp-backup-<timestamp>.ovcpbak)")
			cfs.Parse(rest)
			if *out == "" {
				*out = "ovcp-backup-" + time.Now().Format("20060102-150405") + ".ovcpbak"
			}
			pass := readSecret("Backup passphrase", "OVCP_BACKUP_PASSPHRASE", true)
			s := ctx.openStore()
			defer s.Close()
			f, err := os.Create(*out)
			die(err)
			defer f.Close()
			die(backup.Create(ctx.dataDir, s, f, pass))
			s.Audit("cli", "backup_create", "file="+*out)
			output(backupCreateOut{*out}, func(o backupCreateOut) {
				fmt.Println("backup written:", o.File)
				fmt.Println("keep the passphrase safe: it cannot be recovered, and the archive is unreadable without it")
			})

		case "restore":
			rfs := newFlags("backup restore")
			force := rfs.Bool("force", false, "overwrite an already-initialized data directory")
			rfs.Parse(rest)
			file := rfs.Arg(0)
			if file == "" {
				die(fmt.Errorf("usage: ovcp backup restore [-force] FILE"))
			}
			pass := readSecret("Backup passphrase", "OVCP_BACKUP_PASSPHRASE", false)
			f, err := os.Open(file)
			die(err)
			defer f.Close()
			die(backup.Restore(ctx.dataDir, f, pass, *force))
			output(msg("restored CA, CRL, tls-crypt key, config, and database into %s; "+
				"next: OVCP_SERVER_CN=<host> ovcp renew-server, then ovcp vpn start", ctx.dataDir),
				func(o outcome) {
					fmt.Println("[1/2] restored CA, CRL, tls-crypt key, config, and database into", ctx.dataDir)
					fmt.Println("[2/2] next: OVCP_SERVER_CN=<host> ovcp renew-server   (issues the openvpn server cert)")
					fmt.Println("      then: ovcp vpn start")
				})
		}
	}
}

type backupCreateOut struct {
	File string `json:"file"`
}

func cmdDebug(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "debug", debugOps)
		ofs := newFlags("debug " + op)
		ctrl := ofs.String("ctrl", ctrlSock(), "serve control socket")
		ofs.Parse(rest)
		_, err := controller.Control(*ctrl, "debug "+op)
		die(err)
		output(map[string]bool{"debug": op == "on"}, func(o map[string]bool) {
			fmt.Println("debug logging", op)
		})
	}
}

func cmdTelegram(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "telegram", telegramOps)

		if op == "token" {
			tfs := newFlags("telegram token")
			admin := tfs.String("admin", os.Getenv("OVCP_TELEGRAM_ADMIN"),
				"admin Telegram numeric id or @username (required; env: OVCP_TELEGRAM_ADMIN)")
			tfs.Parse(rest)
			if *admin == "" {
				die(fmt.Errorf("-admin required (the only Telegram identity the bot will ever respond to)"))
			}
			token := readSecret("Telegram bot token", "OVCP_TELEGRAM_TOKEN", false)
			s := ctx.openStore()
			defer s.Close()
			die(telegram.SetCredentials(s, string(token), *admin))
			s.Audit("cli", "telegram_configure", "admin="+*admin)
			output(msg("telegram: token saved, admin set to %s", *admin), func(o outcome) {
				fmt.Println(o.Message)
				fmt.Println("run 'ovcp telegram start' (or restart serve) to bring the bot up")
			})
			return
		}

		ofs := newFlags("telegram " + op)
		ctrl := ofs.String("ctrl", ctrlSock(), "serve control socket")
		ofs.Parse(rest)

		var st controller.TelegramStatus
		var err error
		switch op {
		case "start":
			st, err = controller.TelegramStart(*ctrl)
		case "stop":
			st, err = controller.TelegramStop(*ctrl)
		case "restart":
			st, err = controller.TelegramRestart(*ctrl)
		case "status":
			st, err = controller.TelegramGetStatus(*ctrl)
		}
		die(err)
		if op != "status" {
			s := ctx.openStore()
			s.Audit("cli", "telegram_"+op, fmt.Sprintf("running=%t", st.Running))
			s.Close()
		}
		output(st, func(st controller.TelegramStatus) {
			if !st.TokenSet {
				fmt.Println("telegram: not configured (run 'ovcp telegram token -admin ...')")
				return
			}
			state := "stopped"
			if st.Running {
				state = "running"
			}
			fmt.Printf("telegram: %s, admin %s\n", state, st.Admin)
		})
	}
}

func cmdUser(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "user", userOps)
		s := ctx.openStore()
		defer s.Close()
		switch op {
		case "add":
			afs := newFlags("user add")
			name := afs.String("name", "", "username (required)")
			role := afs.String("role", "operator", "admin|operator|readonly")
			afs.Parse(rest)
			if *name == "" || !auth.ValidRole(*role) {
				die(fmt.Errorf("-name required; role admin|operator|readonly"))
			}
			pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
			h, err := auth.HashPassword(pw)
			die(err)
			_, err = s.AddUser(*name, h, *role)
			die(err)
			s.Audit("cli", "user_add", "name="+*name+" role="+*role)
			output(userAddOut{*name, *role}, func(o userAddOut) {
				fmt.Println("user added:", o.Username, "("+o.Role+")")
			})

		case "list":
			lfs := newFlags("user list")
			sortBy := lfs.String("sort", "", "username|role|created (default: today's order)")
			desc := lfs.Bool("desc", false, "reverse sort order")
			lfs.Parse(rest)
			users, err := s.ListUsers()
			die(err)
			die(sortByFlag(users, userSortGetters, *sortBy, *desc))
			rows := []api.UserSummary{}
			for _, u := range users {
				rows = append(rows, api.NewUserSummary(u))
			}
			output(rows, func(rows []api.UserSummary) {
				for _, u := range rows {
					st := fmt.Sprintf("%-8s", "enabled")
					if u.Disabled {
						st = red(fmt.Sprintf("%-8s", "DISABLED"))
					} else {
						st = green(st)
					}
					tf := "-"
					if u.TOTP {
						tf = "2fa"
					}
					fmt.Printf("%-20s %-9s %s %s\n", u.Username, u.Role, st, tf)
				}
			})

		case "del":
			dfs := newFlags("user del")
			name := dfs.String("name", "", "username (required)")
			dfs.Parse(rest)
			if *name == "" {
				die(fmt.Errorf("-name required"))
			}
			die(s.DeleteUser(*name))
			s.Audit("cli", "user_del", "name="+*name)
			output(msg("deleted: %s", *name), printMsg)

		case "disable", "enable":
			efs := newFlags("user " + op)
			name := efs.String("name", "", "username (required)")
			efs.Parse(rest)
			if *name == "" {
				die(fmt.Errorf("-name required"))
			}
			die(s.SetUserDisabled(*name, op == "disable"))
			s.Audit("cli", "user_"+op, "name="+*name)
			output(userDisabledOut{*name, op == "disable"}, func(o userDisabledOut) {
				fmt.Println(op+"d:", o.Username)
			})

		case "passwd":
			pfs := newFlags("user passwd")
			name := pfs.String("name", "", "username (required)")
			pfs.Parse(rest)
			if *name == "" {
				die(fmt.Errorf("-name required"))
			}
			pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
			h, err := auth.HashPassword(pw)
			die(err)
			die(s.SetUserPassword(*name, h))
			s.Audit("cli", "user_passwd", "name="+*name)
			output(msg("password updated: %s", *name), printMsg)

		case "totp":
			tfs := newFlags("user totp")
			name := tfs.String("name", "", "username (required)")
			off := tfs.Bool("off", false, "disable 2FA")
			tfs.Parse(rest)
			if *name == "" {
				die(fmt.Errorf("-name required"))
			}
			if *off {
				die(s.SetUserTOTP(*name, ""))
				s.Audit("cli", "user_totp_off", "name="+*name)
				output(msg("2FA disabled: %s", *name), printMsg)
				break
			}
			sec, err := auth.TOTPGenerateSecret()
			die(err)
			die(s.SetUserTOTP(*name, sec))
			s.Audit("cli", "user_totp_enroll", "name="+*name)
			url := auth.TOTPProvisioningURL(sec, *name, adminCertCN(ctx.dataDir))
			output(totpOut{sec, url}, func(o totpOut) {
				printQR(o.URL)
				fmt.Println("scan with your authenticator, or enter manually:")
				fmt.Println("  secret:", o.Secret)
				fmt.Println("  url:   ", o.URL)
			})
		}
	}
}

type userAddOut struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type userDisabledOut struct {
	Username string `json:"username"`
	Disabled bool   `json:"disabled"`
}

type totpOut struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

func cmdAudit(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		tail, err := s.AuditTail(50)
		die(err)
		slices.Reverse(tail) // newest first, in both output modes
		output(tail, func(tail []store.AuditEntry) {
			for _, e := range tail {
				fmt.Printf("%s %-12s %-16s %s\n", e.TS.Format(time.RFC3339), e.Actor, e.Action, e.Detail)
			}
		})
	}
}

func cmdCompletion(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		if jsonOut {
			die(fmt.Errorf("-json is not supported for completion (already a script, not data)"))
		}
		script, err := completionScript(fs.Arg(0))
		die(err)
		fmt.Print(script)
	}
}

// readSecret prompts for a secret (env override for automation); both paths
// enforce the same length rule, or init could accept what issue rejects later.
func readSecret(label, env string, confirm bool) []byte {
	v := []byte(os.Getenv(env))
	if len(v) == 0 {
		prompt := func(p string) []byte {
			fmt.Fprint(os.Stderr, p+": ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			die(err)
			return b
		}
		v = prompt(label)
		if confirm && string(v) != string(prompt("Confirm")) {
			die(fmt.Errorf("mismatch"))
		}
	}
	if !auth.SecretLenOK(string(v)) {
		die(fmt.Errorf("%s", auth.SecretLenErr(label)))
	}
	return v
}

// printQR renders a QR code as terminal background-color blocks (the one
// thing qrterminal added over rsc.io/qr itself — not worth a dependency).
// Ignores -no-color/$NO_COLOR: these blocks are the QR code, not decoration.
func printQR(text string) {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return
	}
	black, white := ansi("40", "  "), ansi("47", "  ")
	fmt.Println(strings.Repeat(white, code.Size+2))
	for y := 0; y <= code.Size; y++ {
		fmt.Print(white)
		for x := 0; x <= code.Size; x++ {
			if code.Black(x, y) {
				fmt.Print(black)
			} else {
				fmt.Print(white)
			}
		}
		fmt.Println()
	}
}
