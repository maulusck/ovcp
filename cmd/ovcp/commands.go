package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// command is one subcommand: run registers flags on fs, returning the closure executed once parsed.
// commands is the single source of truth dispatch, helpText, and completeArgs all read.
//
// Help is three tiers, each answering only the question it's asked: `ovcp -h`
// lists every command with desc, a few words (tier 1); `ovcp <command> -h` (or
// a missing/bad op) lists sub with subDesc, still a few words each (tier 2);
// `ovcp <command> <op> -h` prints that op's real flags via fs.PrintDefaults()
// (tier 3, already exists — every flag already carries its own description).
type command struct {
	name    string
	alias   string // short form accepted alongside name in dispatch/completion; "" if none
	desc    string
	sub     []string
	subDesc map[string]string
	run     func(fs *flag.FlagSet) func(ctx *cliContext)
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

// opsUsage renders tier 2: "usage: ovcp <name> <op>" plus one line per op
// with its short description (desc[o] == "" prints a bare name, never
// breaks) — shared by a missing/bad op's error and `ovcp <command> -h`, so
// the two can't drift apart into different listings of the same ops.
func opsUsage(name string, ops []string, desc map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: ovcp %s <op>\n", name)
	tw := tabwriter.NewWriter(&b, 0, 4, 3, ' ', 0)
	for _, o := range ops {
		fmt.Fprintf(tw, "  %s\t%s\n", o, desc[o])
	}
	tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// opArgList validates args[0] against ops, returning it plus the rest —
// opArg's shape without needing an already-Parse'd FlagSet, for op-dispatch
// one level deeper (e.g. "logs config get", where "config"'s own opArg
// already split "get" off as plain rest).
func opArgList(name string, ops []string, desc map[string]string, args []string) (op string, rest []string) {
	if len(args) < 1 || !slices.Contains(ops, args[0]) {
		die(fmt.Errorf("%s", opsUsage(name, ops, desc)))
	}
	return args[0], args[1:]
}

// opArg validates fs's first positional arg against ops, returning it plus
// the rest. Op-dispatched commands must never register flags on fs itself:
// main() calls fs.Parse before the op is known, so a flag placed after the op would never be parsed.
func opArg(fs *flag.FlagSet, name string, ops []string, desc map[string]string) (op string, rest []string) {
	return opArgList(name, ops, desc, fs.Args())
}

// configOp is every "<name> config get|set[|preview|edit]" dispatch: same
// wiring reused by vpn/dns/logs/stats/telegram instead of five hand-rolled
// copies. bodies must have one entry per ops.
func configOp(name string, ops []string, desc map[string]string, bodies map[string]func(fs *flag.FlagSet) func(ctx *cliContext)) func(ctx *cliContext, rest []string) {
	return func(ctx *cliContext, rest []string) {
		op, crest := opArgList(name, ops, desc, rest)
		ofs := newFlags(name + " " + op)
		subUsage(ofs, name+" "+op)
		body := bodies[op](ofs)
		ofs.Parse(crest)
		body(ctx)
	}
}

// parseBoolArg: the CLI's shared on/off vocabulary for any boolean setting —
// on|true|1 and off|false|0, case-insensitive.
func parseBoolArg(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "on", "true", "1":
		return true, nil
	case "off", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("want on|off (or true|false, 1|0), got %q", s)
}

// boolText renders a bool for humans as on/off, matching parseBoolArg's own
// vocabulary — status output shouldn't disagree with the "-flag on|off"
// usage string that set it.
func boolText(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

var (
	vpnOps    = []string{"start", "stop", "restart", "reconnect", "status", "kill", "config"}
	vpnOpDesc = map[string]string{
		"start": "bring the tunnel up", "stop": "bring it down",
		"restart": "full stop + fresh start", "reconnect": "SIGUSR1, no restart",
		"status": "pid, uptime", "kill": "disconnect one client (-cn NAME)",
		"config": "get|set|preview server settings",
	}
	vpnConfigOps = []string{"get", "set", "preview"}
	configOpDesc = map[string]string{ // shared by every "<x> config" dispatch below
		"get": "print the persisted config", "set": "change and persist settings",
		"preview": "show a set's diff, unsaved",
	}
	dnsOps    = []string{"start", "stop", "restart", "status", "config"} // no reconnect: dnsmasq has no such signal
	dnsOpDesc = map[string]string{
		"start": "bring dnsmasq up", "stop": "bring it down",
		"restart": "full stop + fresh start", "status": "pid, uptime",
		"config": "get|set dnsmasq settings",
	}
	dnsConfigOps = []string{"get", "set"}
	certOps      = []string{"issue", "list", "revoke", "renew"}
	certOpDesc   = map[string]string{
		"issue": "issue or renew a client cert (-export for a .ovpn)", "list": "list certs, filter/sort",
		"revoke": "revoke a cert, regen CRL", "renew": "renew or rename the server cert",
	}
	caOps    = []string{"rotate", "renew", "status"}
	caOpDesc = map[string]string{
		"status": "CN, expiry, status — read-only",
		"rotate": "re-encrypt the CA key under a new passphrase",
		"renew":  "reissue the CA cert, same key, extended validity",
	}
	recordOps    = []string{"list", "edit", "include", "exclude"}
	recordOpDesc = map[string]string{
		"list": "list internal DNS records", "edit": "$EDITOR for custom.hosts",
		"include": "resolve this CN while connected (-cn NAME)", "exclude": "stop resolving this CN (-cn NAME)",
	}
	userOps    = []string{"add", "list", "del", "disable", "enable", "passwd", "totp"}
	userOpDesc = map[string]string{
		"add": "create an account", "list": "list accounts", "del": "delete an account",
		"disable": "lock an account out", "enable": "unlock an account",
		"passwd": "change a password", "totp": "enable/disable 2FA",
	}
	backupOps    = []string{"create", "restore"}
	backupOpDesc = map[string]string{
		"create": "encrypted archive of CA, config, database", "restore": "extract an archive into -data",
	}
	debugOps       = []string{"on", "off"}
	debugOpDesc    = map[string]string{"on": "verbose logging, no restart", "off": "back to normal logging"}
	telegramOps    = []string{"config", "start", "stop", "restart", "status"}
	telegramOpDesc = map[string]string{
		"config": "get|set token/admin", "start": "start the poller", "stop": "stop the poller",
		"restart": "restart the poller", "status": "token/admin/chat-linked state",
	}
	telegramConfigOps = []string{"get", "set"}
	logsOpDesc        = map[string]string{
		"config": "get|set rotation policy", "rotate": "copytruncate all logs now",
		"status": "sizes + rotation state",
	}
)

// desc (tier 1, ovcp -h) stays to a few words — each command's own ops get
// their few-word explanation one level deeper (ovcp <command> -h, tier 2),
// and every op's real flags are a level deeper still (tier 3, already
// existing fs.PrintDefaults()). Full prose lives in ovcp(8), not here.
var commands = []command{
	{name: "init", desc: "one-shot setup: CA, server cert, admin user", run: cmdInit},
	{name: "certificate", alias: "cert", desc: "issue, list, revoke, renew certs", sub: certOps, subDesc: certOpDesc, run: cmdCertificate},
	{name: "ca", desc: "CA passphrase rotation or cert renewal, CLI-only", sub: caOps, subDesc: caOpDesc, run: cmdCA},
	{name: "backup", desc: "encrypted export/import: CA, config, database", sub: backupOps, subDesc: backupOpDesc, run: cmdBackup},
	{name: "status", desc: "full-system overview: vpn, dns, certs, telegram", run: cmdStatus},
	{name: "stats", desc: "traffic history, live follow, sampling config", run: cmdStats},
	{name: "vpn", desc: "manage the openvpn worker", sub: vpnOps, subDesc: vpnOpDesc, run: cmdVPN},
	{name: "dns", desc: "manage the dnsmasq worker", sub: dnsOps, subDesc: dnsOpDesc, run: cmdDNS},
	{name: "record", desc: "manage internal DNS records", sub: recordOps, subDesc: recordOpDesc, run: cmdRecord},
	{name: "logs", desc: "log rotation for openvpn/ovcp/dnsmasq logs", sub: logsOps, subDesc: logsOpDesc, run: cmdLogs},
	{name: "debug", desc: "toggle verbose logging on a running serve", sub: debugOps, subDesc: debugOpDesc, run: cmdDebug},
	{name: "telegram", desc: "notify + control bot", sub: telegramOps, subDesc: telegramOpDesc, run: cmdTelegram},
	{name: "user", desc: "manage admin UI accounts", sub: userOps, subDesc: userOpDesc, run: cmdUser},
	{name: "audit", desc: "last 50 audit entries", run: cmdAudit},
	{name: "serve", desc: "run admin UI + API", run: cmdServe},
	{name: "version", desc: "print version", run: cmdVersion},
	{name: "completion", desc: "shell completion script", sub: []string{"bash", "zsh", "fish"}, run: cmdCompletion},
}

// subUsage sets fs.Usage to ovcp's standard "usage: ovcp <path> ..." line, so
// -h looks the same at any nesting depth (top-level command or op below it).
func subUsage(fs *flag.FlagSet, path string) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ovcp %s\n", path)
		fs.PrintDefaults()
	}
}

// cmdCertificate wraps the certificate lifecycle ops: issue (client,
// create+renew+export), list, revoke, renew (server only — see cmdRenew).
func cmdCertificate(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "certificate", certOps, certOpDesc)
		cfs := newFlags("certificate " + op)
		subUsage(cfs, "certificate "+op)
		var body func(ctx *cliContext)
		switch op {
		case "issue":
			body = cmdIssue(cfs)
		case "list":
			body = cmdList(cfs)
		case "revoke":
			body = cmdRevoke(cfs)
		case "renew":
			body = cmdRenew(cfs)
		}
		cfs.Parse(rest)
		body(ctx)
	}
}

// helpText renders the commands table as the -h/usage screen.
func helpText() string {
	var b strings.Builder
	b.WriteString("ovcp <command>\n")
	tw := tabwriter.NewWriter(&b, 0, 4, 3, ' ', 0)
	for _, c := range commands {
		name := c.name
		if c.alias != "" {
			name += " (" + c.alias + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\n", name, c.desc)
	}
	tw.Flush()
	b.WriteString("\novcp <command> -h lists that command's own ops; ovcp <command> <op> -h its flags.\n")
	b.WriteString("-data DIR overrides $OVCP_DATA (default /var/lib/ovcp); must come before\n")
	b.WriteString("the command, e.g. ovcp -data /tmp/ovcp init ...\n")
	b.WriteString("-no-color disables ANSI colors; -debug turns on debug-level logging.\n")
	b.WriteString("-json switches every command to JSON output (JSON log lines for serve);\n")
	b.WriteString("all three go before the command, e.g. ovcp -json certificate list.\n")
	b.WriteString("Full guide: ovcp(8).")
	return b.String()
}

type versionOut struct {
	Version        string `json:"version"`
	Platform       string `json:"platform"`    // runtime.GOOS/GOARCH — always accurate, never injected
	BuildTarget    string `json:"buildTarget"` // Makefile TARGET/Containerfile arch, e.g. "host", "arm64-musl"
	OpenVPNVersion string `json:"openvpnVersion,omitempty"`
	OpenVPNPath    string `json:"openvpnPath,omitempty"`
	DnsmasqVersion string `json:"dnsmasqVersion,omitempty"`
	DnsmasqPath    string `json:"dnsmasqPath,omitempty"`
}

func cmdVersion(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		out := versionOut{Version: version, Platform: runtime.GOOS + "/" + runtime.GOARCH, BuildTarget: buildTarget}
		if v, p, ok := controller.OpenVPNVersion(); ok {
			out.OpenVPNVersion, out.OpenVPNPath = v, p
		}
		if v, p, ok := controller.DnsmasqVersion(); ok {
			out.DnsmasqVersion, out.DnsmasqPath = v, p
		}
		output(out, func(o versionOut) {
			fmt.Println("ovcp", o.Version, paint(ansiCyan, "("+o.Platform+", "+o.BuildTarget+")"))
			if o.OpenVPNVersion == "" {
				fmt.Println("openvpn: not found on PATH")
			} else {
				fmt.Printf("openvpn %s (%s)\n", o.OpenVPNVersion, o.OpenVPNPath)
			}
			if o.DnsmasqVersion == "" {
				fmt.Println("dnsmasq: not found on PATH")
			} else {
				fmt.Printf("dnsmasq %s (%s)\n", o.DnsmasqVersion, o.DnsmasqPath)
			}
		})
	}
}

// cmdIssue is client-only — a server has one cert, touched only by `init`/
// `certificate renew` — and covers create+renew (-renew) and raw or bundle
// output (-export).
func cmdIssue(fs *flag.FlagSet) func(ctx *cliContext) {
	cn := fs.String("cn", "", "common name (required)")
	renew := fs.Bool("renew", false, "replace an existing active cert for this CN (else: error if one exists)")
	days := fs.Int("days", 365, "validity (days)")
	out := fs.String("out", "", "write to files with this prefix instead of printing (.crt/.key, or .ovpn with -export)")
	keyPass := fs.String("key-pass", "", "encrypt private key with this password")
	export := fs.Bool("export", false, "print a ready .ovpn bundle instead of raw cert+key")
	remote := fs.String("remote", "", "-export: server host clients connect to (default: OVCP_SERVER_CN / server cert CN)")
	port := fs.Int("port", 0, "-export: server port (default: the configured server port)")
	proto := fs.String("proto", "", "-export: udp|tcp (default: the configured server proto)")
	serverCN := fs.String("server-cn", "", "-export: verify-x509-name value")
	splitTunnel := fs.Bool("split-tunnel", false, "-export: keep the client's own default route (needs server redirect on)")
	customOpts := fs.String("custom-opts", "", "-export: custom client directives: comma-separated, a file via $(cat FILE), or - for $EDITOR")
	return func(ctx *cliContext) {
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		requirePositive(*days, "days")
		s := ctx.openStore()
		defer s.Close()
		if *renew {
			if err := s.RequireActiveCert(*cn, "client"); err != nil {
				die(fmt.Errorf("%w — omit -renew to issue a new one", err))
			}
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := issueCert(ctx.p, pki.KindClient, *cn, *days, pass, *keyPass)
		die(err)
		action := "issue"
		if *renew {
			action = "renew"
			die(s.ReplaceCert(store.CertFrom(ic, "client")))
			die(regenCRLFromStore(ctx.p, s, pass))
		} else if err := s.AddCert(store.CertFrom(ic, "client")); err != nil {
			die(fmt.Errorf("%w — add -renew to replace it", err))
		}
		refreshCertsHostsCLI(ctx.dataDir, s)
		s.Audit("cli", action, fmt.Sprintf("cn=%s serial=%s", *cn, ic.SerialHex))

		if !*export {
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
			return
		}

		if *remote == "" {
			*remote = adminCertCN(ctx.dataDir)
		}
		if *serverCN == "" {
			*serverCN = adminCertCN(ctx.dataDir)
		}
		if *remote == "" {
			die(fmt.Errorf("-remote required (no server CN found)"))
		}
		raw, _ := s.GetSetting("vpn_config")
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
			extra, _ = editText("")
		default:
			extra = commaOrLines(*customOpts)
		}
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

// issueOut is `issue -json`'s shape: the PEM bytes inline (no -out), or the
// paths they were written to instead.
type issueOut struct {
	Serial   string `json:"serial"`
	CertPEM  string `json:"cert,omitempty"`
	KeyPEM   string `json:"key,omitempty"`
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

// exportOut is `issue -export -json`'s shape: the .ovpn bundle inline (no
// -out), or the path it was written to instead.
type exportOut struct {
	Serial string `json:"serial"`
	Bundle string `json:"bundle,omitempty"`
	File   string `json:"file,omitempty"`
}

// regenCRLFromStore rebuilds the CRL from s's full revoked set — the shared
// tail end of anything that revokes a cert, whether directly (cmdRevoke) or
// as the side effect of a client renewal (cmdRenew).
func regenCRLFromStore(p *pki.PKI, s *store.Store, passphrase []byte) error {
	rev, err := s.RevokedCerts()
	if err != nil {
		return err
	}
	entries := make([]pki.RevokedEntry, len(rev))
	for i, c := range rev {
		entries[i] = pki.RevokedEntry{SerialHex: c.Serial, RevokedAt: *c.RevokedAt}
	}
	return p.RegenCRL(entries, passphrase)
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
		refreshCertsHostsCLI(ctx.dataDir, s)
		die(regenCRLFromStore(ctx.p, s, pass))
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
// rows, or hand off to the command's text renderer. Reads the global -json flag.
func output[T any](rows T, text func(T)) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		die(enc.Encode(rows))
		return
	}
	text(rows)
}

// outcome is the generic {"message":"..."} JSON shape for commands with only
// a confirmation line; commands with real data keep their own richer type.
type outcome struct {
	Message string `json:"message"`
}

func msg(format string, a ...any) outcome { return outcome{fmt.Sprintf(format, a...)} }

// printMsg is outcome's default text renderer — msg(...) + output() with no
// custom formatting, the common case.
func printMsg(o outcome) { fmt.Println(o.Message) }

// progress prints a human-progress line, suppressed under -json so it never
// interleaves with output()'s single JSON object.
func progress(format string, a ...any) {
	if !jsonOut {
		fmt.Printf(format, a...)
	}
}

// sortByFlag sorts rows by the named field (string getters, so RFC3339 time
// fields sort too). Empty key is a no-op; unrecognized key errors rather than silently keeping natural order.
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
	"status": func(c store.Cert) string { return c.Status() },
}

var userSortGetters = map[string]func(store.User) string{
	"username": func(u store.User) string { return u.Username },
	"role":     func(u store.User) string { return u.Role },
	"created":  func(u store.User) string { return u.CreatedAt.Format(time.RFC3339) },
	"status":   func(u store.User) string { return boolText(!u.Disabled) },
	"2fa":      func(u store.User) string { return boolText(u.TOTPSecret != "") },
}

// certStatus renders c.Status() for the text/-json list output — same
// classification store.Cert.Status() gives the API and the telegram bot,
// just upper-cased for "revoked" to keep this command's existing look.
func certStatus(c store.Cert) string {
	st := c.Status()
	if st == "revoked" {
		return "REVOKED"
	}
	return st
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

// coloredStatus is `list`/`record list`'s shared "STATUS  " text cell.
func coloredStatus(status string) string {
	st := fmt.Sprintf("%-8s", status) // pad first: color codes must not count toward width
	switch status {
	case "REVOKED", "expired":
		return red(st)
	case "expiring":
		return yellow(st)
	case "valid":
		return green(st)
	}
	return st
}

// filterSortCerts applies `list`/`record list`'s shared -status/-kind
// filters and -sort/-desc ordering.
func filterSortCerts(certs []store.Cert, status, kind, sortBy string, desc bool) ([]store.Cert, error) {
	var out []store.Cert
	for _, c := range certs {
		if status == "active" && c.RevokedAt != nil {
			continue
		}
		if status == "revoked" && c.RevokedAt == nil {
			continue
		}
		if kind != "all" && c.Kind != kind {
			continue
		}
		out = append(out, c)
	}
	return out, sortByFlag(out, certSortGetters, sortBy, desc)
}

func cmdList(fs *flag.FlagSet) func(ctx *cliContext) {
	status := fs.String("status", "all", "all|active|revoked")
	kind := fs.String("kind", "all", "all|client|server")
	sortBy := fs.String("sort", "", "cn|kind|expiry|serial|status (default: issued order)")
	desc := fs.Bool("desc", false, "reverse sort order")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		certs, err := s.ListCerts()
		die(err)
		out, err := filterSortCerts(certs, *status, *kind, *sortBy, *desc)
		die(err)
		rows := []certOut{}
		for _, c := range out {
			rows = append(rows, certOut{certStatus(c), c.Kind, c.CN, c.Serial, c.NotAfter})
		}
		output(rows, func(rows []certOut) {
			fmt.Printf("%-10s %-10s %-24s %-18s %s\n", "STATUS", "KIND", "CN", "EXPIRES", "SERIAL")
			for _, c := range rows {
				fmt.Printf("%s %-10s %-24s expires %s  %s\n",
					coloredStatus(c.Status), c.Kind, c.CN, c.NotAfter.Format("2006-01-02"), c.Serial)
			}
		})
	}
}

func cmdInit(fs *flag.FlagSet) func(ctx *cliContext) {
	skeleton := fs.Bool("skeleton", false,
		"create/repair the data directory and permissions only; skip CA/admin/server-cert setup. Safe to re-run anytime.")
	caCN := fs.String("ca-cn", "OVCP CA", "CA common name")
	serverCN := fs.String("server-cn", "", "server cert CN / public hostname (required)")
	years := fs.Int("ca-years", 10, "CA validity")
	days := fs.Int("server-days", 825, "server cert validity (days)")
	admin := fs.String("admin", "admin", "initial admin username ('' to skip)")
	mgmt := mgmtFlag(fs)
	return func(ctx *cliContext) {
		if *skeleton {
			die(ensureSkeleton(ctx.dataDir))
			output(msg("data directory ready: %s", ctx.dataDir), printMsg)
			return
		}
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
		if _, _, ok := controller.DnsmasqVersion(); ok {
			cfg.PushInternalDNS = true // dnsmasq present: internal names resolve out of the box
		}
		fillPaths(&cfg, ctx.dataDir, *mgmt)
		raw, _ := json.Marshal(cfg)
		die(s.SetSetting("vpn_config", string(raw)))
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

// initOut is `init -json`'s shape: artifact paths plus the admin UI URL.
// The [N/5] progress lines are suppressed under -json; this is the one result.
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
	mgmt := mgmtFlag(fs)
	ctrl := ctrlFlag(fs, "")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		runServe(ctx.dataDir, *listen, *mgmt, *ctrl, ctx.p, s)
	}
}

// statusOut is what `status -json` prints: the whole system in one object —
// everything vpn|dns|telegram status and certificate list report
// individually, without stitching four commands together.
type statusOut struct {
	Running       bool                       `json:"running"`
	Pid           int                        `json:"pid,omitempty"`
	Uptime        string                     `json:"uptime,omitempty"`     // openvpn child, empty if not running
	OvcpUptime    string                     `json:"ovcpUptime,omitempty"` // serve process, empty if unreachable
	Error         string                     `json:"error,omitempty"`
	Clients       []controller.VPNClient     `json:"clients"`
	DNSRunning    bool                       `json:"dnsRunning"`
	DNSPid        int                        `json:"dnsPid,omitempty"`
	DNSUptime     string                     `json:"dnsUptime,omitempty"`
	CertsTotal    int                        `json:"certsTotal"`
	CertsExpiring int                        `json:"certsExpiring"`
	Telegram      *controller.TelegramStatus `json:"telegram,omitempty"` // nil: serve unreachable, couldn't ask
}

// fmtUptime renders a Go duration string ("3h2m1s"), or "" for the zero
// time (not running / not known).
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
	switch {
	case st.Error != "" && !st.Running:
		// same control socket the OpenVPN line above already reported
		// unreachable — dns-status would fail identically, not really "stopped".
		fmt.Println("DNS: unknown")
	case st.DNSRunning:
		fmt.Println(green(fmt.Sprintf("DNS: running (pid %d, up %s)", st.DNSPid, st.DNSUptime)))
	default:
		fmt.Println(red("DNS: stopped"))
	}
	if st.OvcpUptime != "" {
		fmt.Println("ovcp: up", st.OvcpUptime)
	}
	if st.CertsExpiring == 0 {
		fmt.Printf("Certs: %d\n", st.CertsTotal)
	} else {
		fmt.Printf("Certs: %d, %d expiring\n", st.CertsTotal, st.CertsExpiring)
	}
	switch {
	case st.Error != "" && !st.Running:
		fmt.Println("Telegram: unknown")
	case st.Telegram == nil:
	case !st.Telegram.TokenSet:
		fmt.Println("Telegram: not configured")
	case st.Telegram.Running:
		fmt.Println(green("Telegram: running"))
	default:
		fmt.Println(red("Telegram: stopped"))
	}
}

func cmdStatus(fs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := ctrlFlag(fs, "")
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
			// via serve's control socket, not a second dial to openvpn's mgmt
			// socket — openvpn allows only one connected mgmt client, and serve already holds that slot.
			if cl, err := controller.Clients(*ctrl); err != nil {
				st.Error = err.Error()
			} else {
				st.Clients = cl
			}
		}

		// dns-status/telegram-status share the same control socket the status
		// call above already dialed — if that failed, these would fail
		// identically; skip the guaranteed-redundant round trips.
		serveUnreachable := st.Error != "" && !st.Running
		if !serveUnreachable {
			if dr, err := controller.Control(*ctrl, "dns-status"); err == nil && dr.Pid != 0 {
				st.DNSRunning, st.DNSPid = true, dr.Pid
				st.DNSUptime = fmtUptime(dr.StartedAt)
			}
		}

		s := ctx.openStore()
		defer s.Close()
		if certs, err := s.AllCerts(ctx.p); err == nil {
			st.CertsTotal, st.CertsExpiring = store.CertCounts(certs)
		}
		if !serveUnreachable {
			if tg, err := controller.TelegramGetStatus(*ctrl); err == nil {
				st.Telegram = &tg
			}
		}

		output(st, printStatusText)
	}
}

func cmdKill(fs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := ctrlFlag(fs, "")
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

// cmdRecord manages the Records tab: list certs.hosts/custom.hosts, edit
// custom.hosts in $EDITOR, or include/exclude a CN (mirrors `user enable|disable`).
func cmdRecord(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "record", recordOps, recordOpDesc)
		pp := dataPaths(ctx.dataDir)
		gid := dnsGID(dnsRunAsGroup())
		ctx.openStore().Close() // guarantees dns/ (and everything else) exists before any op below touches it
		switch op {
		case "list":
			lfs := newFlags("record list")
			status := lfs.String("status", "all", "all|active|revoked")
			kind := lfs.String("kind", "all", "all|client|server")
			sortBy := lfs.String("sort", "", "cn|kind|expiry|serial|status (default: issued order)")
			desc := lfs.Bool("desc", false, "reverse sort order")
			lfs.Parse(rest)
			s := ctx.openStore()
			certs, err := s.ListCerts()
			s.Close()
			die(err)
			out, err := filterSortCerts(certs, *status, *kind, *sortBy, *desc)
			die(err)
			customData, _ := os.ReadFile(pp.CustomHosts)
			rows := []recordOut{}
			for _, c := range out {
				rows = append(rows, recordOut{certOut{certStatus(c), c.Kind, c.CN, c.Serial, c.NotAfter}, c.IncludeDNS})
			}
			output(recordListOut{rows, string(customData)}, func(o recordListOut) {
				fmt.Println("Certificate records:")
				fmt.Printf("%-10s %-10s %-24s %-18s %-8s %s\n", "STATUS", "KIND", "CN", "EXPIRES", "DNS", "SERIAL")
				for _, r := range o.Certs {
					dns := "excluded"
					if r.IncludeDNS {
						dns = green("included")
					}
					fmt.Printf("%s %-10s %-24s expires %s  %-8s  %s\n",
						coloredStatus(r.Status), r.Kind, r.CN, r.NotAfter.Format("2006-01-02"), dns, r.Serial)
				}
				fmt.Println("Custom records:")
				fmt.Print(o.Custom)
			})

		case "edit":
			efs := newFlags("record edit")
			efs.Parse(rest)
			cur, _ := os.ReadFile(pp.CustomHosts)
			out, changed := editText(string(cur))
			if !changed {
				output(msg("no change"), printMsg)
				return
			}
			die(api.WriteAtomicHosts(pp.CustomHosts, []byte(out), gid))
			s := ctx.openStore()
			s.Audit("cli", "dns_custom_change", "")
			s.Close()
			output(msg("saved"), printMsg)

		case "include", "exclude":
			ifs := newFlags("record " + op)
			cn := ifs.String("cn", "", "certificate CN (required)")
			ifs.Parse(rest)
			if *cn == "" {
				die(fmt.Errorf("-cn required"))
			}
			s := ctx.openStore()
			defer s.Close()
			certs, err := s.ListCerts()
			die(err)
			c, found := activeCertByCN(certs, *cn)
			if !found {
				die(fmt.Errorf("no active certificate for CN %q", *cn))
			}
			include := op == "include"
			if c.IncludeDNS == include {
				output(msg("%s is already %sd", *cn, op), printMsg)
				return
			}
			die(s.SetCertDNS(c.Serial, include))
			refreshCertsHostsCLI(ctx.dataDir, s)
			s.Audit("cli", "cert_dns_"+op, "cn="+*cn+" serial="+c.Serial)
			output(msg("%sd: %s", op, *cn), printMsg)
		}
	}
}

// recordOut is certOut plus the one field `list -json` needs beyond it.
type recordOut struct {
	certOut
	IncludeDNS bool `json:"includeDNS"`
}

type recordListOut struct {
	Certs  []recordOut `json:"certs"`
	Custom string      `json:"custom"`
}

// activeCertByCN finds cn's currently-active (non-revoked) cert — the store
// package keeps the equivalent lookup private (activeCertSerial), so this
// is the CLI's own read-only scan over the already-public ListCerts.
func activeCertByCN(certs []store.Cert, cn string) (store.Cert, bool) {
	for _, c := range certs {
		if c.CN == cn && c.RevokedAt == nil {
			return c, true
		}
	}
	return store.Cert{}, false
}

// runProcOp executes one already-resolved lifecycle op (start/stop/restart/
// reconnect/status) against the control socket — shared by procCmd (dns) and
// cmdVPN (vpn, which special-cases kill before falling through to this).
func runProcOp(ctx *cliContext, name, op string, rest []string, wirePrefix string) {
	ofs := newFlags(name + " " + op)
	ctrl := ctrlFlag(ofs, "")
	ofs.Parse(rest)
	r, err := controller.Control(*ctrl, wirePrefix+op)
	die(err)
	if op != "status" { // status is read-only, don't audit
		s := ctx.openStore()
		s.Audit("cli", name+"_"+op, fmt.Sprintf("pid=%d", r.Pid))
		s.Close()
	}
	output(r, func(r controller.ControlResult) { printProcText(name, op, r) })
}

// dnsConfigBodies wires dns's config sub-ops through configOp — same
// GET/POST /api/dns/config the web UI's Records tab uses.
var dnsConfigBodies = map[string]func(fs *flag.FlagSet) func(ctx *cliContext){
	"get": cmdDNSConfigGet, "set": cmdDNSConfigSet,
}

// cmdDNS drives the dnsmasq worker's lifecycle, plus `config` (settings, not
// a lifecycle op) — mirrors cmdVPN's kill/config special-cases.
func cmdDNS(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "dns", dnsOps, dnsOpDesc)
		if op == "config" {
			configOp("dns config", dnsConfigOps, configOpDesc, dnsConfigBodies)(ctx, rest)
			return
		}
		runProcOp(ctx, "dns", op, rest, "dns-")
	}
}

// warnDNSLeak prints api.DNSLeakWarning's advisory (if any) after a vpn/dns
// config save — same non-fatal check the web UI shows inline.
func warnDNSLeak(s *store.Store) {
	raw, _ := s.GetSetting("vpn_config")
	if w := api.DNSLeakWarning(ovpnconf.Load(raw), api.LoadDNSConfig(s)); w != "" {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

func cmdDNSConfigGet(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		output(api.LoadDNSConfig(s), func(c api.DNSConfig) {
			fmt.Println("block-internet:", boolText(c.BlockInternet))
		})
		warnDNSLeak(s)
	}
}

// cmdDNSConfigSet: same "empty means unchanged" idiom every config set uses.
func cmdDNSConfigSet(fs *flag.FlagSet) func(ctx *cliContext) {
	blockInternet := fs.String("block-internet", "", "on|off (unchanged if omitted)")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		cfg := api.LoadDNSConfig(s)
		if *blockInternet != "" {
			on, err := parseBoolArg(*blockInternet)
			die(err)
			cfg.BlockInternet = on
		}
		die(api.SaveDNSConfig(s, cfg))
		action := "off"
		if cfg.BlockInternet {
			action = "on"
		}
		s.Audit("cli", "dns_block_internet_"+action, "")
		warnDNSLeak(s)
		output(cfg, func(c api.DNSConfig) {
			fmt.Println("block-internet:", boolText(c.BlockInternet), "(restart dns to apply)")
			fmt.Println("saved")
		})
	}
}

// vpnConfigBodies wires vpn's config sub-ops through configOp — get/set
// mirror the web UI's GET/PUT /api/vpn/config exactly (same ovpnconf.Config,
// same wire shape).
var vpnConfigBodies = map[string]func(fs *flag.FlagSet) func(ctx *cliContext){
	"get": cmdVPNConfigGet, "set": cmdVPNConfigSet,
	"preview": cmdVPNConfigPreview,
}

// cmdVPN drives the openvpn worker's lifecycle, plus `kill` (disconnect one
// client) and `config` (settings, not a lifecycle op) — both keep their own
// flags/sub-dispatch instead of runProcOp's plain start/stop/restart shape.
func cmdVPN(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "vpn", vpnOps, vpnOpDesc)
		switch op {
		case "kill":
			kfs := newFlags("vpn kill")
			subUsage(kfs, "vpn kill")
			body := cmdKill(kfs)
			kfs.Parse(rest)
			body(ctx)
		case "config":
			configOp("vpn config", vpnConfigOps, configOpDesc, vpnConfigBodies)(ctx, rest)
		default:
			runProcOp(ctx, "vpn", op, rest, "")
		}
	}
}

// printProcText renders a lifecycle op's ControlResult, uppercased to match
// `ovcp status`'s "VPN:"/"DNS:" labels — audit events (runProcOp, before
// this runs) keep the original lowercase name.
func printProcText(name, op string, r controller.ControlResult) {
	name = strings.ToUpper(name)
	switch {
	case op == "status" && r.Pid == 0:
		fmt.Println(red(name + " stopped"))
	case op == "status":
		fmt.Println(green(fmt.Sprintf("%s running (pid %d, up %s)", name, r.Pid, fmtUptime(r.StartedAt))))
	case op == "start" && !r.Changed:
		fmt.Printf("%s already started (pid %d)\n", name, r.Pid)
	case op == "start":
		fmt.Printf("%s started (pid %d)\n", name, r.Pid)
	case op == "stop" && !r.Changed:
		fmt.Println(name, "already stopped")
	case op == "stop":
		fmt.Println(name, "stopped")
	case op == "restart":
		fmt.Printf("%s restarted (pid %d)\n", name, r.Pid)
	case op == "reconnect":
		fmt.Printf("%s reconnect sent (pid %d)\n", name, r.Pid)
	}
	if op == "status" {
		if u := fmtUptime(r.ServeStartedAt); u != "" {
			fmt.Println("ovcp: up", u)
		}
	}
}

// cmdRenew is server-only — a server has one cert, at fixed paths `serve`
// reads, no bundle concept (see cmdIssue for that). -cn renames it in place:
// server identity is kind-only, not CN-keyed, so renew and rename are one op.
func cmdRenew(fs *flag.FlagSet) func(ctx *cliContext) {
	cn := fs.String("cn", "", "new common name — omit to keep the current one")
	days := fs.Int("days", 825, "validity (days)")
	return func(ctx *cliContext) {
		requirePositive(*days, "days")
		s := ctx.openStore()
		defer s.Close()
		// renew replaces the current server cert; nothing active would
		// otherwise silently fall through to a plain issue instead of erroring.
		if err := s.RequireActiveCert("", "server"); err != nil {
			die(fmt.Errorf("%w — run `ovcp init` first", err))
		}
		targetCN := *cn
		if targetCN == "" {
			targetCN = adminCertCN(ctx.dataDir)
		}
		if targetCN == "" {
			die(fmt.Errorf("can't auto-detect the current server CN (e.g. right after a backup restore) — pass -cn"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := ctx.p.Issue(pki.KindServer, targetCN, *days, pass)
		die(err)
		die(writeServerCert(dataPaths(ctx.dataDir), s, ic))
		s.Audit("cli", "renew", fmt.Sprintf("kind=server cn=%s serial=%s", targetCN, ic.SerialHex))
		output(renewOut{CN: targetCN, Serial: ic.SerialHex, NotAfter: ic.NotAfter}, func(o renewOut) {
			fmt.Printf("server cert renewed: %s (cn %s, expires %s)\n", o.Serial, o.CN, o.NotAfter.Format("2006-01-02"))
			fmt.Println("run `ovcp vpn restart` to apply")
			if *cn != "" {
				fmt.Println("the admin UI's own TLS cert keeps the old CN until `ovcp serve` is restarted")
			}
		})
	}
}

// renewOut is `certificate renew -json`'s shape.
type renewOut struct {
	CN       string    `json:"cn"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"notAfter"`
}

// commaOrLines: comma list → one directive per line; no-op without a comma, so $(cat FILE) passes through unchanged.
// ponytail: assumes no directive needs a literal comma; use -custom-opts - if one ever does.
func commaOrLines(s string) string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.Join(parts, "\n")
}

// editText opens initial in $EDITOR (fallback vi), returning what was saved
// and whether it changed — computed once so every caller gets it for free.
func editText(initial string) (out string, changed bool) {
	tmp := filepath.Join(os.TempDir(), "ovcp-edit.conf")
	die(os.WriteFile(tmp, []byte(initial), 0o600))
	defer os.Remove(tmp)
	editor := cmp.Or(os.Getenv("EDITOR"), "vi")
	cmd := exec.Command(editor, tmp)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	die(cmd.Run())
	data, err := os.ReadFile(tmp)
	die(err)
	out = string(data)
	return out, out != initial
}

// cmdVPNConfigGet prints the persisted server config — GET /api/vpn/config's CLI twin.
func cmdVPNConfigGet(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		raw, _ := s.GetSetting("vpn_config")
		output(ovpnconf.Load(raw), printConfigText)
		warnDNSLeak(s)
	}
}

// printConfigText is config get/set's shared text rendering of a full config.
func printConfigText(c ovpnconf.Config) {
	fmt.Println("proto:      ", c.Proto)
	fmt.Println("port:       ", c.Port)
	fmt.Println("subnet:     ", c.Subnet)
	fmt.Println("cipher:     ", c.Cipher)
	fmt.Println("dns:        ", strings.Join(c.DNS, ", "))
	fmt.Println("push-internal-dns:", boolText(c.PushInternalDNS))
	fmt.Println("routes:     ", strings.Join(c.Routes, ", "))
	fmt.Println("redirect-gw:", boolText(c.RedirectGW))
	if c.Extra != "" {
		fmt.Println("extra:")
		fmt.Println(c.Extra)
	}
}

// configFlags registers config set/preview's shared flags — zero value means
// "leave unchanged", same idiom `certificate issue -export`'s -port/-proto
// use — and returns a closure applying whichever were set onto a base config.
func configFlags(fs *flag.FlagSet) func(cur ovpnconf.Config) (ovpnconf.Config, error) {
	proto := fs.String("proto", "", "udp|tcp (unchanged if omitted)")
	port := fs.Int("port", 0, "1-65535 (unchanged if omitted)")
	subnet := fs.String("subnet", "", "VPN subnet CIDR (unchanged if omitted)")
	cipher := fs.String("cipher", "", "AES-256-GCM|AES-128-GCM|CHACHA20-POLY1305 (unchanged if omitted)")
	dns := fs.String("dns", "", "comma-separated pushed DNS resolvers (unchanged if omitted)")
	pushInternalDNS := fs.String("push-internal-dns", "", "on|off: also push the internal dnsmasq resolver, first (unchanged if omitted)")
	routes := fs.String("routes", "", "comma-separated pushed routes, CIDR (unchanged if omitted)")
	redirectGW := fs.String("redirect-gw", "", "on|off: route all client traffic through the VPN (unchanged if omitted)")
	extra := fs.String("extra", "", "custom directives: comma-separated, a file via $(cat FILE), or - for $EDITOR (unchanged if omitted)")
	return func(cfg ovpnconf.Config) (ovpnconf.Config, error) {
		if *proto != "" {
			cfg.Proto = *proto
		}
		if *port != 0 {
			cfg.Port = *port
		}
		if *subnet != "" {
			cfg.Subnet = *subnet
		}
		if *cipher != "" {
			cfg.Cipher = *cipher
		}
		if *dns != "" {
			cfg.DNS = ovpnconf.SplitCSV(*dns)
		}
		if *pushInternalDNS != "" {
			b, err := parseBoolArg(*pushInternalDNS)
			if err != nil {
				return cfg, fmt.Errorf("-push-internal-dns: %w", err)
			}
			cfg.PushInternalDNS = b
		}
		if *routes != "" {
			cfg.Routes = ovpnconf.SplitCSV(*routes)
		}
		if *redirectGW != "" {
			b, err := parseBoolArg(*redirectGW)
			if err != nil {
				return cfg, fmt.Errorf("-redirect-gw: %w", err)
			}
			cfg.RedirectGW = b
		}
		switch *extra {
		case "":
		case "-":
			cfg.Extra, _ = editText(cfg.Extra)
		default:
			cfg.Extra = commaOrLines(*extra)
		}
		return cfg, nil
	}
}

// printDiff renders a server.conf diff — shared by preview (dry-run) and
// set (what it's about to persist), one rendering not two.
func printDiff(diff []string) {
	if len(diff) == 0 {
		fmt.Println("no changes vs. the saved server.conf")
		return
	}
	for _, l := range diff {
		if strings.HasPrefix(l, "+") {
			fmt.Println(green(l))
		} else {
			fmt.Println(red(l))
		}
	}
}

// cmdVPNConfigSet applies flag overrides and persists — PUT /api/vpn/config's
// CLI twin. -extra - opens $EDITOR on the raw directives inline (configFlags);
// there's no separate `edit` op to keep in sync with this validate/diff/persist
// sequence, just this one path every vpn config change saves through. An empty
// diff never writes or audits — true whether that's zero flags passed, values
// matching what's already saved, or an $EDITOR session that changed nothing.
func cmdVPNConfigSet(fs *flag.FlagSet) func(ctx *cliContext) {
	apply := configFlags(fs)
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		raw, _ := s.GetSetting("vpn_config")
		cur := ovpnconf.Load(raw)
		cfg, err := apply(cur)
		die(err)
		die(cfg.Validate())
		diff := ovpnconf.Diff(cur.Render(), cfg.Render())
		if len(diff) == 0 {
			output(cfg, func(c ovpnconf.Config) { printDiff(diff) })
			return
		}
		enc, _ := json.Marshal(cfg)
		die(s.SetSetting("vpn_config", string(enc)))
		die(cfg.WriteAtomic(dataPaths(ctx.dataDir).ServerConf))
		s.Audit("cli", "config_change", "")
		warnDNSLeak(s)
		output(cfg, func(c ovpnconf.Config) {
			printDiff(diff)
			fmt.Println("saved; run `ovcp vpn restart` to apply")
		})
	}
}

// cmdVPNConfigPreview applies flag overrides without persisting, showing the
// server.conf diff — POST /api/vpn/config/preview's CLI twin.
func cmdVPNConfigPreview(fs *flag.FlagSet) func(ctx *cliContext) {
	apply := configFlags(fs)
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		raw, _ := s.GetSetting("vpn_config")
		cur := ovpnconf.Load(raw)
		cfg, err := apply(cur)
		die(err)
		die(cfg.Validate())
		diff := ovpnconf.Diff(cur.Render(), cfg.Render())
		output(previewOut{diff, len(diff) > 0}, func(o previewOut) { printDiff(o.Diff) })
		if w := api.DNSLeakWarning(cfg, api.LoadDNSConfig(s)); w != "" {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
	}
}

type previewOut struct {
	Diff    []string `json:"diff"`
	Changed bool     `json:"changed"`
}

// cmdCA wraps the CA-level ops (passphrase rotation, cert renewal) — the
// most sensitive surface in the tool, deliberately CLI-only and kept on its
// own top-level menu rather than folded into `certificate` (the CA isn't a
// certs-table row at all, see store's schema).
func cmdCA(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "ca", caOps, caOpDesc)
		cfs := newFlags("ca " + op)
		subUsage(cfs, "ca "+op)
		var body func(ctx *cliContext)
		switch op {
		case "rotate":
			body = cmdRotateCA(cfs)
		case "renew":
			body = cmdRenewCA(cfs)
		case "status":
			body = cmdCAStatus(cfs)
		}
		cfs.Parse(rest)
		body(ctx)
	}
}

// caStatusOut is `ca status -json`'s shape; status reuses store.Cert.Status,
// same classification the API and telegram bot use.
type caStatusOut struct {
	CN       string    `json:"cn"`
	NotAfter time.Time `json:"notAfter"`
	Status   string    `json:"status"`
}

func cmdCAStatus(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		cert, err := ctx.p.CACert()
		die(err)
		o := caStatusOut{
			CN: cert.Subject.CommonName, NotAfter: cert.NotAfter,
			Status: store.Cert{NotAfter: cert.NotAfter}.Status(),
		}
		output(o, func(o caStatusOut) {
			fmt.Printf("%s  %-10s expires %s\n", o.CN, coloredStatus(o.Status), o.NotAfter.Format("2006-01-02"))
		})
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

// cmdRenewCA reissues the CA cert in place: new serial, extended validity,
// same key — every already-issued cert stays valid, nothing needs
// reissuing. Distinct from `ca rotate`, which only changes the passphrase.
func cmdRenewCA(fs *flag.FlagSet) func(ctx *cliContext) {
	years := fs.Int("years", 10, "validity (years)")
	return func(ctx *cliContext) {
		requirePositive(*years, "years")
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		cert, err := ctx.p.RenewCA(*years, pass)
		die(err)
		s := ctx.openStore()
		defer s.Close()
		s.Audit("cli", "renew_ca", "")
		output(renewCAOut{cert.NotAfter}, func(o renewCAOut) {
			fmt.Println("CA cert renewed; valid until", o.NotAfter.Format("2006-01-02"))
			fmt.Println("run `ovcp vpn restart` to apply")
		})
	}
}

type renewCAOut struct {
	NotAfter time.Time `json:"notAfter"`
}

// cmdBackup and cmdUser take no top-level flags: opArg's rest is fed to a
// fresh FlagSet per op, same as vpn/debug/telegram.
func cmdBackup(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "backup", backupOps, backupOpDesc)
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
				"next: OVCP_SERVER_CN=<host> ovcp certificate renew, then ovcp vpn start", ctx.dataDir),
				func(o outcome) {
					fmt.Println("[1/2] restored CA, CRL, tls-crypt key, config, and database into", ctx.dataDir)
					fmt.Println("[2/2] next: OVCP_SERVER_CN=<host> ovcp certificate renew   (issues the openvpn server cert)")
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
		op, rest := opArg(fs, "debug", debugOps, debugOpDesc)
		ofs := newFlags("debug " + op)
		ctrl := ctrlFlag(ofs, "")
		ofs.Parse(rest)
		_, err := controller.Control(*ctrl, "debug "+op)
		die(err)
		output(map[string]bool{"debug": op == "on"}, func(o map[string]bool) {
			fmt.Println("debug logging", op)
		})
	}
}

// telegramConfigBodies wires telegram's config sub-ops through configOp —
// same GET/PUT /api/telegram/config the web UI uses.
var telegramConfigBodies = map[string]func(fs *flag.FlagSet) func(ctx *cliContext){
	"get": cmdTelegramConfigGet, "set": cmdTelegramConfigSet,
}

func cmdTelegramConfigGet(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		output(telegram.ConfigStatus(s), func(st controller.TelegramStatus) {
			fmt.Println("token-set:", boolText(st.TokenSet))
			fmt.Println("admin:    ", st.Admin)
		})
	}
}

// cmdTelegramConfigSet: token and admin are independently optional, so
// changing one never requires re-supplying the other — -token is a flag
// (not a value) since a secret has no business appearing on the command line.
// Admin is applied before token: SetAdmin's goodbye message to the outgoing
// admin needs the chat id SetToken would otherwise already have wiped, had
// both been changed in this one invocation (SetToken clears it on any real
// token change, same unlink-on-identity-change rule SetAdmin follows).
func cmdTelegramConfigSet(fs *flag.FlagSet) func(ctx *cliContext) {
	setToken := fs.Bool("token", false, "prompt for (or read $OVCP_TELEGRAM_TOKEN) a new bot token")
	admin := fs.String("admin", os.Getenv("OVCP_TELEGRAM_ADMIN"),
		"admin Telegram numeric id or @username (unchanged if omitted; env: OVCP_TELEGRAM_ADMIN)")
	return func(ctx *cliContext) {
		if !*setToken && *admin == "" {
			die(fmt.Errorf("nothing to set: pass -token and/or -admin"))
		}
		s := ctx.openStore()
		defer s.Close()
		if *admin != "" {
			die(telegram.SetAdmin(s, *admin))
			s.Audit("cli", "telegram_admin_change", "admin="+*admin)
		}
		if *setToken {
			token := readSecret("Telegram bot token", "OVCP_TELEGRAM_TOKEN", false)
			die(telegram.SetToken(s, string(token)))
			s.Audit("cli", "telegram_token_change", "")
		}
		output(telegram.ConfigStatus(s), func(st controller.TelegramStatus) {
			fmt.Println("token-set:", boolText(st.TokenSet))
			fmt.Println("admin:    ", st.Admin)
			fmt.Println("saved; run 'ovcp telegram start' (or restart serve) to bring the bot up")
		})
	}
}

func cmdTelegram(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "telegram", telegramOps, telegramOpDesc)
		if op == "config" {
			configOp("telegram config", telegramConfigOps, configOpDesc, telegramConfigBodies)(ctx, rest)
			return
		}

		ofs := newFlags("telegram " + op)
		ctrl := ctrlFlag(ofs, "")
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
				fmt.Println("Telegram: not configured (run 'ovcp telegram config set -token -admin ...')")
				return
			}
			state, color := "stopped", red
			if st.Running {
				state, color = "running", green
			}
			if (op == "start" || op == "stop") && !st.Changed {
				state = "already " + state
			}
			fmt.Println(color(fmt.Sprintf("Telegram: %s, admin %s", state, st.Admin)))
		})
	}
}

func cmdUser(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "user", userOps, userOpDesc)
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
			status := lfs.String("status", "all", "all|enabled|disabled")
			role := lfs.String("role", "all", "all|admin|operator|readonly")
			sortBy := lfs.String("sort", "", "username|role|created|status|2fa (default: today's order)")
			desc := lfs.Bool("desc", false, "reverse sort order")
			lfs.Parse(rest)
			users, err := s.ListUsers()
			die(err)
			var filtered []store.User
			for _, u := range users {
				if *status == "enabled" && u.Disabled {
					continue
				}
				if *status == "disabled" && !u.Disabled {
					continue
				}
				if *role != "all" && u.Role != *role {
					continue
				}
				filtered = append(filtered, u)
			}
			die(sortByFlag(filtered, userSortGetters, *sortBy, *desc))
			rows := []api.UserSummary{}
			for _, u := range filtered {
				rows = append(rows, api.NewUserSummary(u))
			}
			output(rows, func(rows []api.UserSummary) {
				fmt.Printf("%-20s %-9s %-8s %-4s %s\n", "USERNAME", "ROLE", "STATUS", "2FA", "CREATED")
				for _, u := range rows {
					st := fmt.Sprintf("%-8s", "enabled")
					if u.Disabled {
						st = red(fmt.Sprintf("%-8s", "disabled"))
					} else {
						st = green(st)
					}
					tf := "-"
					if u.TOTP {
						tf = "2fa"
					}
					fmt.Printf("%-20s %-9s %s %-4s %s\n", u.Username, u.Role, st, tf, u.CreatedAt.Format("2006-01-02"))
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

var auditSortGetters = map[string]func(store.AuditEntry) string{
	"ts":     func(e store.AuditEntry) string { return e.TS.Format(time.RFC3339) },
	"actor":  func(e store.AuditEntry) string { return e.Actor },
	"action": func(e store.AuditEntry) string { return e.Action },
}

func cmdAudit(fs *flag.FlagSet) func(ctx *cliContext) {
	sortBy := fs.String("sort", "", "ts|actor|action (default: newest first)")
	desc := fs.Bool("desc", false, "reverse sort order")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		tail, err := s.AuditTail(50)
		die(err)
		slices.Reverse(tail) // newest first, in both output modes
		die(sortByFlag(tail, auditSortGetters, *sortBy, *desc))
		output(tail, func(tail []store.AuditEntry) {
			fmt.Printf("%-25s %-12s %-16s %s\n", "TIME", "ACTOR", "ACTION", "DETAIL")
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
// enforce the same complexity rule, unless $OVCP_YOLO_PASSWORD is set (auth.SecretYOLO) — your funeral.
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
	if !auth.SecretOK(string(v)) {
		if !auth.SecretYOLO() {
			die(fmt.Errorf("%s", auth.SecretErr(label)))
		}
		fmt.Fprintf(os.Stderr,
			"warning: %s ignored — %s is set, so the lock is now purely decorative\n",
			auth.SecretErr(label), auth.SecretYOLOEnv)
	}
	return v
}

// printQR renders a QR code as Unicode block characters (avoids a qrterminal
// dependency); no ANSI color involved, so -no-color/$NO_COLOR don't apply.
func printQR(text string) {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return
	}
	black, white := "██", "  "
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
