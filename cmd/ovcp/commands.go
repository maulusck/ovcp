package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

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
	"github.com/ovcp/ovcp/internal/upstream"
)

// opBody is one op's flag-registration + closure, real dispatch and
// completion alike — a flag is only ever declared once. command.run's shape, one level down.
type opBody = func(fs *flag.FlagSet) func(ctx *cliContext)

// nestedDispatch is an op-of-op dispatch (only "config": `vpn config
// get|set`) — completion's copy of what opDispatch drives for real execution.
type nestedDispatch struct {
	ops    []string
	bodies map[string]opBody
}

// command is one subcommand: run registers flags on fs, returning the closure
// executed once parsed. commands is the single dispatch source. 3-tier help:
// `-h` (desc), `<command> -h` (subDesc), `<command> <op> -h` (fs.PrintDefaults()).
type command struct {
	name    string
	alias   string // short form accepted alongside name in dispatch/completion; "" if none
	desc    string
	sub     []string
	subDesc map[string]string
	run     func(fs *flag.FlagSet) func(ctx *cliContext)

	// opBodies/nested back completion — same bodies/factories real dispatch
	// (opDispatch) already runs through. Nil if no op-level flags exist.
	opBodies map[string]opBody
	nested   map[string]nestedDispatch
}

// registeredFlagNames calls register on a throwaway FlagSet (same code path
// as real parsing, just never Parse'd or executed) and reads the flag names
// back — the one trick both command- and op-level completion use.
func registeredFlagNames(register opBody) []string {
	fs := newFlags("")
	register(fs)
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, "-"+f.Name) })
	return names
}

// flagNames is registeredFlagNames for c's own top-level flags.
func (c command) flagNames() []string { return registeredFlagNames(c.run) }

// opBodiesFlagNames is registeredFlagNames for one op inside a bodies map —
// nil (no completion) if op isn't in bodies at all.
func opBodiesFlagNames(bodies map[string]opBody, op string) []string {
	body, ok := bodies[op]
	if !ok {
		return nil
	}
	return registeredFlagNames(body)
}

// opsUsage renders tier 2: "usage: ovcp <name> <op>" plus one line per op
// (desc[o]=="" prints a bare name, never breaks) — shared by a missing/bad
// op's error and `ovcp <command> -h`, so the two can't drift into different listings.
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
// opArg's shape without needing an already-Parse'd FlagSet, for a second op
// level (e.g. "logs config get" — "config"'s own opArg already split "get" off).
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

// opDispatch: pick op from rest, register its flags via bodies[op] (same
// call completion runs against a throwaway FlagSet), parse, run. Every
// op-dispatched command's whole switch now, not just "<name> config" anymore.
func opDispatch(name string, ops []string, desc map[string]string, bodies map[string]opBody) func(ctx *cliContext, rest []string) {
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
		"include": "resolve this CN while connected — client certs only (-cn NAME)",
		"exclude": "stop resolving this CN — client certs only (-cn NAME)",
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
	upstreamOps    = []string{"list", "add", "del", "set-default", "assign", "reconcile", "status"}
	upstreamOpDesc = map[string]string{
		"list": "configured upstreams and the active default",
		"add":  "define one (-id, -iface, [-gateway], [-desc])",
		"del":  "remove one (-id)", "set-default": "switch the active exit (-id | -clear)",
		"assign":    "per-client override (-cn, -id | -clear)",
		"reconcile": "re-apply and report which upstreams are up/down",
		"status":    "nftables detection + enabled state",
	}
)

// desc stays a few words (see command's doc comment for the 3-tier shape);
// full prose lives in ovcp(8), not here.
var commands = []command{
	{name: "init", desc: "one-shot setup: CA, server cert, admin user", run: cmdInit},
	{name: "certificate", alias: "cert", desc: "issue, list, revoke, renew certs", sub: certOps, subDesc: certOpDesc, run: cmdCertificate, opBodies: certBodies},
	{name: "ca", desc: "CA passphrase rotation or cert renewal, CLI-only", sub: caOps, subDesc: caOpDesc, run: cmdCA, opBodies: caBodies},
	{name: "backup", desc: "encrypted export/import: CA, config, database", sub: backupOps, subDesc: backupOpDesc, run: cmdBackup, opBodies: backupBodies},
	{name: "status", desc: "full-system overview: vpn, dns, certs, telegram", run: cmdStatus},
	{name: "stats", desc: "traffic history, live follow, sampling config", run: cmdStats, nested: statsNested},
	{name: "vpn", desc: "manage the openvpn worker", sub: vpnOps, subDesc: vpnOpDesc, run: cmdVPN, opBodies: vpnBodies, nested: vpnNested},
	{name: "dns", desc: "manage the dnsmasq worker", sub: dnsOps, subDesc: dnsOpDesc, run: cmdDNS, opBodies: dnsBodies, nested: dnsNested},
	{name: "record", desc: "manage internal DNS records", sub: recordOps, subDesc: recordOpDesc, run: cmdRecord, opBodies: recordBodies},
	{name: "upstream", desc: "route VPN egress through a chosen interface or SOCKS proxy", sub: upstreamOps, subDesc: upstreamOpDesc, run: cmdUpstream, opBodies: upstreamBodies},
	{name: "logs", desc: "log rotation for openvpn/ovcp/dnsmasq logs", sub: logsOps, subDesc: logsOpDesc, run: cmdLogs, nested: logsNested},
	{name: "debug", desc: "toggle verbose logging on a running serve", sub: debugOps, subDesc: debugOpDesc, run: cmdDebug, opBodies: debugBodies},
	{name: "telegram", desc: "notify + control bot", sub: telegramOps, subDesc: telegramOpDesc, run: cmdTelegram, opBodies: telegramBodies, nested: telegramNested},
	{name: "user", desc: "manage admin UI accounts", sub: userOps, subDesc: userOpDesc, run: cmdUser, opBodies: userBodies},
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

// certBodies wires certificate's ops through opDispatch — issue (client,
// create+renew+export), list, revoke, renew (server only — see cmdRenew).
var certBodies = map[string]opBody{
	"issue": cmdIssue, "list": cmdList, "revoke": cmdRevoke, "renew": cmdRenew,
}

func cmdCertificate(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("certificate", certOps, certOpDesc, certBodies)(ctx, fs.Args())
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
	NftVersion     string `json:"nftVersion,omitempty"`
	NftPath        string `json:"nftPath,omitempty"`
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
		if v, p, ok := controller.NftablesVersion(); ok {
			out.NftVersion, out.NftPath = v, p
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
			if o.NftVersion == "" {
				fmt.Println("nftables: not found on PATH")
			} else {
				fmt.Printf("nftables %s (%s)\n", o.NftVersion, o.NftPath)
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
			output(issueOut{ic.SerialHex, string(ic.CertPEM), string(ic.KeyPEM)}, func(o issueOut) {
				fmt.Print(o.CertPEM, o.KeyPEM)
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
			var err error
			extra, err = editText("")
			die(err)
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
		output(exportOut{ic.SerialHex, string(bundle)}, func(o exportOut) {
			fmt.Print(o.Bundle)
			fmt.Fprintln(os.Stderr, "serial:", o.Serial)
		})
	}
}

// issueOut / exportOut are `issue -json`'s shapes: the PEM pair, or with
// -export the .ovpn bundle, inline — stdout is the only output.
type issueOut struct {
	Serial  string `json:"serial"`
	CertPEM string `json:"cert"`
	KeyPEM  string `json:"key"`
}

type exportOut struct {
	Serial string `json:"serial"`
	Bundle string `json:"bundle"`
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

// coloredStatus is every command's shared colored status cell. Padding is
// printTable's job now, not this function's — it just colors the word.
func coloredStatus(status string) string {
	switch status {
	case "REVOKED", "expired", "down", "disabled":
		return red(status)
	case "expiring":
		return yellow(status)
	case "valid", "up", "enabled":
		return green(status)
	}
	return status
}

// ansiSGR matches the color escapes ovcp's own red/green/yellow emit —
// visibleWidth strips them so colored and plain cells still measure right.
var ansiSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// visibleWidth: rune count, ANSI stripped first.
// ponytail: not display-width-aware, a wide (CJK) rune still misaligns —
// real content here (IDs, CNs, English text) is single-width; upgrade if that changes.
func visibleWidth(s string) int {
	return utf8.RuneCountInString(ansiSGR.ReplaceAllString(s, ""))
}

// printTable is the one aligned-table mechanism every list command shares
// — auto-sizes each column to its widest cell, no hardcoded widths to
// drift out of sync with real data.
func printTable(headers []string, rows [][]string) {
	all := append([][]string{headers}, rows...)
	widths := make([]int, len(headers))
	for _, row := range all {
		for i, cell := range row {
			if w := visibleWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for _, row := range all {
		var b strings.Builder
		for i, cell := range row {
			b.WriteString(cell)
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-visibleWidth(cell)+1))
			}
		}
		fmt.Println(b.String())
	}
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
			trows := make([][]string, len(rows))
			for i, c := range rows {
				trows[i] = []string{coloredStatus(c.Status), c.Kind, c.CN, c.NotAfter.Format("2006-01-02"), c.Serial}
			}
			printTable([]string{"STATUS", "KIND", "CN", "EXPIRES", "SERIAL"}, trows)
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
	RoutingWarn   string                     `json:"routingWarning,omitempty"`
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
	if st.RoutingWarn != "" {
		fmt.Println("warning:", st.RoutingWarn)
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
		st.RoutingWarn = controller.RoutingPrereqsWarning()

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

func cmdRecordList(lfs *flag.FlagSet) func(ctx *cliContext) {
	status := lfs.String("status", "all", "all|active|revoked")
	kind := lfs.String("kind", "all", "all|client|server")
	sortBy := lfs.String("sort", "", "cn|kind|expiry|serial|status (default: issued order)")
	desc := lfs.Bool("desc", false, "reverse sort order")
	return func(ctx *cliContext) {
		pp := dataPaths(ctx.dataDir)
		s := ctx.openStore()
		certs, err := s.ListCerts()
		raw, _ := s.GetSetting("vpn_config")
		s.Close()
		die(err)
		out, err := filterSortCerts(certs, *status, *kind, *sortBy, *desc)
		die(err)
		customData, _ := os.ReadFile(pp.CustomHosts)
		// liveIP: CN -> resolvable IP right now.
		liveIP := map[string]string{}
		if live, err := controller.Clients(ctrlSock()); err == nil {
			for _, cl := range live {
				if cl.VirtualAddress != "" {
					liveIP[cl.CN] = cl.VirtualAddress
				}
			}
		}
		if ip, err := ovpnconf.Load(raw).ServerTunIP(); err == nil {
			liveIP[adminCertCN(ctx.dataDir)] = ip.String()
		}
		rows := []recordOut{}
		for _, c := range out {
			rows = append(rows, recordOut{certOut{certStatus(c), c.Kind, c.CN, c.Serial, c.NotAfter}, c.IncludeDNS, liveIP[c.CN]})
		}
		output(recordListOut{rows, string(customData)}, func(o recordListOut) {
			fmt.Println("Certificate records:")
			trows := make([][]string, len(o.Certs))
			for i, r := range o.Certs {
				text := "excluded"
				if r.IncludeDNS {
					text = "included"
					if r.IP != "" {
						text = r.IP
					}
				}
				dns := text
				if r.IncludeDNS {
					dns = green(text)
				}
				trows[i] = []string{coloredStatus(r.Status), r.Kind, r.CN, r.NotAfter.Format("2006-01-02"), dns, r.Serial}
			}
			printTable([]string{"STATUS", "KIND", "CN", "EXPIRES", "DNS", "SERIAL"}, trows)
			fmt.Println("Custom records:")
			fmt.Print(o.Custom)
		})
	}
}

func cmdRecordEdit(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		pp := dataPaths(ctx.dataDir)
		ctx.openStore().Close() // guarantees dns/ (and everything else) exists before the read/write below
		cur, _ := os.ReadFile(pp.CustomHosts)
		out, err := editText(string(cur))
		die(err)
		if out == string(cur) {
			output(msg("no change"), printMsg)
			return
		}
		die(api.WriteAtomicHosts(pp.CustomHosts, []byte(out)))
		s := ctx.openStore()
		s.Audit("cli", "dns_custom_change", "")
		s.Close()
		output(msg("saved"), printMsg)
	}
}

// cmdRecordIncludeExclude: one body shared by both ops (mirrors `user
// enable|disable`), parameterized by op since the only difference is which.
func cmdRecordIncludeExclude(op string) opBody {
	return func(ifs *flag.FlagSet) func(ctx *cliContext) {
		cn := ifs.String("cn", "", "certificate CN (required)")
		return func(ctx *cliContext) {
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

// recordBodies wires record's ops through opDispatch.
var recordBodies = map[string]opBody{
	"list": cmdRecordList, "edit": cmdRecordEdit,
	"include": cmdRecordIncludeExclude("include"), "exclude": cmdRecordIncludeExclude("exclude"),
}

// cmdRecord manages the Records tab: list certs.hosts/custom.hosts, edit
// custom.hosts in $EDITOR, or include/exclude a CN (mirrors `user enable|disable`).
func cmdRecord(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("record", recordOps, recordOpDesc, recordBodies)(ctx, fs.Args())
	}
}

// upstreamsReady dies with a clear error if nftables isn't usable — same
// "fails cleanly without it" treatment dns commands get without dnsmasq.
func upstreamsReady() {
	if _, path, _ := controller.NftablesVersion(); !upstream.Enabled(path) {
		die(fmt.Errorf("upstreams disabled: nftables not found on PATH, or OVCP_UPSTREAMS_ENABLED=false"))
	}
}

// applyUpstreamsCLI relays through a running serve at sock (preserves its
// live tracker); direct-applies as a fallback when serve isn't running.
// Never fails — caller prints the returned warning.
func applyUpstreamsCLI(s *store.Store, cfg upstream.Config, sock string) string {
	if err := controller.UpstreamReapply(sock); err != nil {
		raw, _ := s.GetSetting("vpn_config")
		upstream.Apply(cfg, ovpnconf.Load(raw).Subnet) // best-effort; warning below covers the result either way
	}
	return upstream.Warning(cfg.Upstreams)
}

// warnUpstream prints w to stderr if non-empty — same shape as warnDNSLeak.
func warnUpstream(w string) {
	if w != "" {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

// saveAndApplyUpstreamsCLI mirrors api.saveAndApplyUpstreams for the CLI's
// three plain mutators (add/del/set-default): persist, reapply (warning
// printed here), audit — the one tail all three share.
func saveAndApplyUpstreamsCLI(s *store.Store, cfg upstream.Config, action, detail string) {
	die(api.SaveUpstreamConfig(s, cfg))
	warnUpstream(applyUpstreamsCLI(s, cfg, ctrlSock()))
	s.Audit("cli", action, detail)
}

type upstreamStatusOut struct {
	Enabled    bool   `json:"enabled"`
	NftVersion string `json:"nftVersion,omitempty"`
	NftPath    string `json:"nftPath,omitempty"`
	Default    string `json:"default,omitempty"`
}

// upstreamOut is one upstream row for both `list -json` and `reconcile
// -json` — explicit, lowercase-tagged fields, this CLI's standard -json
// shape (certOut/recordOut), not upstream.Config's own bare REST shape.
type upstreamOut struct {
	ID          string `json:"id"`
	Up          bool   `json:"up"`
	Iface       string `json:"iface,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	SOCKS       string `json:"socks,omitempty"`
	Table       int    `json:"table"`
	Description string `json:"description,omitempty"`
}

type upstreamListOut struct {
	Upstreams []upstreamOut     `json:"upstreams"`
	Default   string            `json:"default,omitempty"`
	PerCN     map[string]string `json:"perCN,omitempty"`
}

// buildUpstreamListOut computes live up/down status once — the one place
// list/reconcile derive both their -json payload and text table from.
func buildUpstreamListOut(cfg upstream.Config) upstreamListOut {
	rows := make([]upstreamOut, len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		rows[i] = upstreamOut{u.ID, u.IsUp(), u.Iface, u.Gateway, upstream.RedactSOCKS(u.SOCKS), u.Table, u.Description}
	}
	return upstreamListOut{rows, cfg.Default, cfg.PerCN}
}

// upStatus is the "up"/"down" text coloredStatus keys off, shared by list/reconcile.
func upStatus(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func cmdUpstreamStatus(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		ver, path, _ := controller.NftablesVersion()
		out := upstreamStatusOut{
			Enabled:    upstream.Enabled(path),
			NftVersion: ver, NftPath: path, Default: api.LoadUpstreamConfig(s).Default,
		}
		output(out, func(o upstreamStatusOut) {
			if !o.Enabled {
				fmt.Println("upstreams: disabled (nftables not found, or OVCP_UPSTREAMS_ENABLED=false)")
				return
			}
			fmt.Println("upstreams: enabled,", o.NftVersion)
			if o.Default == "" {
				fmt.Println("default: off (host's own default route)")
			} else {
				fmt.Println("default:", o.Default)
			}
		})
	}
}

func cmdUpstreamList(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		cfg := api.LoadUpstreamConfig(s)
		output(buildUpstreamListOut(cfg), func(r upstreamListOut) {
			fmt.Println("Upstreams:")
			trows := make([][]string, len(r.Upstreams))
			for i, u := range r.Upstreams {
				iface, gw := u.Iface, u.Gateway
				if gw == "" {
					gw = "onlink"
				}
				if u.SOCKS != "" {
					iface, gw = "(socks)", u.SOCKS
				}
				id := u.ID
				if u.ID == r.Default {
					id += green(" (default)")
				}
				trows[i] = []string{id, coloredStatus(upStatus(u.Up)), iface, gw, fmt.Sprintf("%d", u.Table), u.Description}
			}
			printTable([]string{"ID", "STATUS", "IFACE", "GATEWAY/SOCKS", "TABLE", "DESCRIPTION"}, trows)
			if len(r.PerCN) > 0 {
				cns := make([]string, 0, len(r.PerCN))
				for cn := range r.PerCN {
					cns = append(cns, cn)
				}
				slices.Sort(cns)
				fmt.Println("Per-CN overrides:")
				perCNRows := make([][]string, len(cns))
				for i, cn := range cns {
					perCNRows[i] = []string{cn, r.PerCN[cn]}
				}
				printTable([]string{"CN", "UPSTREAM"}, perCNRows)
			}
		})
	}
}

func cmdUpstreamAdd(afs *flag.FlagSet) func(ctx *cliContext) {
	id := afs.String("id", "", "short name (required)")
	iface := afs.String("iface", "", "egress interface, e.g. eth1, wg0")
	gateway := afs.String("gateway", "", "next-hop IP (empty = onlink); -iface mode only")
	socks := afs.String("socks", "", "socks5://[user:pass@]host:port backend (Tor, proxychains, self-hosted); mutually exclusive with -iface/-gateway")
	dialTimeout := afs.Int("dial-timeout", 0, "TCP connect timeout in seconds, 0 = server default; -socks mode only")
	handshakeTimeout := afs.Int("handshake-timeout", 0, "SOCKS negotiation timeout in seconds, 0 = server default (higher for Tor, lower for a fast/local backend); -socks mode only")
	desc := afs.String("desc", "", "description")
	return func(ctx *cliContext) {
		upstreamsReady()
		if *id == "" {
			die(fmt.Errorf("-id required"))
		}
		if (*iface == "") == (*socks == "") {
			die(fmt.Errorf("exactly one of -iface or -socks required"))
		}
		if *socks != "" && *gateway != "" {
			die(fmt.Errorf("-gateway is not valid with -socks"))
		}
		if *socks == "" && (*dialTimeout != 0 || *handshakeTimeout != 0) {
			die(fmt.Errorf("-dial-timeout/-handshake-timeout are only valid with -socks"))
		}
		s := ctx.openStore()
		defer s.Close()
		cfg, added, err := api.LoadUpstreamConfig(s).WithAdded(upstream.Upstream{
			ID: *id, Iface: *iface, Gateway: *gateway, SOCKS: *socks,
			DialTimeout: *dialTimeout, HandshakeTimeout: *handshakeTimeout,
			Description: *desc,
		})
		die(err)
		saveAndApplyUpstreamsCLI(s, cfg, "upstream_add", *id)
		output(msg("added: %s (table %d)", *id, added.Table), printMsg)
	}
}

func cmdUpstreamDel(dfs *flag.FlagSet) func(ctx *cliContext) {
	id := dfs.String("id", "", "upstream id (required)")
	return func(ctx *cliContext) {
		upstreamsReady()
		if *id == "" {
			die(fmt.Errorf("-id required"))
		}
		s := ctx.openStore()
		defer s.Close()
		cfg, found := api.LoadUpstreamConfig(s).Without(*id)
		if !found {
			die(fmt.Errorf("upstream %q not found", *id))
		}
		saveAndApplyUpstreamsCLI(s, cfg, "upstream_del", *id)
		output(msg("deleted: %s", *id), printMsg)
	}
}

func cmdUpstreamSetDefault(sfs *flag.FlagSet) func(ctx *cliContext) {
	id := sfs.String("id", "", "upstream id, empty turns it off")
	clear := sfs.Bool("clear", false, "turn off the default (same as -id \"\")")
	return func(ctx *cliContext) {
		upstreamsReady()
		if *clear {
			*id = ""
		}
		s := ctx.openStore()
		defer s.Close()
		cfg, err := api.LoadUpstreamConfig(s).SetDefault(*id)
		die(err)
		action := "upstream_default_set"
		if *id == "" {
			action = "upstream_default_off"
		}
		saveAndApplyUpstreamsCLI(s, cfg, action, *id)
		text := "default: " + *id
		if *id == "" {
			text = "default: off (host's own default route)"
		}
		output(msg("%s", text), printMsg)
	}
}

func cmdUpstreamAssign(afs *flag.FlagSet) func(ctx *cliContext) {
	cn := afs.String("cn", "", "client CN (required)")
	id := afs.String("id", "", "upstream id to assign")
	clear := afs.Bool("clear", false, "clear this CN's override, fall back to default")
	ctrl := ctrlFlag(afs, "")
	return func(ctx *cliContext) {
		upstreamsReady()
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		if *clear == (*id != "") {
			die(fmt.Errorf("exactly one of -id or -clear required"))
		}
		s := ctx.openStore()
		defer s.Close()
		before := api.UpstreamAuthActive(s)
		cfg, err := api.LoadUpstreamConfig(s).Assign(*cn, *id, *clear)
		die(err)
		warning, err := api.ApplyAssign(s, dataPaths(ctx.dataDir).ServerConf, true, before, cfg, *id)
		die(err)
		warnUpstream(warning)
		action := "upstream_assign"
		if *clear {
			action = "upstream_unassign"
		}
		s.Audit("cli", action, *cn)
		// Best-effort: instantly rewrites an already-connected client's live
		// rule; unreachable serve just means it applies on next reconnect.
		if err := controller.UpstreamAssign(*ctrl, *cn); err != nil {
			slog.Warn("upstream assign: live rewrite skipped", "cn", *cn, "err", err)
		}
		text := fmt.Sprintf("assigned: %s -> %s", *cn, *id)
		if *clear {
			text = "cleared: " + *cn
		}
		output(msg("%s", text), printMsg)
	}
}

func cmdUpstreamReconcile(rfs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := ctrlFlag(rfs, "")
	return func(ctx *cliContext) {
		upstreamsReady()
		s := ctx.openStore()
		defer s.Close()
		cfg := api.LoadUpstreamConfig(s)
		warnUpstream(applyUpstreamsCLI(s, cfg, *ctrl))
		s.Audit("cli", "upstream_reconcile", "")
		output(buildUpstreamListOut(cfg), func(r upstreamListOut) {
			inUse := make(map[string]bool, len(r.PerCN)+1)
			if r.Default != "" {
				inUse[r.Default] = true
			}
			for _, id := range r.PerCN {
				inUse[id] = true
			}
			trows := make([][]string, len(r.Upstreams))
			for i, u := range r.Upstreams {
				note := ""
				if !u.Up && inUse[u.ID] {
					note = "actively routed, traffic is being kill-switched"
				}
				trows[i] = []string{u.ID, coloredStatus(upStatus(u.Up)), note}
			}
			printTable([]string{"ID", "STATUS", "NOTE"}, trows)
		})
	}
}

// upstreamBodies wires upstream's ops through opDispatch.
var upstreamBodies = map[string]opBody{
	"status": cmdUpstreamStatus, "list": cmdUpstreamList, "add": cmdUpstreamAdd,
	"del": cmdUpstreamDel, "set-default": cmdUpstreamSetDefault,
	"assign": cmdUpstreamAssign, "reconcile": cmdUpstreamReconcile,
}

func cmdUpstream(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("upstream", upstreamOps, upstreamOpDesc, upstreamBodies)(ctx, fs.Args())
	}
}

// recordOut is certOut plus the fields `list -json` needs beyond it.
type recordOut struct {
	certOut
	IncludeDNS bool   `json:"includeDNS"`
	IP         string `json:"ip,omitempty"`
}

type recordListOut struct {
	Certs  []recordOut `json:"certs"`
	Custom string      `json:"custom"`
}

// activeCertByCN finds cn's active client cert. Client-only: the server's
// DNS line is unconditional, so its row acts not-found here too.
func activeCertByCN(certs []store.Cert, cn string) (store.Cert, bool) {
	for _, c := range certs {
		if c.CN == cn && c.RevokedAt == nil && c.Kind == "client" {
			return c, true
		}
	}
	return store.Cert{}, false
}

// procOpBody registers a lifecycle op's one flag (-ctrl) and returns its
// closure — the one place it's declared, runProcOp and completion alike.
func procOpBody(name, op, wirePrefix string) opBody {
	return func(fs *flag.FlagSet) func(ctx *cliContext) {
		ctrl := ctrlFlag(fs, "")
		return func(ctx *cliContext) {
			r, err := controller.Control(*ctrl, wirePrefix+op)
			die(err)
			if op != "status" { // status is read-only, don't audit
				s := ctx.openStore()
				s.Audit("cli", name+"_"+op, fmt.Sprintf("pid=%d", r.Pid))
				s.Close()
			}
			output(r, func(r controller.ControlResult) { printProcText(name, op, r) })
		}
	}
}

// runProcOp executes one already-resolved lifecycle op against the control
// socket — shared by procCmd (dns) and cmdVPN (vpn, which special-cases
// kill/config before falling through to this).
func runProcOp(ctx *cliContext, name, op string, rest []string, wirePrefix string) {
	ofs := newFlags(name + " " + op)
	body := procOpBody(name, op, wirePrefix)(ofs)
	ofs.Parse(rest)
	body(ctx)
}

// dnsConfigBodies wires dns's config sub-ops through opDispatch — same
// GET/POST /api/dns/config the web UI's Records tab uses.
var dnsConfigBodies = map[string]opBody{
	"get": cmdDNSConfigGet, "set": cmdDNSConfigSet,
}

// dnsBodies/dnsNested back completion for dns's ops — same procOpBody/
// dnsConfigBodies real dispatch already runs through.
var dnsBodies = map[string]opBody{
	"start": procOpBody("dns", "start", "dns-"), "stop": procOpBody("dns", "stop", "dns-"),
	"restart": procOpBody("dns", "restart", "dns-"), "status": procOpBody("dns", "status", "dns-"),
}
var dnsNested = map[string]nestedDispatch{"config": {ops: dnsConfigOps, bodies: dnsConfigBodies}}

// cmdDNS drives the dnsmasq worker's lifecycle, plus `config` (settings, not
// a lifecycle op) — mirrors cmdVPN's kill/config special-cases.
func cmdDNS(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "dns", dnsOps, dnsOpDesc)
		if op == "config" {
			opDispatch("dns config", dnsConfigOps, configOpDesc, dnsConfigBodies)(ctx, rest)
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

// vpnConfigBodies wires vpn's config sub-ops through opDispatch — get/set
// mirror the web UI's GET/PUT /api/vpn/config exactly (same ovpnconf.Config,
// same wire shape).
var vpnConfigBodies = map[string]opBody{
	"get": cmdVPNConfigGet, "set": cmdVPNConfigSet,
	"preview": cmdVPNConfigPreview,
}

// vpnBodies/vpnNested back completion for vpn's ops — same procOpBody/
// cmdKill/vpnConfigBodies real dispatch already runs through.
var vpnBodies = map[string]opBody{
	"start": procOpBody("vpn", "start", ""), "stop": procOpBody("vpn", "stop", ""),
	"restart": procOpBody("vpn", "restart", ""), "reconnect": procOpBody("vpn", "reconnect", ""),
	"status": procOpBody("vpn", "status", ""), "kill": cmdKill,
}
var vpnNested = map[string]nestedDispatch{"config": {ops: vpnConfigOps, bodies: vpnConfigBodies}}

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
			opDispatch("vpn config", vpnConfigOps, configOpDesc, vpnConfigBodies)(ctx, rest)
		default:
			runProcOp(ctx, "vpn", op, rest, "")
			if op == "start" {
				if w := controller.RoutingPrereqsWarning(); w != "" {
					fmt.Fprintln(os.Stderr, "warning:", w)
				}
			}
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

// editText opens initial in $EDITOR (default vi, run by the shell so it may
// carry arguments) in a private temp file, and returns what was saved.
func editText(initial string) (string, error) {
	f, err := os.CreateTemp("", "ovcp-edit-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(initial)
	if err = errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	cmd := exec.Command("sh", "-c", `${EDITOR:-vi} "$1"`, "sh", f.Name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("editor: %w", err)
	}
	out, err := os.ReadFile(f.Name())
	return string(out), err
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
			var err error
			if cfg.Extra, err = editText(cfg.Extra); err != nil {
				return cfg, err
			}
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
// CLI twin; -extra - opens $EDITOR inline, no separate `edit` op to drift.
// An empty diff never writes or audits, whether from no flags, unchanged values, or a no-op $EDITOR session.
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

// caBodies wires ca's ops through opDispatch — the most sensitive surface,
// deliberately CLI-only, kept on its own top-level menu instead of folded
// into `certificate` (the CA isn't a certs-table row, see store's schema).
var caBodies = map[string]opBody{
	"rotate": cmdRotateCA, "renew": cmdRenewCA, "status": cmdCAStatus,
}

func cmdCA(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("ca", caOps, caOpDesc, caBodies)(ctx, fs.Args())
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
			fmt.Printf("%s  %s expires %s\n", o.CN, coloredStatus(o.Status), o.NotAfter.Format("2006-01-02"))
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
func cmdBackupCreate(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		if jsonOut {
			die(fmt.Errorf("-json is not supported for backup create (the archive is the output)"))
		}
		if term.IsTerminal(int(os.Stdout.Fd())) {
			die(fmt.Errorf("refusing to write the archive to a terminal; redirect stdout to a file"))
		}
		pass := readSecret("Backup passphrase", "OVCP_BACKUP_PASSPHRASE", true)
		s := ctx.openStore()
		defer s.Close()
		die(backup.Create(ctx.dataDir, s, os.Stdout, pass))
		s.Audit("cli", "backup_create", "")
		fmt.Fprintln(os.Stderr, "backup written; keep the passphrase safe: it cannot be recovered, and the archive is unreadable without it")
	}
}

func cmdBackupRestore(rfs *flag.FlagSet) func(ctx *cliContext) {
	force := rfs.Bool("force", false, "overwrite an already-initialized data directory")
	return func(ctx *cliContext) {
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

// backupBodies wires backup's ops through opDispatch.
var backupBodies = map[string]opBody{"create": cmdBackupCreate, "restore": cmdBackupRestore}

func cmdBackup(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("backup", backupOps, backupOpDesc, backupBodies)(ctx, fs.Args())
	}
}

// cmdDebugOp: one body shared by "on"/"off" (same single -ctrl flag),
// parameterized by op.
func cmdDebugOp(op string) opBody {
	return func(ofs *flag.FlagSet) func(ctx *cliContext) {
		ctrl := ctrlFlag(ofs, "")
		return func(ctx *cliContext) {
			_, err := controller.Control(*ctrl, "debug "+op)
			die(err)
			output(map[string]bool{"debug": op == "on"}, func(o map[string]bool) {
				fmt.Println("debug logging", op)
			})
		}
	}
}

// debugBodies wires debug's ops through opDispatch.
var debugBodies = map[string]opBody{"on": cmdDebugOp("on"), "off": cmdDebugOp("off")}

func cmdDebug(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("debug", debugOps, debugOpDesc, debugBodies)(ctx, fs.Args())
	}
}

// telegramConfigBodies wires telegram's config sub-ops through opDispatch —
// same GET/PUT /api/telegram/config the web UI uses.
var telegramConfigBodies = map[string]opBody{
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

// cmdTelegramConfigSet: token and admin are independently optional — -token
// is a flag, not a value, since a secret has no business on the command line.
// Admin applies before token: SetToken wipes the chat id on any real change, so setting both needs SetAdmin's goodbye message sent first.
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

// telegramLifecycleBody registers one telegram lifecycle op's -ctrl flag —
// same shape procOpBody uses for vpn/dns, kept separate since telegram
// calls its own TelegramStart/Stop/Restart/GetStatus, not controller.Control.
func telegramLifecycleBody(op string) opBody {
	return func(fs *flag.FlagSet) func(ctx *cliContext) {
		ctrl := ctrlFlag(fs, "")
		return func(ctx *cliContext) {
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
}

// telegramBodies/telegramNested back completion for telegram's ops — same
// telegramLifecycleBody/telegramConfigBodies real dispatch already runs through.
var telegramBodies = map[string]opBody{
	"start": telegramLifecycleBody("start"), "stop": telegramLifecycleBody("stop"),
	"restart": telegramLifecycleBody("restart"), "status": telegramLifecycleBody("status"),
}
var telegramNested = map[string]nestedDispatch{"config": {ops: telegramConfigOps, bodies: telegramConfigBodies}}

func cmdTelegram(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		op, rest := opArg(fs, "telegram", telegramOps, telegramOpDesc)
		if op == "config" {
			opDispatch("telegram config", telegramConfigOps, configOpDesc, telegramConfigBodies)(ctx, rest)
			return
		}
		ofs := newFlags("telegram " + op)
		body := telegramBodies[op](ofs)
		ofs.Parse(rest)
		body(ctx)
	}
}

func cmdUserAdd(afs *flag.FlagSet) func(ctx *cliContext) {
	name := afs.String("name", "", "username (required)")
	role := afs.String("role", "operator", "admin|operator|readonly")
	return func(ctx *cliContext) {
		if *name == "" || !auth.ValidRole(*role) {
			die(fmt.Errorf("-name required; role admin|operator|readonly"))
		}
		pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
		h, err := auth.HashPassword(pw)
		die(err)
		s := ctx.openStore()
		defer s.Close()
		_, err = s.AddUser(*name, h, *role)
		die(err)
		s.Audit("cli", "user_add", "name="+*name+" role="+*role)
		output(userAddOut{*name, *role}, func(o userAddOut) {
			fmt.Println("user added:", o.Username, "("+o.Role+")")
		})
	}
}

func cmdUserList(lfs *flag.FlagSet) func(ctx *cliContext) {
	status := lfs.String("status", "all", "all|enabled|disabled")
	role := lfs.String("role", "all", "all|admin|operator|readonly")
	sortBy := lfs.String("sort", "", "username|role|created|status|2fa (default: today's order)")
	desc := lfs.Bool("desc", false, "reverse sort order")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
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
			trows := make([][]string, len(rows))
			for i, u := range rows {
				status := "enabled"
				if u.Disabled {
					status = "disabled"
				}
				tf := "-"
				if u.TOTP {
					tf = "2fa"
				}
				trows[i] = []string{u.Username, u.Role, coloredStatus(status), tf, u.CreatedAt.Format("2006-01-02")}
			}
			printTable([]string{"USERNAME", "ROLE", "STATUS", "2FA", "CREATED"}, trows)
		})
	}
}

func cmdUserDel(dfs *flag.FlagSet) func(ctx *cliContext) {
	name := dfs.String("name", "", "username (required)")
	return func(ctx *cliContext) {
		if *name == "" {
			die(fmt.Errorf("-name required"))
		}
		s := ctx.openStore()
		defer s.Close()
		die(s.DeleteUser(*name))
		s.Audit("cli", "user_del", "name="+*name)
		output(msg("deleted: %s", *name), printMsg)
	}
}

// cmdUserEnableDisable: one body shared by both ops, parameterized by op.
func cmdUserEnableDisable(op string) opBody {
	return func(efs *flag.FlagSet) func(ctx *cliContext) {
		name := efs.String("name", "", "username (required)")
		return func(ctx *cliContext) {
			if *name == "" {
				die(fmt.Errorf("-name required"))
			}
			s := ctx.openStore()
			defer s.Close()
			die(s.SetUserDisabled(*name, op == "disable"))
			s.Audit("cli", "user_"+op, "name="+*name)
			output(userDisabledOut{*name, op == "disable"}, func(o userDisabledOut) {
				fmt.Println(op+"d:", o.Username)
			})
		}
	}
}

func cmdUserPasswd(pfs *flag.FlagSet) func(ctx *cliContext) {
	name := pfs.String("name", "", "username (required)")
	return func(ctx *cliContext) {
		if *name == "" {
			die(fmt.Errorf("-name required"))
		}
		pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
		h, err := auth.HashPassword(pw)
		die(err)
		s := ctx.openStore()
		defer s.Close()
		die(s.SetUserPassword(*name, h))
		s.Audit("cli", "user_passwd", "name="+*name)
		output(msg("password updated: %s", *name), printMsg)
	}
}

func cmdUserTOTP(tfs *flag.FlagSet) func(ctx *cliContext) {
	name := tfs.String("name", "", "username (required)")
	off := tfs.Bool("off", false, "disable 2FA")
	return func(ctx *cliContext) {
		if *name == "" {
			die(fmt.Errorf("-name required"))
		}
		s := ctx.openStore()
		defer s.Close()
		if *off {
			die(s.SetUserTOTP(*name, ""))
			s.Audit("cli", "user_totp_off", "name="+*name)
			output(msg("2FA disabled: %s", *name), printMsg)
			return
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

// userBodies wires user's ops through opDispatch.
var userBodies = map[string]opBody{
	"add": cmdUserAdd, "list": cmdUserList, "del": cmdUserDel,
	"disable": cmdUserEnableDisable("disable"), "enable": cmdUserEnableDisable("enable"),
	"passwd": cmdUserPasswd, "totp": cmdUserTOTP,
}

func cmdUser(fs *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		opDispatch("user", userOps, userOpDesc, userBodies)(ctx, fs.Args())
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
			trows := make([][]string, len(tail))
			for i, e := range tail {
				trows[i] = []string{e.TS.Format(time.RFC3339), e.Actor, e.Action, e.Detail}
			}
			printTable([]string{"TIME", "ACTOR", "ACTION", "DETAIL"}, trows)
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
