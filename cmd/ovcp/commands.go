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
		"revoke": "revoke a client cert, regen CRL", "renew": "renew or rename the server cert",
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
		"create": "encrypted archive of CA, config, database, to stdout", "restore": "extract the archive on stdin into -data",
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
		"add":  "define one (-id, -iface [-gateway] | -socks URL, [-desc])",
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
	customOpts := linesFlag(fs, "custom-opts", "-export: one custom client directive per use, a file via $(cat FILE), or - for $EDITOR")
	return func(ctx *cliContext) {
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		s := ctx.openStore()
		defer s.Close()
		req := api.ClientRequest{CN: *cn, Days: *days, KeyPass: *keyPass, Renew: *renew,
			Passphrase: readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)}
		var ic *pki.IssuedCert
		var bundle []byte
		var err error
		if *export {
			if *remote == "" {
				*remote = adminCertCN(ctx.dataDir)
			}
			if *serverCN == "" {
				*serverCN = adminCertCN(ctx.dataDir)
			}
			extra, _, lerr := linesValue(*customOpts, "")
			die(lerr)
			ic, bundle, err = api.ExportClient(s, ctx.p, dataPaths(ctx.dataDir).TLSCrypt, req, api.ExportOpts{
				Remote: *remote, ServerCN: *serverCN, Proto: *proto, Port: *port, Extra: extra, SplitTunnel: *splitTunnel})
		} else {
			ic, err = api.IssueClient(s, ctx.p, req)
		}
		switch {
		case errors.Is(err, store.ErrDuplicateCN):
			err = fmt.Errorf("%w — add -renew to replace it", err)
		case errors.Is(err, store.ErrNoActiveCert):
			err = fmt.Errorf("%w — omit -renew to issue a new one", err)
		}
		die(err)
		if *renew {
			restartSessionsCLI(*cn)
		}
		refreshCertsHostsCLI(ctx.dataDir, s)
		api.AuditClient(s, "cli", req, ic)

		if *export {
			output(api.ExportResult{Serial: ic.SerialHex, Bundle: string(bundle)}, func(o api.ExportResult) {
				fmt.Print(o.Bundle)
				fmt.Fprintln(os.Stderr, "serial:", o.Serial)
			})
			return
		}
		output(api.IssueResult{Serial: ic.SerialHex, Cert: string(ic.CertPEM), Key: string(ic.KeyPEM)}, func(o api.IssueResult) {
			fmt.Print(o.Cert, o.Key)
			fmt.Fprintln(os.Stderr, "serial:", o.Serial)
		})
	}
}

// restartSessionsCLI is Server.restartSessions through a running serve.
func restartSessionsCLI(cn string) {
	if _, err := controller.Kill(ctrlSock(), cn, "RESTART"); err != nil && !errors.Is(err, controller.ErrServeDown) {
		slog.Warn("revoke: live sessions not restarted", "cn", cn, "err", err)
	}
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
		res := must(api.RevokeCert(s, ctx.p, "cli", *serial, pass))
		refreshCertsHostsCLI(ctx.dataDir, s)
		restartSessionsCLI(res.CN)
		output(res, func(o api.RevokeResult) {
			fmt.Println("revoked; CRL regenerated:", o.CRLPath)
		})
	}
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

// msg is a CLI-only command's api.Msg; the shared actions build their own.
func msg(format string, a ...any) api.Msg {
	return api.Msg{Message: fmt.Sprintf(format, a...), Changed: true}
}

// must dies on an action's error, else hands back its result.
func must[T any](v T, err error) T {
	die(err)
	return v
}

// printMsg is api.Msg's text rendering.
func printMsg(o api.Msg) { fmt.Println(o.Message) }

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

// coloredStatus is every command's shared colored status cell. Padding is
// printTable's job now, not this function's — it just colors the word.
func coloredStatus(status string) string {
	switch status {
	case "revoked":
		return red("REVOKED")
	case "expired", "down", "disabled":
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

// visibleWidth: rune count, ANSI stripped first. Padded columns hold names (ASCII by
// pki.CheckName) and fixed words; free text sits in the last column, never padded.
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
		rows := []api.CertRow{}
		for _, c := range out {
			rows = append(rows, api.NewCertRow(c))
		}
		output(rows, func(rows []api.CertRow) {
			trows := make([][]string, len(rows))
			for i, c := range rows {
				trows[i] = []string{coloredStatus(c.Status), c.Kind, c.CN, c.Expires.Format("2006-01-02"), c.Serial}
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
			die(api.WriteServerCert(s, pp.ServerCert, pp.ServerKey, ic))
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
		die(api.SaveConfig(s, cfg))
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
func printStatusText(st api.Status) {
	switch {
	case st.Error != "" && !st.Running:
		fmt.Println("OpenVPN: unknown —", st.Error)
	case !st.Running:
		fmt.Println(red("OpenVPN: stopped"))
	case st.Error != "":
		fmt.Printf("OpenVPN: running (pid %d, up %s)\n", st.Pid, fmtUptime(st.StartedAt))
		fmt.Println("Clients: unavailable —", st.Error)
	default:
		fmt.Println(green(fmt.Sprintf("OpenVPN: running (pid %d, up %s)", st.Pid, fmtUptime(st.StartedAt))))
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
		fmt.Println(green(fmt.Sprintf("DNS: running (pid %d, up %s)", st.DNSPid, fmtUptime(st.DNSStartedAt))))
	default:
		fmt.Println(red("DNS: stopped"))
	}
	if u := fmtUptime(st.ServeStartedAt); u != "" {
		fmt.Println("ovcp: up", u)
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
	if st.RoutingWarning != "" {
		fmt.Println("warning:", st.RoutingWarning)
	}
}

func cmdStatus(fs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := ctrlFlag(fs, "")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		output(api.BuildStatus(s, ctx.p, ctrlSource(*ctrl), upstreamsEnabled()), printStatusText)
	}
}

// ctrlSource is api.StatusSource through a running serve's control socket.
type ctrlSource string

func (c ctrlSource) VPN() (controller.ControlResult, error) {
	return controller.Control(string(c), "status")
}
func (c ctrlSource) DNS() (controller.ControlResult, error) {
	return controller.Control(string(c), "dns-status")
}
func (c ctrlSource) Clients() ([]controller.VPNClient, error) {
	return controller.Clients(string(c))
}
func (c ctrlSource) Telegram() (controller.TelegramStatus, error) {
	return controller.TelegramGetStatus(string(c))
}

func cmdKill(fs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := ctrlFlag(fs, "")
	cn := fs.String("cn", "", "client CN (required)")
	return func(ctx *cliContext) {
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		s := ctx.openStore()
		defer s.Close()
		kill := func(cn, verb string) (int, error) { return controller.Kill(*ctrl, cn, verb) }
		output(must(api.Kill(s, "cli", *cn, kill)), printMsg)
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
		cfg := api.LoadConfig(s)
		s.Close()
		die(err)
		out, err := filterSortCerts(certs, *status, *kind, *sortBy, *desc)
		die(err)
		customData, _ := os.ReadFile(pp.CustomHosts)
		live, _ := controller.Clients(ctrlSock()) // serve down: nothing resolves live
		ip, _ := cfg.ServerTunIP()
		output(api.Records(out, live, adminCertCN(ctx.dataDir), ip, string(customData)), func(o api.RecordList) {
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
				trows[i] = []string{coloredStatus(r.Status), r.Kind, r.CN, r.Expires.Format("2006-01-02"), dns, r.Serial}
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
		s := ctx.openStore() // guarantees dns/ exists before the read below
		defer s.Close()
		cur, _ := os.ReadFile(pp.CustomHosts)
		out, err := editText(string(cur))
		die(err)
		output(must(api.SetCustomHosts(s, "cli", pp.CustomHosts, out)), printMsg)
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
			m := must(api.SetCertDNS(s, "cli", c.Serial, op == "include"))
			if m.Changed {
				refreshCertsHostsCLI(ctx.dataDir, s)
			}
			output(m, printMsg)
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

// upstreamsEnabled: nft found and not opted out — upstream.Enabled for the CLI.
func upstreamsEnabled() bool {
	_, path, _ := controller.NftablesVersion()
	return upstream.Enabled(path)
}

// applyUpstreamsCLI relays through a running serve at sock (preserves its
// live tracker); direct-applies as a fallback when serve isn't running.
// Never fails — caller prints the returned warning.
func applyUpstreamsCLI(cfg upstream.Config, sock string) string {
	if err := controller.UpstreamReapply(sock); err != nil {
		upstream.Apply(cfg) // best-effort; warning below covers the result either way
	}
	return upstream.Warning(cfg.Upstreams)
}

// warnLine prints a result's warning to stderr, if it has one.
func warnLine(w string) {
	if w != "" {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

type upstreamStatusOut struct {
	Enabled    bool   `json:"enabled"`
	NftVersion string `json:"nftVersion,omitempty"`
	NftPath    string `json:"nftPath,omitempty"`
	Default    string `json:"default,omitempty"`
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
		output(api.ViewUpstreams(cfg, ""), func(r api.UpstreamView) {
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
		s := ctx.openStore()
		defer s.Close()
		showUpstreams(api.AddUpstream(s, "cli", upstreamsEnabled(), upstream.Upstream{
			ID: *id, Iface: *iface, Gateway: *gateway, SOCKS: *socks,
			DialTimeout: *dialTimeout, HandshakeTimeout: *handshakeTimeout,
			Description: *desc,
		}, cliApplier))
	}
}

func cmdUpstreamDel(dfs *flag.FlagSet) func(ctx *cliContext) {
	id := dfs.String("id", "", "upstream id (required)")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		showUpstreams(api.DeleteUpstream(s, "cli", upstreamsEnabled(), *id, cliApplier))
	}
}

func cmdUpstreamSetDefault(sfs *flag.FlagSet) func(ctx *cliContext) {
	id := sfs.String("id", "", "upstream id, empty turns it off")
	clear := sfs.Bool("clear", false, "turn off the default (same as -id \"\")")
	return func(ctx *cliContext) {
		if *clear {
			*id = ""
		}
		s := ctx.openStore()
		defer s.Close()
		showUpstreams(api.SetDefaultUpstream(s, "cli", upstreamsEnabled(), *id, cliApplier))
	}
}

func cmdUpstreamAssign(afs *flag.FlagSet) func(ctx *cliContext) {
	cn := afs.String("cn", "", "client CN (required)")
	id := afs.String("id", "", "upstream id to assign")
	clear := afs.Bool("clear", false, "clear this CN's override, fall back to default")
	ctrl := ctrlFlag(afs, "")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		// no serve running: no live rule to rewrite, it applies on reconnect
		rewrite := func(cn string) error {
			if err := controller.UpstreamAssign(*ctrl, cn); !errors.Is(err, controller.ErrServeDown) {
				return err
			}
			return nil
		}
		showUpstreams(api.AssignUpstream(s, "cli", upstreamsEnabled(), dataPaths(ctx.dataDir).ServerConf, *cn, *id, *clear, rewrite))
	}
}

// cliApplier is api.Applier through a running serve, else applied directly.
func cliApplier(cfg upstream.Config) string { return applyUpstreamsCLI(cfg, ctrlSock()) }

// showUpstreams prints an upstream mutation's message, its warning on stderr.
func showUpstreams(v api.UpstreamView, err error) {
	die(err)
	warnLine(v.Warning)
	output(v, func(v api.UpstreamView) { fmt.Println(v.Message) })
}

func cmdUpstreamReconcile(rfs *flag.FlagSet) func(ctx *cliContext) {
	ctrl := ctrlFlag(rfs, "")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		v := must(api.ReconcileUpstreams(s, "cli", upstreamsEnabled(), func(cfg upstream.Config) string { return applyUpstreamsCLI(cfg, *ctrl) }))
		warnLine(v.Warning)
		output(v, func(r api.UpstreamView) {
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

func cmdDNSConfigGet(_ *flag.FlagSet) func(ctx *cliContext) {
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		v := api.ViewDNS(s)
		warnLine(v.Warning)
		output(v, func(v api.DNSView) { fmt.Println("block-internet:", boolText(v.BlockInternet)) })
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
		v := must(api.SetDNSConfig(s, "cli", cfg))
		warnLine(v.Warning)
		output(v, func(v api.DNSView) {
			fmt.Println("block-internet:", boolText(v.BlockInternet), "(restart dns to apply)")
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
				if w := controller.RoutingPrereqsWarning(upstreamsEnabled()); w != "" {
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
		s := ctx.openStore()
		defer s.Close()
		pp := dataPaths(ctx.dataDir)
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		res, err := api.RenewServer(s, ctx.p, pp.ServerCert, pp.ServerKey, "cli", cmp.Or(*cn, adminCertCN(ctx.dataDir)), *days, pass)
		if errors.Is(err, store.ErrNoActiveCert) {
			err = fmt.Errorf("%w — run `ovcp init` first", err)
		}
		die(err)
		output(res, func(o api.RenewResult) {
			fmt.Printf("server cert renewed: %s (cn %s, expires %s)\n", o.Serial, o.CN, o.NotAfter.Format("2006-01-02"))
			fmt.Println("run `ovcp vpn restart` to apply")
			if *cn != "" {
				fmt.Println("the admin UI's own TLS cert keeps the old CN until `ovcp serve` is restarted")
			}
		})
	}
}

// linesFlag is a repeatable flag: each use adds one line, taken verbatim.
func linesFlag(fs *flag.FlagSet, name, usage string) *[]string {
	var v []string
	fs.Func(name, usage, func(s string) error { v = append(v, s); return nil })
	return &v
}

// linesValue joins a linesFlag's lines, or edits initial in $EDITOR for a lone
// "-"; ok is false when the flag was never given.
func linesValue(v []string, initial string) (s string, ok bool, err error) {
	if len(v) == 1 && v[0] == "-" {
		s, err = editText(initial)
		return s, true, err
	}
	return strings.Join(v, "\n"), len(v) > 0, nil
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
		output(api.LoadConfig(s), printConfigText)
		warnLine(api.ViewDNS(s).Warning)
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
	extra := linesFlag(fs, "extra", "one custom directive per use, a file via $(cat FILE), or - for $EDITOR (unchanged if omitted)")
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
		if s, ok, err := linesValue(*extra, cfg.Extra); err != nil {
			return cfg, err
		} else if ok {
			cfg.Extra = s
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
		cfg, err := apply(api.LoadConfig(s))
		die(err)
		diff, err := api.SetVPNConfig(s, dataPaths(ctx.dataDir).ServerConf, cfg)
		die(err)
		if len(diff) == 0 {
			output(cfg, func(c ovpnconf.Config) { printDiff(diff) })
			return
		}
		s.Audit("cli", "config_change", "")
		warnLine(api.ViewDNS(s).Warning)
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
		cfg, err := apply(api.LoadConfig(s))
		die(err)
		pv := must(api.PreviewVPNConfig(s, cfg))
		warnLine(pv.Warning)
		output(pv, func(o api.Preview) { printDiff(o.Diff) })
	}
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
		if rfs.NArg() > 0 || term.IsTerminal(int(os.Stdin.Fd())) {
			die(fmt.Errorf("usage: ovcp backup restore [-force] < ARCHIVE"))
		}
		pass := readSecret("Backup passphrase", "OVCP_BACKUP_PASSPHRASE", false)
		die(backup.Restore(ctx.dataDir, os.Stdin, pass, *force))
		output(msg("restored CA, CRL, tls-crypt key, config, and database into %s; "+
			"next: OVCP_SERVER_CN=<host> ovcp certificate renew, then ovcp vpn start", ctx.dataDir),
			func(o api.Msg) {
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
			die(controller.Debug(*ctrl, op == "on"))
			s := ctx.openStore()
			s.Audit("cli", "debug_"+op, "")
			s.Close()
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
		pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
		s := ctx.openStore()
		defer s.Close()
		output(must(api.AddUser(s, "cli", *name, pw, *role)), printMsg)
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
		s := ctx.openStore()
		defer s.Close()
		output(must(api.DeleteUser(s, "cli", *name)), printMsg)
	}
}

// cmdUserEnableDisable: one body shared by both ops, parameterized by op.
func cmdUserEnableDisable(op string) opBody {
	return func(efs *flag.FlagSet) func(ctx *cliContext) {
		name := efs.String("name", "", "username (required)")
		return func(ctx *cliContext) {
			s := ctx.openStore()
			defer s.Close()
			output(must(api.SetUserDisabled(s, "cli", *name, op == "disable")), printMsg)
		}
	}
}

func cmdUserPasswd(pfs *flag.FlagSet) func(ctx *cliContext) {
	name := pfs.String("name", "", "username (required)")
	return func(ctx *cliContext) {
		pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
		s := ctx.openStore()
		defer s.Close()
		output(must(api.SetUserPassword(s, "cli", *name, pw)), printMsg)
	}
}

func cmdUserTOTP(tfs *flag.FlagSet) func(ctx *cliContext) {
	name := tfs.String("name", "", "username (required)")
	off := tfs.Bool("off", false, "disable 2FA")
	return func(ctx *cliContext) {
		s := ctx.openStore()
		defer s.Close()
		if *off {
			output(must(api.DisableTOTP(s, "cli", *name)), printMsg)
			return
		}
		enr := must(api.EnrollTOTP(s, "cli", *name, adminCertCN(ctx.dataDir)))
		output(enr, func(o api.TOTPEnrollment) {
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
		// the controlling terminal, not stdin: stdin and stdout stay free for data
		prompt := func(p string) []byte {
			tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				die(fmt.Errorf("%s: no terminal to prompt on; set %s", label, env))
			}
			defer tty.Close()
			fmt.Fprint(tty, p+": ")
			b, err := term.ReadPassword(int(tty.Fd()))
			fmt.Fprintln(tty)
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
