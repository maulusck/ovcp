package main

// Black-box CLI tests: main() calls die() (os.Exit(1)), unsafe in-process, so
// these drive the compiled binary as a subprocess. serve/vpn start spawning
// real openvpn against real upstreams is covered in upstream_test.go.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/store"
)

var binPath string

func TestMain(m *testing.M) {
	if mode := os.Getenv(e2eHelperEnv); mode != "" {
		runE2EHelper(mode, os.Getenv("OVCP_E2E_HELPER_ADDR"))
		return
	}
	dir, err := os.MkdirTemp("", "ovcp-test-bin")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "ovcp")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("build ovcp: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

func run(t *testing.T, env []string, args ...string) result {
	t.Helper()
	return runIn(t, env, nil, args...)
}

// runIn is run with stdin. Every invocation gets its own session, so the
// binary never has a controlling terminal to prompt on.
func runIn(t *testing.T, env []string, stdin []byte, args ...string) result {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("exec %v: %v", args, err)
	}
	return result{stdout.String(), stderr.String(), code}
}

// baseEnv gives one test its own data dir and non-interactive secrets.
func baseEnv(t *testing.T) []string {
	return []string{
		"OVCP_DATA=" + t.TempDir(),
		"OVCP_CA_PASSPHRASE=correct horse battery staple",
		"OVCP_USER_PASSWORD=admin-password-1",
	}
}

func dataDir(env []string) string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "OVCP_DATA="); ok {
			return v
		}
	}
	return ""
}

func withEnv(env []string, extra ...string) []string {
	return append(append([]string{}, env...), extra...)
}

// certLines returns list's rows containing substr (kind or CN column).
func certLines(stdout, substr string) []string {
	var out []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return out
}

func serialOf(t *testing.T, line string) string {
	t.Helper()
	f := strings.Fields(line)
	if len(f) == 0 {
		t.Fatalf("no fields in line %q", line)
	}
	return f[len(f)-1]
}

func TestVersionAndUsage(t *testing.T) {
	if r := run(t, nil, "version"); r.code != 0 || !strings.Contains(r.stdout, "ovcp") {
		t.Fatalf("version: %+v", r)
	}
	if r := run(t, nil); r.code != 2 || !strings.Contains(r.stderr, "ovcp <command>") {
		t.Fatalf("no-args usage: %+v", r)
	}
	if r := run(t, nil, "bogus-command"); r.code != 2 || !strings.Contains(r.stderr, "ovcp <command>") {
		t.Fatalf("unknown command usage: %+v", r)
	}
}

// TestJSONEnvVar: $OVCP_JSON must switch output on exactly like -json, no
// flag needed — same pattern as $NO_COLOR.
func TestJSONEnvVar(t *testing.T) {
	r := run(t, []string{"OVCP_JSON=1"}, "version")
	if r.code != 0 {
		t.Fatalf("OVCP_JSON=1 version: %+v", r)
	}
	if err := json.Unmarshal([]byte(r.stdout), &versionOut{}); err != nil {
		t.Fatalf("OVCP_JSON=1 should produce JSON, got: %+v", r)
	}
}

// TestVersionJSON: -json version must parse, always carrying a version
// (openvpn fields are omitempty, absent rather than null when not on PATH).
func TestVersionJSON(t *testing.T) {
	r := run(t, nil, "-json", "version")
	if r.code != 0 {
		t.Fatalf("-json version: %+v", r)
	}
	var out versionOut
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.Version == "" {
		t.Fatalf("-json version unmarshal: %v: %+v", err, r)
	}
}

// TestJSONErrors guards die()'s -json branch: a fatal error must land as
// {"error":"..."} on stdout, not stderr's plain text, so scripts get a consistent shape on failure too.
func TestJSONErrors(t *testing.T) {
	r := run(t, nil, "-json", "certificate", "revoke")
	if r.code == 0 {
		t.Fatalf("revoke without -serial should fail: %+v", r)
	}
	var out struct{ Error string }
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.Error == "" {
		t.Fatalf("-json error shape: %v: %+v", err, r)
	}
	if r.stderr != "" {
		t.Fatalf("-json error must not also print to stderr: %+v", r)
	}
}

// assertCleanJSON: r succeeded, stdout is exactly one JSON value unmarshaling
// into v, and nothing leaked to stderr — the env-var/-json automation
// contract every command must honor, not just the ones TestJSONFullAutomation walks end to end.
func assertCleanJSON(t *testing.T, r result, v any) {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("want success: %+v", r)
	}
	if r.stderr != "" {
		t.Fatalf("secret from env must never prompt/print to stderr: %+v", r)
	}
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		t.Fatalf("stdout must be exactly one clean JSON value: %v: %+v", err, r)
	}
}

// TestJSONFullAutomation is the "Ansible module" scenario: every secret via
// env var, -json throughout, no tty. Guards that no command leaks prompt text onto stdout or writes to stderr on success.
func TestJSONFullAutomation(t *testing.T) {
	env := withEnv(baseEnv(t), "OVCP_JSON=1")

	assertCleanJSON(t, run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", "admin"), &initOut{})
	assertCleanJSON(t, run(t, env, "certificate", "issue", "-cn", "alice"), &issueOut{})

	var rows []certOut
	assertCleanJSON(t, run(t, env, "certificate", "list"), &rows)
	var serial string
	for _, c := range rows {
		if c.CN == "alice" {
			serial = c.Serial
		}
	}
	if serial == "" {
		t.Fatalf("alice not found in list output: %+v", rows)
	}
	assertCleanJSON(t, run(t, env, "certificate", "revoke", "-serial", serial), &revokeOut{})
	assertCleanJSON(t, run(t, env, "certificate", "renew"), &renewOut{})

	rotate := withEnv(env, "OVCP_CA_NEW_PASSPHRASE=a totally different passphrase")
	assertCleanJSON(t, run(t, rotate, "ca", "rotate"), &outcome{})

	create := withEnv(env, "OVCP_BACKUP_PASSPHRASE=backup-pass-123")
	if r := run(t, create, "backup", "create"); r.code == 0 || !strings.Contains(r.stdout, `"error"`) {
		t.Fatalf("backup create must refuse -json (the archive is the output): %+v", r)
	}

	addBob := withEnv(env, "OVCP_USER_PASSWORD=bobs-password-1")
	assertCleanJSON(t, run(t, addBob, "user", "add", "-name", "bob", "-role", "operator"), &userAddOut{})
}

// TestJSONMissingSecretNoTTY backs "no env var, no terminal: fails fast, on
// any command" — covering readSecret's confirm=false and confirm=true shapes covers every call site.
func TestJSONMissingSecretNoTTY(t *testing.T) {
	env := withEnv(baseEnv(t), "OVCP_JSON=1")
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	noSecrets := []string{"OVCP_DATA=" + dataDir(env), "OVCP_JSON=1"}

	for _, args := range [][]string{
		{"certificate", "issue", "-cn", "alice"}, // confirm=false: one prompt
		{"ca", "rotate"},                         // confirm=true: prompt + confirm
	} {
		r := run(t, noSecrets, args...)
		if r.code == 0 {
			t.Fatalf("%v with no secret available should fail, not hang: %+v", args, r)
		}
		var out struct{ Error string }
		if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.Error == "" {
			t.Fatalf("%v: want a clean JSON error, got: %v: %+v", args, err, r)
		}
	}
}

// TestHelp: -h and --help print the command list and exit 0.
func TestHelp(t *testing.T) {
	for _, f := range []string{"-h", "--help"} {
		if r := run(t, nil, f); r.code != 0 || !strings.Contains(r.stderr, "ovcp <command>") {
			t.Fatalf("%s: %+v", f, r)
		}
	}
}

// TestEveryCommandHelp is the whole-CLI-surface guard: every command in the
// table must have a working, non-empty -h that names itself, table-driven so
// new commands are covered for free (user/backup/telegram's -h used to print nothing).
func TestEveryCommandHelp(t *testing.T) {
	for _, c := range commands {
		r := run(t, nil, c.name, "-h")
		if r.code != 0 {
			t.Errorf("%s -h: exit=%d, want 0: %+v", c.name, r.code, r)
		}
		if !strings.Contains(r.stderr, "usage: ovcp "+c.name) {
			t.Errorf("%s -h: stderr doesn't name the command, got %q", c.name, r.stderr)
		}
	}
}

// TestDataFlagPosition covers -data itself (every other test uses OVCP_DATA).
// It's parsed before the subcommand name, so it must come first: ovcp -data DIR <command>, like git -C / docker -H.
func TestDataFlagPosition(t *testing.T) {
	dir := t.TempDir()
	env := []string{
		"OVCP_CA_PASSPHRASE=correct horse battery staple",
		"OVCP_USER_PASSWORD=admin-password-1",
	}
	if r := run(t, env, "-data", dir, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init with -data flag: %+v", r)
	}
	if r := run(t, env, "-data", dir, "certificate", "list"); r.code != 0 || len(certLines(r.stdout, "server")) != 1 {
		t.Fatalf("-data flag before the subcommand should target dir: %+v", r)
	}
}

// TestGlobalFlagsBeforeCommand guards a real bug: several global flags
// stacked before the command must still dispatch and strip correctly (see
// TestCompleteAfterGlobalFlags), and -mgmt must still reach server.conf.
func TestGlobalFlagsBeforeCommand(t *testing.T) {
	dir := t.TempDir()
	env := []string{
		"OVCP_CA_PASSPHRASE=correct horse battery staple",
		"OVCP_USER_PASSWORD=admin-password-1",
	}
	mgmt := filepath.Join(dir, "custom-mgmt.sock")
	r := run(t, env, "-data", dir, "-debug", "-json", "-no-color",
		"init", "-server-cn", "vpn.example.com", "-admin", "", "-mgmt", mgmt)
	if r.code != 0 {
		t.Fatalf("init with stacked global flags + -mgmt: %+v", r)
	}
	conf, err := os.ReadFile(filepath.Join(dir, "server.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "management "+mgmt+" unix") {
		t.Fatalf("server.conf missing custom -mgmt socket %q:\n%s", mgmt, conf)
	}
}

// TestLifecycle exercises the everyday flow: init, issue, list, export,
// revoke, audit — the same sequence a real operator runs.
func TestLifecycle(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", "admin"); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	if r := run(t, env, "certificate", "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}

	list := run(t, env, "certificate", "list")
	rows := certLines(list.stdout, "alice")
	if list.code != 0 || len(rows) != 1 {
		t.Fatalf("list after issue: %+v", list)
	}
	serial := serialOf(t, rows[0])

	if r := run(t, env, "certificate", "issue", "-cn", "bob", "-export", "-remote", "vpn.example.com"); r.code != 0 ||
		!strings.Contains(r.stdout, "BEGIN CERTIFICATE") || !strings.Contains(r.stdout, "BEGIN PRIVATE KEY") {
		t.Fatalf("export: %+v", r)
	}

	if r := run(t, env, "certificate", "revoke", "-serial", serial); r.code != 0 {
		t.Fatalf("revoke: %+v", r)
	}
	list = run(t, env, "certificate", "list")
	if rows := certLines(list.stdout, "alice"); len(rows) != 1 || !strings.Contains(rows[0], "REVOKED") {
		t.Fatalf("expected alice REVOKED: %+v", list)
	}

	audit := run(t, env, "audit")
	if audit.code != 0 || !strings.Contains(audit.stdout, "issue") || !strings.Contains(audit.stdout, "revoke") {
		t.Fatalf("audit: %+v", audit)
	}
}

// TestStats covers the snapshot (non-follow) path against an empty history —
// no live openvpn here, but enough to exercise the text/json branches and the -follow/-json guard.
func TestStats(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "stats"); r.code != 0 || !strings.Contains(r.stdout, "no samples yet") {
		t.Fatalf("stats (empty): %+v", r)
	}
	if r := run(t, env, "stats", "-cn", "alice"); r.code != 0 || !strings.Contains(r.stdout, "no samples yet") {
		t.Fatalf("stats -cn (empty): %+v", r)
	}
	r := run(t, env, "-json", "stats")
	if r.code != 0 {
		t.Fatalf("-json stats: %+v", r)
	}
	var out statsSnapshot
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.Samples == nil || out.Sessions == nil {
		t.Fatalf("-json stats shape: want empty arrays, not null: %+v err=%v", r, err)
	}
	// -json errors go to stdout as {"error":...} (die()'s json branch), not stderr.
	if r := run(t, env, "-json", "stats", "-follow"); r.code == 0 || !strings.Contains(r.stdout, "-follow") {
		t.Fatalf("-json stats -follow should be rejected: %+v", r)
	}
}

// TestCertAlias covers "cert" dispatching identically to "certificate".
func TestCertAlias(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "cert", "list"); r.code != 0 {
		t.Fatalf("cert list: %+v", r)
	}
}

// TestStatsConfigCommand covers the config get/set path added alongside the
// snapshot/-follow flags — same "-1 means unchanged" idiom as logs config.
// TestFollowLinesReturningClient: a CN gone for a tick and back has no
// stale sample, so the global rate's dt stays one tick (it was the gap).
func TestFollowLinesReturningClient(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	prev := map[string]store.Sample{}
	tick := func(at time.Time, clients ...controller.VPNClient) string {
		return followLines(clients, nil, "", at, prev)[0]
	}
	tick(t0, controller.VPNClient{CN: "alice"}, controller.VPNClient{CN: "bob"})
	tick(t0.Add(time.Second), controller.VPNClient{CN: "alice", BytesRecv: 1000})
	got := tick(t0.Add(2*time.Second), controller.VPNClient{CN: "alice", BytesRecv: 2000}, controller.VPNClient{CN: "bob", BytesRecv: 5000})
	if !strings.Contains(got, "rx "+fmtRate(1000)) {
		t.Fatalf("header %q: want rx %s (alice over one tick, bob new)", got, fmtRate(1000))
	}
}

func TestStatsConfigCommand(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "stats", "config", "get"); r.code != 0 ||
		!strings.Contains(r.stdout, "sample-interval-sec: 60") || !strings.Contains(r.stdout, "retention-hours:     24") {
		t.Fatalf("stats config get defaults: %+v", r)
	}
	if r := run(t, env, "stats", "config", "set", "-retention-hours", "48"); r.code != 0 {
		t.Fatalf("stats config set: %+v", r)
	}
	if r := run(t, env, "stats", "config", "get"); r.code != 0 ||
		!strings.Contains(r.stdout, "retention-hours:     48") || !strings.Contains(r.stdout, "sample-interval-sec: 60") {
		t.Fatalf("stats config get after set: %+v", r)
	}
	if r := run(t, env, "stats", "config", "set", "-sample-interval-sec", "0"); r.code == 0 {
		t.Fatalf("stats config set 0 must be rejected: %+v", r)
	}
}

// TestLogsCommand covers config get/set (same "-1 means unchanged" idiom as
// stats config), rotate, and status — logs.go had zero CLI-level coverage.
func TestLogsCommand(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "logs", "config", "get"); r.code != 0 ||
		!strings.Contains(r.stdout, "enabled:           on") ||
		!strings.Contains(r.stdout, "retention-days:    14") ||
		!strings.Contains(r.stdout, "keep-uncompressed: 2") {
		t.Fatalf("logs config get defaults: %+v", r)
	}
	if r := run(t, env, "logs", "config", "set", "-enabled", "off", "-retention-days", "7"); r.code != 0 {
		t.Fatalf("logs config set: %+v", r)
	}
	if r := run(t, env, "logs", "config", "get"); r.code != 0 ||
		!strings.Contains(r.stdout, "enabled:           off") ||
		!strings.Contains(r.stdout, "retention-days:    7") ||
		!strings.Contains(r.stdout, "keep-uncompressed: 2") {
		t.Fatalf("logs config get after set: %+v", r)
	}
	if r := run(t, env, "logs", "config", "set", "-keep-uncompressed", "-2"); r.code == 0 {
		t.Fatalf("a negative keep-uncompressed must be refused: %+v", r)
	}
	if r := run(t, env, "logs", "rotate"); r.code != 0 || !strings.Contains(r.stdout, "rotated") {
		t.Fatalf("logs rotate: %+v", r)
	}
	if r := run(t, env, "logs", "status"); r.code != 0 || !strings.Contains(r.stdout, "openvpn") ||
		!strings.Contains(r.stdout, "ovcp") || !strings.Contains(r.stdout, "dnsmasq") {
		t.Fatalf("logs status: %+v", r)
	}
}

func TestSortByFlag(t *testing.T) {
	type row struct{ name string }
	rows := []row{{"charlie"}, {"alice"}, {"bob"}}
	getters := map[string]func(row) string{"name": func(r row) string { return r.name }}

	if err := sortByFlag(rows, getters, "", false); err != nil || rows[0].name != "charlie" {
		t.Fatalf("empty key should be a no-op, got %v err=%v", rows, err)
	}
	if err := sortByFlag(rows, getters, "name", false); err != nil || rows[0].name != "alice" || rows[2].name != "charlie" {
		t.Fatalf("want alice,bob,charlie, got %v err=%v", rows, err)
	}
	if err := sortByFlag(rows, getters, "name", true); err != nil || rows[0].name != "charlie" || rows[2].name != "alice" {
		t.Fatalf("want charlie,bob,alice, got %v err=%v", rows, err)
	}
	if err := sortByFlag(rows, getters, "bogus", false); err == nil {
		t.Fatal("unrecognized -sort value should error, not silently no-op")
	}
}

func TestVisibleWidth(t *testing.T) {
	// ansi() wraps unconditionally (unlike red/green/yellow, which no-op
	// outside a real terminal) — needed here so the ANSI-stripping path is
	// actually exercised regardless of whether the test runs on a tty.
	cases := map[string]int{
		"":                           0,
		"up":                         2,
		ansi(ansiRed, "REVOKED"):     7,
		ansi(ansiGreen, "enabled"):   7,
		ansi(ansiYellow, "expiring"): 8,
		"café":                       4, // rune count, not byte count
	}
	for s, want := range cases {
		if got := visibleWidth(s); got != want {
			t.Errorf("visibleWidth(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestListFilterSort(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "bob"); r.code != 0 {
		t.Fatalf("issue bob: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue alice: %+v", r)
	}
	serial := serialOf(t, certLines(run(t, env, "certificate", "list").stdout, "bob")[0])
	if r := run(t, env, "certificate", "revoke", "-serial", serial); r.code != 0 {
		t.Fatalf("revoke: %+v", r)
	}

	if r := run(t, env, "certificate", "list", "-status", "revoked"); len(certLines(r.stdout, "bob")) != 1 || len(certLines(r.stdout, "alice")) != 0 {
		t.Fatalf("-status revoked should show only bob: %+v", r)
	}
	if r := run(t, env, "certificate", "list", "-status", "active"); len(certLines(r.stdout, "alice")) != 1 || len(certLines(r.stdout, "bob")) != 0 {
		t.Fatalf("-status active should exclude revoked bob: %+v", r)
	}
	if r := run(t, env, "certificate", "list", "-kind", "server"); len(certLines(r.stdout, "vpn.example.com")) != 1 || len(certLines(r.stdout, "alice")) != 0 {
		t.Fatalf("-kind server should show only the server cert: %+v", r)
	}

	r := run(t, env, "certificate", "list", "-status", "all", "-sort", "cn")
	rows := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(rows) != 4 || !strings.Contains(rows[1], "alice") {
		t.Fatalf("-sort cn should put alice first (after the header row): %+v", r)
	}
	r = run(t, env, "certificate", "list", "-status", "all", "-sort", "cn", "-desc")
	rows = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(rows) != 4 || !strings.Contains(rows[1], "vpn.example.com") {
		t.Fatalf("-sort cn -desc should put vpn.example.com first (after the header row): %+v", r)
	}

	// an unrecognized -sort value must error, not silently fall back to
	// unsorted output that looks like it worked.
	if r := run(t, env, "certificate", "list", "-sort", "name"); r.code == 0 {
		t.Fatalf("-sort name (not a real field) should fail, not silently no-op: %+v", r)
	}
}

// TestListExpiring covers the "expiring" status tier (certExpiryWarnDays):
// a cert inside the warn window but not yet expired, in both text and -json.
func TestListExpiring(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "soon", "-days", "10"); r.code != 0 {
		t.Fatalf("issue soon: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "fine", "-days", "400"); r.code != 0 {
		t.Fatalf("issue fine: %+v", r)
	}

	r := run(t, env, "certificate", "list")
	if rows := certLines(r.stdout, "soon"); len(rows) != 1 || !strings.Contains(rows[0], "expiring") {
		t.Fatalf("expected soon expiring: %+v", r)
	}
	if rows := certLines(r.stdout, "fine"); len(rows) != 1 || !strings.Contains(rows[0], "valid") {
		t.Fatalf("expected fine valid: %+v", r)
	}

	r = run(t, env, "-json", "certificate", "list")
	if r.code != 0 {
		t.Fatalf("-json list: %+v", r)
	}
	var rows []certOut
	if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
		t.Fatalf("-json list unmarshal: %v: %+v", err, r)
	}
	status := map[string]string{}
	for _, c := range rows {
		status[c.CN] = c.Status
	}
	if status["soon"] != "expiring" {
		t.Fatalf("want soon expiring in -json, got %q: %+v", status["soon"], rows)
	}
	if status["fine"] != "valid" {
		t.Fatalf("want fine valid in -json, got %q: %+v", status["fine"], rows)
	}
}

func TestUserListSort(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	addUser := withEnv(env, "OVCP_USER_PASSWORD=some-password-1")
	for _, name := range []string{"charlie", "alice", "bob"} {
		if r := run(t, addUser, "user", "add", "-name", name, "-role", "operator"); r.code != 0 {
			t.Fatalf("user add %s: %+v", name, r)
		}
	}
	r := run(t, env, "user", "list", "-sort", "username")
	rows := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(rows) != 4 || !strings.HasPrefix(rows[1], "alice") {
		t.Fatalf("-sort username should put alice first (after the header row): %+v", r)
	}
	// text mode must carry the same CreatedAt -json exposes (api.UserSummary),
	// not silently drop it — see cmdUser's "list" text renderer.
	today := time.Now().Format("2006-01-02")
	if !strings.Contains(rows[0], "CREATED") || !strings.Contains(rows[1], today) {
		t.Fatalf("user list text output must show a CREATED column: %+v", r)
	}
	r = run(t, env, "user", "list", "-sort", "username", "-desc")
	rows = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(rows) != 4 || !strings.HasPrefix(rows[1], "charlie") {
		t.Fatalf("-sort username -desc should put charlie first (after the header row): %+v", r)
	}

	if r := run(t, addUser, "user", "add", "-name", "dana", "-role", "readonly"); r.code != 0 {
		t.Fatalf("user add dana: %+v", r)
	}
	if r := run(t, env, "user", "disable", "-name", "bob"); r.code != 0 {
		t.Fatalf("user disable bob: %+v", r)
	}
	if r := run(t, env, "user", "list", "-status", "disabled"); !strings.Contains(r.stdout, "bob") || strings.Contains(r.stdout, "alice") {
		t.Fatalf("-status disabled should show only bob: %+v", r)
	}
	if r := run(t, env, "user", "list", "-role", "readonly"); !strings.Contains(r.stdout, "dana") || strings.Contains(r.stdout, "alice") {
		t.Fatalf("-role readonly should show only dana: %+v", r)
	}
}

// TestIssueValidation covers issue's non-positive-validity guard, and that
// -kind is gone (client-only now, matching export/API — see cmdIssue).
func TestIssueValidation(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "vpn.example.com", "-kind", "server"); r.code == 0 {
		t.Fatalf("-kind should no longer be a recognized flag: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "alice", "-days", "0"); r.code == 0 {
		t.Fatalf("-days 0 should be rejected: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "alice", "-days", "-5"); r.code == 0 {
		t.Fatalf("-days -5 should be rejected: %+v", r)
	}
	// the client-cert / positive-days path itself must still work
	if r := run(t, env, "certificate", "issue", "-cn", "alice", "-key-pass", "hunter2"); r.code != 0 {
		t.Fatalf("client cert with -key-pass should still work: %+v", r)
	}
}

func TestRenewServerValidation(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "renew", "-days", "0"); r.code == 0 {
		t.Fatalf("-days 0 should be rejected: %+v", r)
	}
}

func TestInitValidation(t *testing.T) {
	if r := run(t, baseEnv(t), "init", "-server-cn", "vpn.example.com", "-admin", "", "-ca-years", "0"); r.code == 0 {
		t.Fatalf("-ca-years 0 should be rejected: %+v", r)
	}
	if r := run(t, baseEnv(t), "init", "-server-cn", "vpn.example.com", "-admin", "", "-server-days", "-1"); r.code == 0 {
		t.Fatalf("-server-days -1 should be rejected: %+v", r)
	}
}

// TestExportFollowsConfig covers a bug where `export` ignored the persisted
// server config and always rendered the hardcoded 1194/udp/AES-256-GCM defaults regardless of what the server ran.
func TestExportFollowsConfig(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	s, err := store.Open(filepath.Join(dataDir(env), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ovpnconf.Default()
	cfg.Port, cfg.Proto, cfg.Cipher = 51820, "tcp", "CHACHA20-POLY1305"
	raw, _ := json.Marshal(cfg)
	if err := s.SetSetting("vpn_config", string(raw)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r := run(t, env, "certificate", "issue", "-cn", "alice", "-export", "-remote", "vpn.example.com")
	if r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
	for _, want := range []string{"remote vpn.example.com 51820", "proto tcp", "data-ciphers CHACHA20-POLY1305"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("export should follow the configured server, missing %q: %+v", want, r)
		}
	}

	// an explicit flag still overrides the configured default
	r2 := run(t, env, "certificate", "issue", "-cn", "bob", "-export", "-remote", "vpn.example.com", "-port", "1234", "-proto", "udp")
	if r2.code != 0 || !strings.Contains(r2.stdout, "remote vpn.example.com 1234") || !strings.Contains(r2.stdout, "proto udp") {
		t.Fatalf("explicit -port/-proto should override the configured default: %+v", r2)
	}
}

func TestExportSplitTunnel(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	// RedirectGW defaults to true — split-tunnel should apply out of the box.
	r := run(t, env, "certificate", "issue", "-cn", "alice", "-export", "-remote", "vpn.example.com", "-split-tunnel")
	if r.code != 0 || !strings.Contains(r.stdout, `pull-filter ignore "redirect-gateway"`) {
		t.Fatalf("split-tunnel should apply when the server redirects: %+v", r)
	}

	s, err := store.Open(filepath.Join(dataDir(env), "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ovpnconf.Default()
	cfg.RedirectGW = false
	raw, _ := json.Marshal(cfg)
	if err := s.SetSetting("vpn_config", string(raw)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r2 := run(t, env, "certificate", "issue", "-cn", "bob", "-export", "-remote", "vpn.example.com", "-split-tunnel")
	if r2.code == 0 {
		t.Fatalf("split-tunnel should be rejected when the server doesn't redirect: %+v", r2)
	}
	if rows := certLines(run(t, env, "certificate", "list").stdout, "bob"); len(rows) != 0 {
		t.Fatalf("a refused export must issue nothing: %v", rows)
	}
}

func TestExportCustomOpts(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	r := run(t, env, "certificate", "issue", "-cn", "alice", "-export", "-remote", "vpn.example.com", "-custom-opts", "keepalive 5 30", "-custom-opts", `push "dhcp-option DOMAIN-SEARCH a,b"`)
	if r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
	for _, want := range []string{"keepalive 5 30\n", `push "dhcp-option DOMAIN-SEARCH a,b"` + "\n"} { // each use one line, commas kept
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("missing %q in bundle: %+v", want, r)
		}
	}
}

func TestRotateCA(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	// ca rotate has no flags of its own, so -h must still exit 0 without
	// falling through to the real (interactive, passphrase-changing) op.
	if r := run(t, env, "ca", "rotate", "-h"); r.code != 0 {
		t.Fatalf("ca rotate -h: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "presanity"); r.code != 0 {
		t.Fatalf("ca rotate -h must not have rotated the CA: %+v", r)
	}

	rotate := withEnv(env, "OVCP_CA_NEW_PASSPHRASE=a totally different passphrase")
	if r := run(t, rotate, "ca", "rotate"); r.code != 0 {
		t.Fatalf("ca rotate: %+v", r)
	}

	if r := run(t, env, "certificate", "issue", "-cn", "carol"); r.code == 0 {
		t.Fatalf("issue with the old CA passphrase should now fail: %+v", r)
	}

	newPass := []string{"OVCP_DATA=" + dataDir(env), "OVCP_CA_PASSPHRASE=a totally different passphrase"}
	if r := run(t, newPass, "certificate", "issue", "-cn", "carol"); r.code != 0 {
		t.Fatalf("issue with the new CA passphrase should work: %+v", r)
	}
}

// TestNoFlagCommandsAcceptHelp: commands with no flags still parse an empty
// FlagSet, so -h and unknown flags behave normally instead of being ignored.
func TestNoFlagCommandsAcceptHelp(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	for _, args := range [][]string{{"version", "-h"}, {"certificate", "list", "-h"}, {"audit", "-h"}, {"user", "list", "-h"}} {
		if r := run(t, env, args...); r.code != 0 {
			t.Fatalf("%v should exit 0 on -h: %+v", args, r)
		}
	}
	if r := run(t, env, "certificate", "list", "-bogus"); r.code == 0 {
		t.Fatalf("unknown flag on a no-flag command should still fail: %+v", r)
	}
}

func TestRenewServer(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	before := len(certLines(run(t, env, "certificate", "list").stdout, "server"))

	r := run(t, env, "certificate", "renew")
	if r.code != 0 {
		t.Fatalf("renew: %+v", r)
	}
	if strings.Contains(r.stdout, "admin UI's own TLS cert") {
		t.Fatalf("same-CN renew must not claim admin-tls needs a restart: %+v", r)
	}

	after := len(certLines(run(t, env, "certificate", "list").stdout, "server"))
	if after != before+1 {
		t.Fatalf("expected one more server cert row: before=%d after=%d", before, after)
	}
	if r := run(t, env, "audit"); !strings.Contains(r.stdout, "kind=server") {
		t.Fatalf("audit missing renew kind=server: %+v", r)
	}

	// -cn renames the server cert; text mode must say so, not just -json
	// (renewOut.CN) — see cmdRenew's text renderer.
	r = run(t, env, "certificate", "renew", "-cn", "renamed.example.com")
	if r.code != 0 || !strings.Contains(r.stdout, "renamed.example.com") {
		t.Fatalf("certificate renew -cn must show the new cn in text output: %+v", r)
	}
	if !strings.Contains(r.stdout, "admin UI's own TLS cert") {
		t.Fatalf("a -cn rename must warn that admin-tls needs its own restart: %+v", r)
	}
}

// TestRenewRefusesNonexistentCert: renewing with nothing active to replace
// must error, not silently issue a fresh cert — a guess-and-hope renewal
// would otherwise create a phantom cert nobody asked for. Covers
// `certificate issue -renew`; the server cert can't be revoked away from `renew`.
func TestRenewRefusesNonexistentCert(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "ghost", "-renew"); r.code == 0 {
		t.Fatalf("renewing a never-issued client CN should fail, got: %+v", r)
	}
	var rows []certOut
	assertCleanJSON(t, run(t, withEnv(env, "OVCP_JSON=1"), "certificate", "list"), &rows)
	for _, c := range rows {
		if c.CN == "ghost" {
			t.Fatalf("a failed renewal must not have created a cert: %+v", rows)
		}
	}

	// the server cert is never revocable, so renew always has one to replace.
	var serverSerial string
	for _, c := range rows {
		if c.Kind == "server" {
			serverSerial = c.Serial
		}
	}
	if serverSerial == "" {
		t.Fatal("server cert not found after init")
	}
	if r := run(t, env, "certificate", "revoke", "-serial", serverSerial); r.code == 0 {
		t.Fatalf("revoking the server cert must be refused: %+v", r)
	}
	if r := run(t, env, "certificate", "renew"); r.code != 0 {
		t.Fatalf("renew after a refused revoke: %+v", r)
	}
}

// TestRevokeWrongPassphraseKeepsCert: a revoke whose CRL can't be signed
// must leave the cert active, never revoked in the store but absent from the CRL.
func TestRevokeWrongPassphraseKeepsCert(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}
	var rows []certOut
	assertCleanJSON(t, run(t, withEnv(env, "OVCP_JSON=1"), "certificate", "list"), &rows)
	var serial string
	for _, c := range rows {
		if c.CN == "alice" {
			serial = c.Serial
		}
	}
	if r := run(t, withEnv(env, "OVCP_CA_PASSPHRASE=Wrong-but-strong-9"), "certificate", "revoke", "-serial", serial); r.code == 0 {
		t.Fatalf("revoke with a wrong passphrase must fail: %+v", r)
	}
	if r := run(t, env, "certificate", "revoke", "-serial", serial); r.code != 0 {
		t.Fatalf("revoke with the right passphrase must still work: %+v", r)
	}
}

// TestRenewClient covers client renewal via `certificate issue -renew`:
// revokes the outgoing cert, issues a fresh one under the same CN, and
// hands back usable key material (no escrow), inline or to files with -out.
func TestRenewClient(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "certificate", "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}
	var rows []certOut
	assertCleanJSON(t, run(t, withEnv(env, "OVCP_JSON=1"), "certificate", "list"), &rows)
	var oldSerial string
	for _, c := range rows {
		if c.CN == "alice" {
			oldSerial = c.Serial
		}
	}
	if oldSerial == "" {
		t.Fatalf("alice not found before renewal: %+v", rows)
	}

	r := run(t, env, "certificate", "issue", "-cn", "alice", "-renew")
	if r.code != 0 {
		t.Fatalf("issue -renew: %+v", r)
	}
	if !strings.Contains(r.stdout, "BEGIN CERTIFICATE") || !strings.Contains(r.stdout, "BEGIN PRIVATE KEY") {
		t.Fatalf("client renewal should print fresh cert+key, got: %+v", r)
	}

	assertCleanJSON(t, run(t, withEnv(env, "OVCP_JSON=1"), "certificate", "list"), &rows)
	var oldStatus, newSerial string
	aliceCount := 0
	for _, c := range rows {
		if c.CN != "alice" {
			continue
		}
		aliceCount++
		if c.Serial == oldSerial {
			oldStatus = c.Status
		} else {
			newSerial = c.Serial
		}
	}
	if aliceCount != 2 {
		t.Fatalf("expected outgoing + renewed alice rows (2), got %d: %+v", aliceCount, rows)
	}
	if oldStatus != "REVOKED" {
		t.Fatalf("outgoing cert should be revoked, got status %q", oldStatus)
	}
	if newSerial == "" {
		t.Fatal("renewed cert not found in list")
	}

	// without -renew, an active CN is refused rather than replaced.
	if r := run(t, env, "certificate", "issue", "-cn", "alice"); r.code == 0 {
		t.Fatalf("issue without -renew on an active CN should fail, got: %+v", r)
	}

	// stdout is the only output: the renewed cert and key, PEM.
	r = run(t, env, "certificate", "issue", "-cn", "alice", "-renew")
	if r.code != 0 || !strings.Contains(r.stdout, "BEGIN CERTIFICATE") || !strings.Contains(r.stdout, "PRIVATE KEY") {
		t.Fatalf("issue -renew should print cert and key: %+v", r)
	}
}

func TestRenewCA(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "ca", "renew", "-years", "0"); r.code == 0 {
		t.Fatalf("-years 0 should be rejected: %+v", r)
	}
	r := run(t, withEnv(env, "OVCP_JSON=1"), "ca", "renew")
	if r.code != 0 {
		t.Fatalf("ca renew: %+v", r)
	}
	var out renewCAOut
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.NotAfter.IsZero() {
		t.Fatalf("ca renew -json unmarshal: %v: %+v", err, r)
	}
	// a fresh issue must still work — same CA key, just renewed.
	if r := run(t, env, "certificate", "issue", "-cn", "bob"); r.code != 0 {
		t.Fatalf("issue after ca renew should still work: %+v", r)
	}
}

// TestCAStatus: read-only, stays out of `certificate list` (CA management is
// CLI-only, on purpose — see cmdCertificate).
func TestCAStatus(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-ca-cn", "Test CA", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	r := run(t, withEnv(env, "OVCP_JSON=1"), "ca", "status")
	if r.code != 0 {
		t.Fatalf("ca status: %+v", r)
	}
	var out caStatusOut
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.CN != "Test CA" || out.Status != "valid" {
		t.Fatalf("ca status -json unmarshal: %v: %+v", err, r)
	}
	var rows []certOut
	assertCleanJSON(t, run(t, withEnv(env, "OVCP_JSON=1"), "certificate", "list"), &rows)
	for _, c := range rows {
		if c.Kind == "ca" {
			t.Fatalf("certificate list must not include the CA: %+v", rows)
		}
	}
}

// TestBackupRestore mirrors the disaster-recovery flow: create, restore into
// a fresh dir (wrong passphrase must fail), renew the server cert, confirm cert metadata survived.
func TestBackupRestore(t *testing.T) {
	src := baseEnv(t)
	if r := run(t, src, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, src, "certificate", "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}

	backupFile := filepath.Join(t.TempDir(), "backup.ovcpbak")
	create := withEnv(src, "OVCP_BACKUP_PASSPHRASE=backup-pass-123")
	r := run(t, create, "backup", "create")
	if r.code != 0 || os.WriteFile(backupFile, []byte(r.stdout), 0o600) != nil {
		t.Fatalf("backup create: %+v", r)
	}

	dstDir := t.TempDir()
	wrongPass := []string{"OVCP_DATA=" + dstDir, "OVCP_BACKUP_PASSPHRASE=wrong"}
	archive, _ := os.ReadFile(backupFile)
	if r := runIn(t, wrongPass, archive, "backup", "restore"); r.code == 0 {
		t.Fatalf("restore with wrong passphrase should fail: %+v", r)
	}

	restore := []string{"OVCP_DATA=" + dstDir, "OVCP_BACKUP_PASSPHRASE=backup-pass-123"}
	if r := runIn(t, restore, archive, "backup", "restore"); r.code != 0 {
		t.Fatalf("backup restore: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "pki", "server.crt")); err == nil {
		t.Fatal("server.crt should not exist right after restore")
	}

	renew := []string{"OVCP_DATA=" + dstDir, "OVCP_SERVER_CN=vpn.example.com",
		"OVCP_CA_PASSPHRASE=correct horse battery staple"}
	if r := run(t, renew, "certificate", "renew"); r.code != 0 {
		t.Fatalf("renew after restore: %+v", r)
	}
	if r := run(t, renew, "certificate", "list"); r.code != 0 || len(certLines(r.stdout, "alice")) != 1 {
		t.Fatalf("restored db should still have alice: %+v", r)
	}

	// dstDir is now initialized: restore must refuse without -force; the
	// archive comes only from stdin, so a stray argument is refused too.
	if r := runIn(t, restore, archive, "backup", "restore"); r.code == 0 {
		t.Fatalf("restore over an initialized dir without -force should fail: %+v", r)
	}
	if r := runIn(t, restore, archive, "backup", "restore", "-force", backupFile); r.code == 0 {
		t.Fatalf("a file argument must be refused (stdin only): %+v", r)
	}
	if r := runIn(t, restore, archive, "backup", "restore", "-force"); r.code != 0 {
		t.Fatalf("-force should overwrite: %+v", r)
	}
}

func TestUserManagement(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	addBob := withEnv(env, "OVCP_USER_PASSWORD=bobs-password-1")
	if r := run(t, addBob, "user", "add", "-name", "bob", "-role", "operator"); r.code != 0 {
		t.Fatalf("user add: %+v", r)
	}
	if r := run(t, env, "user", "list"); r.code != 0 || !strings.Contains(r.stdout, "bob") {
		t.Fatalf("user list after add: %+v", r)
	}

	if r := run(t, env, "user", "disable", "-name", "bob"); r.code != 0 {
		t.Fatalf("user disable: %+v", r)
	}
	if r := run(t, env, "user", "list"); !strings.Contains(r.stdout, "disabled") {
		t.Fatalf("expected disabled: %+v", r)
	}
	if r := run(t, env, "user", "enable", "-name", "bob"); r.code != 0 {
		t.Fatalf("user enable: %+v", r)
	}
	if r := run(t, addBob, "user", "passwd", "-name", "bob"); r.code != 0 {
		t.Fatalf("user passwd: %+v", r)
	}

	if r := run(t, env, "user", "del", "-name", "bob"); r.code != 0 {
		t.Fatalf("user del: %+v", r)
	}
	if r := run(t, env, "user", "list"); strings.Contains(r.stdout, "bob") {
		t.Fatalf("bob should be gone: %+v", r)
	}
}

// TestPasswordYOLOCLI: OVCP_YOLO_PASSWORD waives complexity for readSecret's
// env-var path too (init's OVCP_USER_PASSWORD), with a warning on stderr.
func TestPasswordYOLOCLI(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	weak := withEnv(env, "OVCP_USER_PASSWORD=alllowercase")
	if r := run(t, weak, "user", "add", "-name", "eve", "-role", "operator"); r.code == 0 {
		t.Fatalf("single-class password should be rejected: %+v", r)
	}

	yolo := withEnv(weak, "OVCP_YOLO_PASSWORD=1")
	r := run(t, yolo, "user", "add", "-name", "eve", "-role", "operator")
	if r.code != 0 {
		t.Fatalf("weak password should be accepted with OVCP_YOLO_PASSWORD set: %+v", r)
	}
	if !strings.Contains(r.stderr, "OVCP_YOLO_PASSWORD") {
		t.Fatalf("expected a warning naming OVCP_YOLO_PASSWORD on stderr, got: %+v", r)
	}
}

// TestUnreachableServe: remote-control commands must fail cleanly, not hang, when no `serve` process is up.
// TestTelegramConfigValidation covers what's reachable without a real
// Telegram API call: neither -token nor -admin errors, unknown op errors.
// Success path (and independent token/admin setting) is covered in internal/telegram's own tests (mocked API).
func TestTelegramConfigValidation(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "telegram", "config", "set"); r.code == 0 {
		t.Fatalf("telegram config set with neither -token nor -admin should fail: %+v", r)
	}
	if r := run(t, env, "telegram", "bogus"); r.code == 0 {
		t.Fatalf("telegram bogus should fail: %+v", r)
	}
}

// TestFlagAfterOp guards a real bug: -ctrl on the FlagSet main() parses
// before the op is known meant "ovcp vpn start -ctrl X" fell back to the default socket. The error naming the bogus path proves it parsed.
func TestFlagAfterOp(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	bogus := filepath.Join(t.TempDir(), "bogus-control.sock")
	for _, args := range [][]string{
		{"vpn", "start", "-ctrl", bogus},
		{"debug", "on", "-ctrl", bogus},
		{"telegram", "status", "-ctrl", bogus},
	} {
		r := run(t, env, args...)
		if r.code == 0 || !strings.Contains(r.stderr, bogus) {
			t.Fatalf("%v: -ctrl after the op must be honored, got: %+v", args, r)
		}
	}
}

func TestUnreachableServe(t *testing.T) {
	env := withEnv(baseEnv(t), "OVCP_CTRL_SOCK="+filepath.Join(t.TempDir(), "control.sock"))
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	if r := run(t, env, "vpn", "status"); r.code == 0 {
		t.Fatalf("vpn status with no serve running should fail: %+v", r)
	}
	if r := run(t, env, "dns", "status"); r.code == 0 {
		t.Fatalf("dns status with no serve running should fail: %+v", r)
	}
	if r := run(t, env, "debug", "on"); r.code == 0 {
		t.Fatalf("debug on with no serve running should fail: %+v", r)
	}
	if r := run(t, env, "telegram", "status"); r.code == 0 {
		t.Fatalf("telegram status with no serve running should fail: %+v", r)
	}
	// status is deliberately soft: no worker to report on isn't a CLI error.
	// certs still come from the store directly (no serve needed) — 2 here:
	// the server cert plus AllCerts' synthetic CA row. dns-status/telegram-status
	// share the same unreachable control socket as the status call above, so
	// they're "unknown", not a false "stopped" or a silently missing line.
	if r := run(t, env, "status"); r.code != 0 || !strings.Contains(r.stdout, "OpenVPN: unknown") ||
		!strings.Contains(r.stdout, "DNS: unknown") || !strings.Contains(r.stdout, "Telegram: unknown") ||
		!strings.Contains(r.stdout, "Certs: 2") {
		t.Fatalf("status with no serve running: %+v", r)
	}

	kill := withEnv(env, "OVCP_MGMT_SOCK="+filepath.Join(t.TempDir(), "mgmt.sock"))
	if r := run(t, kill, "vpn", "kill", "-cn", "nobody"); r.code == 0 {
		t.Fatalf("kill with no mgmt socket should fail: %+v", r)
	}
}

func TestBuildDnsmasqArgs(t *testing.T) {
	ip := net.ParseIP("10.8.0.1")
	args := buildDnsmasqArgs(ip, "/d/dns", false)
	want := []string{
		"-k", "--user=root", "--bind-dynamic",
		"--listen-address=10.8.0.1",
		"--hostsdir=/d/dns", "--log-queries", "--log-facility=-",
	}
	if len(args) != len(want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q (full: %v)", i, args[i], want[i], args)
		}
	}

	blocked := buildDnsmasqArgs(ip, "/d/dns", true)
	if !containsArg(blocked, "--no-resolv") || !containsArg(blocked, "--server=/#/") {
		t.Fatalf("blockInternet=true must append --no-resolv and --server=/#/, got %v", blocked)
	}
}

// fakeVersionScript writes a script that prints versionOutput for --version,
// standing in for dnsmasq's own --version banner.
func fakeVersionScript(t *testing.T, versionOutput string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-dnsmasq.sh")
	script := "#!/bin/sh\ncat <<'EOF'\n" + versionOutput + "EOF\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func captureWarnings(t *testing.T, fn func()) string {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	fn()
	return buf.String()
}

func TestWarnMissingInotify(t *testing.T) {
	withInotify := fakeVersionScript(t, "Dnsmasq version 2.91\ncompile time options: inotify dumpfile\n")
	if out := captureWarnings(t, func() { warnMissingInotify(withInotify) }); strings.Contains(out, "inotify") {
		t.Fatalf("dnsmasq with inotify support must not warn, got: %s", out)
	}

	withoutInotify := fakeVersionScript(t, "Dnsmasq version 2.85\ncompile time options: dumpfile\n")
	if out := captureWarnings(t, func() { warnMissingInotify(withoutInotify) }); !strings.Contains(out, "inotify") {
		t.Fatalf("dnsmasq without inotify support must warn, got: %s", out)
	}

	if out := captureWarnings(t, func() { warnMissingInotify("") }); out != "" {
		t.Fatalf("no binary found must not warn about inotify, got: %s", out)
	}
}

// TestDNSSupervisorPreStart: Args must be recomputed on every start, not
// fixed once — a Subnet change must apply without restarting ovcp itself.
func TestDNSSupervisorPreStart(t *testing.T) {
	const (
		firstSubnet, firstListen   = "10.9.0.0/24", "--listen-address=10.9.0.1"
		secondSubnet, secondListen = "10.10.0.0/24", "--listen-address=10.10.0.1"
	)
	dir := t.TempDir()
	if err := ensureSkeleton(dir); err != nil { // supervise() trusts logs/ already exists
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "ovcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	saveSubnet := func(subnet string) {
		cfg := ovpnconf.Default()
		cfg.Subnet = subnet
		raw, _ := json.Marshal(cfg)
		s.SetSetting("vpn_config", string(raw))
	}

	saveSubnet(firstSubnet)
	pp := dataPaths(dir)
	sup := newDNSSupervisor(pp, fakeBin(t), s)
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop()
	if !containsArg(sup.Args, firstListen) {
		t.Fatalf("Args = %v, want %s", sup.Args, firstListen)
	}

	saveSubnet(secondSubnet)
	if err := sup.Restart(); err != nil {
		t.Fatal(err)
	}
	if !containsArg(sup.Args, secondListen) {
		t.Fatalf("Args after Subnet change = %v, want %s", sup.Args, secondListen)
	}
}

// fakeBin stands in for a real worker binary — ignores args, just sleeps.
func fakeBin(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-worker.sh")
	script := "#!/bin/sh\ncase \"$1\" in\n--version) echo 'fake 1.0 inotify';;\n*) exec sleep 300;;\nesac\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestEnsureSkeleton(t *testing.T) {
	dir := t.TempDir()
	pp := dataPaths(dir)

	if err := ensureSkeleton(dir); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		dir:            0o700,
		pp.PKIDir:      0o700,
		pp.LogsDir:     0o700,
		pp.DNSDir:      0o700,
		pp.CertsHosts:  0o600,
		pp.CustomHosts: 0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s mode = %v err=%v, want %o", path, fi, err, want)
		}
	}

	// custom.hosts is user-authored: a second call must not clobber existing content.
	if err := os.WriteFile(pp.CustomHosts, []byte("10.8.0.99 pihole\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := ensureSkeleton(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pp.CustomHosts)
	if err != nil || string(got) != "10.8.0.99 pihole\n" {
		t.Fatalf("custom.hosts clobbered on re-run: got %q err=%v", got, err)
	}

	// a pre-existing dataDir at the wrong mode must still be repaired —
	// MkdirAll alone is a no-op here, only the explicit Chmod fixes it.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureSkeleton(dir); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dataDir mode after repair = %v err=%v, want 0700", fi, err)
	}
}

// TestCustomOptsNoChange is the actual regression test for the bug that
// started this: `ovcp custom-opts` used to print "saved" (and write to the
// DB/server.conf) even when $EDITOR made no change at all.
func TestCustomOptsNoChange(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	noop := filepath.Join(t.TempDir(), "noop-editor.sh")
	if err := os.WriteFile(noop, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := run(t, withEnv(env, "EDITOR="+noop), "vpn", "config", "set", "-extra", "-"); r.code != 0 || !strings.Contains(r.stdout, "no changes") {
		t.Fatalf("no-op editor should report 'no changes': %+v", r)
	}

	touch := filepath.Join(t.TempDir(), "touch-editor.sh")
	if err := os.WriteFile(touch, []byte("#!/bin/sh\necho 'client-to-client' >> \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := run(t, withEnv(env, "EDITOR="+touch), "vpn", "config", "set", "-extra", "-")
	if r.code != 0 || !strings.Contains(r.stdout, "saved") {
		t.Fatalf("an editor that changed content should report 'saved': %+v", r)
	}
	// the actual bug: edit used to save silently, with no diff shown and no
	// validation run — it now saves through the same path `set` does.
	if !strings.Contains(r.stdout, "client-to-client") {
		t.Fatalf("edit should show its diff, not just 'saved': %+v", r)
	}

	// a failed edit fails the command and leaves no temp file; $EDITOR may carry arguments.
	tmp := t.TempDir()
	if r := run(t, withEnv(env, "TMPDIR="+tmp, "EDITOR=false"), "vpn", "config", "set", "-extra", "-"); r.code == 0 {
		t.Fatalf("a failing editor must fail the command: %+v", r)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temp file left behind: %v", left)
	}
	if r := run(t, withEnv(env, "EDITOR="+noop+" --wait"), "vpn", "config", "set", "-extra", "-"); r.code != 0 {
		t.Fatalf("$EDITOR with arguments: %+v", r)
	}

	// bare `set` (no flags at all) is also an empty diff — must not silently
	// re-write server.conf/re-audit a no-op, same guard -extra -'s no-op needs.
	if r := run(t, env, "vpn", "config", "set"); r.code != 0 || !strings.Contains(r.stdout, "no changes") || strings.Contains(r.stdout, "saved; run") {
		t.Fatalf("bare set with no flags should report 'no changes', not persist: %+v", r)
	}
	// any use of -extra sets it, so an empty one clears what the editor added
	if r := run(t, env, "vpn", "config", "set", "-extra", ""); r.code != 0 || !strings.Contains(r.stdout, "saved; run") {
		t.Fatalf("-extra '' should clear and persist: %+v", r)
	}
}

// TestConfigGetSetPreview is the CLI/web-UI-parity guard for issue #1: every
// server setting the web UI can PUT to /api/config must be reachable from
// the CLI too, with matching zero-value-means-unchanged flag semantics.
func TestConfigGetSetPreview(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	// defaults, unmodified
	get := run(t, env, "vpn", "config", "get")
	if get.code != 0 || !strings.Contains(get.stdout, "proto:       udp") || !strings.Contains(get.stdout, "port:        1194") {
		t.Fatalf("config get (defaults): %+v", get)
	}

	// preview must show the diff without persisting anything
	pv := run(t, env, "vpn", "config", "preview", "-proto", "tcp", "-port", "51820")
	if pv.code != 0 || !strings.Contains(pv.stdout, "-proto udp") || !strings.Contains(pv.stdout, "+proto tcp") {
		t.Fatalf("config preview: %+v", pv)
	}
	if get2 := run(t, env, "vpn", "config", "get"); !strings.Contains(get2.stdout, "proto:       udp") {
		t.Fatalf("config preview must not persist: %+v", get2)
	}

	// set persists; flags left at zero value must leave those fields untouched
	set := run(t, env, "vpn", "config", "set", "-proto", "tcp", "-port", "51820",
		"-dns", "1.1.1.1, 9.9.9.9", "-routes", "192.168.5.0/24", "-redirect-gw", "false")
	if set.code != 0 || !strings.Contains(set.stdout, "saved") {
		t.Fatalf("config set: %+v", set)
	}
	got := run(t, withEnv(env, "OVCP_JSON=1"), "vpn", "config", "get")
	var cfg ovpnconf.Config
	if err := json.Unmarshal([]byte(got.stdout), &cfg); err != nil {
		t.Fatalf("config get -json: %v: %+v", err, got)
	}
	if cfg.Proto != "tcp" || cfg.Port != 51820 || cfg.Cipher != "AES-256-GCM" {
		t.Fatalf("config set should change only the given flags: %+v", cfg)
	}
	if len(cfg.DNS) != 2 || cfg.DNS[0] != "1.1.1.1" || len(cfg.Routes) != 1 || cfg.RedirectGW {
		t.Fatalf("config set DNS/Routes/redirect-gw not applied: %+v", cfg)
	}

	// server.conf on disk must reflect the persisted change
	conf, err := os.ReadFile(filepath.Join(dataDir(env), "server.conf"))
	if err != nil || !strings.Contains(string(conf), "proto tcp") || !strings.Contains(string(conf), "port 51820") {
		t.Fatalf("server.conf not updated by config set: %v\n%s", err, conf)
	}

	if r := run(t, env, "vpn", "config", "set", "-redirect-gw", "bogus"); r.code == 0 {
		t.Fatalf("-redirect-gw must reject anything but true/false: %+v", r)
	}
	if r := run(t, env, "vpn", "config", "set", "-cipher", "DES"); r.code == 0 {
		t.Fatalf("config set must validate, not persist a bogus cipher: %+v", r)
	}
}

// TestDNSCommand: "dns reconnect" is rejected by arg validation alone
// (dnsOps has no such op); wire-level routing is covered by
// TestControlDNSRouting, "no serve running" by TestUnreachableServe above.
// dns config is the CLI twin of TestDNSBlockInternetToggle (api package).
func TestDNSCommand(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "dns", "reconnect"); r.code == 0 {
		t.Fatalf("dns reconnect must not exist: %+v", r)
	}

	if r := run(t, env, "dns", "config", "get"); r.code != 0 || !strings.Contains(r.stdout, "off") {
		t.Fatalf("dns config get default: %+v", r)
	}
	// on/true/1 (and off/false/0) are all the same boolean vocabulary going in — exercise both
	// spellings; text output always comes back as on/off (boolText).
	if r := run(t, env, "dns", "config", "set", "-block-internet", "on"); r.code != 0 {
		t.Fatalf("dns config set on: %+v", r)
	}
	if r := run(t, env, "dns", "config", "get"); r.code != 0 || !strings.Contains(r.stdout, "on") {
		t.Fatalf("dns config get after on: %+v", r)
	}
	if r := run(t, env, "dns", "config", "set", "-block-internet", "0"); r.code != 0 {
		t.Fatalf("dns config set 0: %+v", r)
	}
	if r := run(t, env, "dns", "config", "get"); r.code != 0 || !strings.Contains(r.stdout, "off") {
		t.Fatalf("dns config get after 0: %+v", r)
	}
	if r := run(t, env, "dns", "config", "set", "-block-internet", "bogus"); r.code == 0 {
		t.Fatalf("dns config set bogus arg must fail: %+v", r)
	}
}

// TestRefreshCertsHostsCLI: issue/revoke/record must regenerate certs.hosts
// themselves — the CLI has no running serve to do it for them.
func TestRefreshCertsHostsCLI(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "ovcp.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	// init already lays out the whole skeleton, so certs.hosts exists —
	// empty — before any cert changes, not just at the first `issue`.
	certsHosts := filepath.Join(dataDir(env), "dns", "certs.hosts")
	if got, err := os.ReadFile(certsHosts); err != nil || len(got) != 0 {
		t.Fatalf("certs.hosts before any cert changes: content=%q err=%v, want empty", got, err)
	}

	if r := run(t, env, "certificate", "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}
	got, err := os.ReadFile(certsHosts)
	if err != nil || !strings.Contains(string(got), "ovcp.example.com") {
		t.Fatalf("certs.hosts after issue: content=%q err=%v", got, err)
	}
}

// TestRecordCommand covers list/include/exclude; edit is exercised by the
// same $EDITOR-stub technique as TestCustomOptsNoChange.
func TestRecordCommand(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}

	// before anything else runs, list must still work (ensureSkeleton creates
	// empty files on first touch) and report empty content for both sections.
	r := run(t, env, "record", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "Certificate records:") || !strings.Contains(r.stdout, "Custom records:") {
		t.Fatalf("record list: %+v", r)
	}

	if r := run(t, env, "record", "include", "-cn", "nonexistent"); r.code == 0 {
		t.Fatal("include on an unknown CN must fail")
	}
	// server's DNS line is unconditional — same "no active cert" error as
	// a CN that was never issued, not a silent no-op success.
	if r := run(t, env, "record", "exclude", "-cn", "vpn.example.com"); r.code == 0 {
		t.Fatal("exclude on the server CN must fail")
	}

	if r := run(t, env, "certificate", "issue", "-cn", "recordtest"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}
	if r := run(t, env, "record", "exclude", "-cn", "recordtest"); r.code != 0 || !strings.Contains(r.stdout, "excluded") {
		t.Fatalf("record exclude: %+v", r)
	}
	if r := run(t, env, "record", "include", "-cn", "recordtest"); r.code != 0 || !strings.Contains(r.stdout, "included") {
		t.Fatalf("record include: %+v", r)
	}
	// already included: must say so, not silently re-report success.
	if r := run(t, env, "record", "include", "-cn", "recordtest"); r.code != 0 || !strings.Contains(r.stdout, "already included") {
		t.Fatalf("record include (already included): %+v", r)
	}

	noop := filepath.Join(t.TempDir(), "noop-editor.sh")
	os.WriteFile(noop, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if r := run(t, withEnv(env, "EDITOR="+noop), "record", "edit"); r.code != 0 || !strings.Contains(r.stdout, "no change") {
		t.Fatalf("record edit no-op: %+v", r)
	}

	touch := filepath.Join(t.TempDir(), "touch-editor.sh")
	os.WriteFile(touch, []byte("#!/bin/sh\necho '10.8.0.50 pihole' >> \"$1\"\n"), 0o755)
	if r := run(t, withEnv(env, "EDITOR="+touch), "record", "edit"); r.code != 0 || !strings.Contains(r.stdout, "saved") {
		t.Fatalf("record edit with a change: %+v", r)
	}
	r = run(t, env, "record", "list")
	if !strings.Contains(r.stdout, "10.8.0.50 pihole") {
		t.Fatalf("record list should show the edited custom entry: %+v", r)
	}
	// list must show every cert (not just currently-connected ones), with
	// its DNS status — the whole point of this command over a raw dump.
	if !strings.Contains(r.stdout, "recordtest") || !strings.Contains(r.stdout, "included") {
		t.Fatalf("record list should show recordtest as included: %+v", r)
	}
	// server's own line is always-on — its DNS column shows the real tun IP,
	// not just "included", same as a connected client would.
	if !strings.Contains(r.stdout, "10.8.0.1") {
		t.Fatalf("record list should show the server's own tun IP: %+v", r)
	}

	rj := run(t, withEnv(env, "OVCP_JSON=1"), "record", "list")
	var out recordListOut
	if err := json.Unmarshal([]byte(rj.stdout), &out); err != nil {
		t.Fatalf("record list -json: %v (%+v)", err, rj)
	}
	var found bool
	for _, c := range out.Certs {
		if c.CN == "recordtest" {
			found = c.IncludeDNS
		}
	}
	if !found {
		t.Fatalf("record list -json certs = %+v, want recordtest included", out.Certs)
	}
	if !strings.Contains(out.Custom, "10.8.0.50 pihole") {
		t.Fatalf("record list -json custom = %q, want the edited entry", out.Custom)
	}

	// a renewal revokes the old server cert: only the active one shows the live IP.
	if r := run(t, env, "certificate", "renew"); r.code != 0 {
		t.Fatalf("renew: %+v", r)
	}
	rj = run(t, withEnv(env, "OVCP_JSON=1"), "record", "list")
	out = recordListOut{}
	if err := json.Unmarshal([]byte(rj.stdout), &out); err != nil {
		t.Fatalf("record list -json: %v (%+v)", err, rj)
	}
	for _, c := range out.Certs {
		if c.Kind == "server" && (c.IP != "") == (c.Status == "REVOKED") {
			t.Fatalf("server row %+v: the IP belongs to the active cert only", c)
		}
	}
}

// TestDropRoot: as (userns) root, an invocation becomes OVCP_USER in place —
// same pid and name, every uid dropped, exactly dropCaps ambient — works
// without NET_ADMIN, owns the data dir it creates, and never re-owns an
// existing one. --map-auto maps subuids so "daemon" (uid 1) is a real target.
func TestDropRoot(t *testing.T) {
	if exec.Command("unshare", "--map-root-user", "--map-auto", "true").Run() != nil {
		t.Skip("unshare --map-auto unavailable (needs /etc/subuid)")
	}
	d, err := os.MkdirTemp("", "ovcp-droproot")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o755)                     // daemon must reach its data dir
	os.Chmod(filepath.Dir(binPath), 0o755) // and the binary
	script := `set -e
export OVCP_USER=daemon OVCP_DATA=$D/data OVCP_CTRL_SOCK=$D/run/c OVCP_MGMT_SOCK=$D/run/m \
  OVCP_LISTEN=127.0.0.1:0 OVCP_OPENVPN_AUTOSTART=false OVCP_DNSMASQ_AUTOSTART=false
trap 'kill $p 2>/dev/null; wait; rm -rf $D' EXIT
setpriv --bounding-set -net_admin "$BIN" init -server-cn vpn.example.com -admin "" >/dev/null
"$BIN" serve 2>/dev/null & p=$!
for i in $(seq 50); do [ -S $D/run/c ] && break; sleep 0.1; done
awk '/^Name/{print $2} /^Uid/{print $2$3$4$5} /^CapAmb/{print $2}' /proc/$p/status
stat -c %u $D/data
mkdir $D/foreign && OVCP_DATA=$D/foreign "$BIN" version >/dev/null && stat -c %u $D/foreign`
	cmd := exec.Command("unshare", "--map-root-user", "--map-auto", "sh", "-c", script)
	cmd.Env = append(os.Environ(), "D="+d, "BIN="+binPath,
		"OVCP_CA_PASSPHRASE=correct horse battery staple", "OVCP_USER_PASSWORD=admin-password-1")
	out, err := cmd.CombinedOutput()
	if got, want := string(out), "ovcp\n1111\n0000000000001400\n1\n0\n"; err != nil || got != want {
		t.Fatalf("got %q err=%v, want %q", got, err, want)
	}
}

// TestBackupCreateRefusesTerminal: the archive goes to stdout only, so a
// terminal stdout is refused instead of filled with binary.
func TestBackupCreateRefusesTerminal(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) unavailable for a pty")
	}
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	cmd := exec.Command("script", "-qec", binPath+" backup create", "/dev/null")
	cmd.Env = append(os.Environ(), append(env, "OVCP_BACKUP_PASSPHRASE=backup-pass-123")...)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "refusing to write the archive to a terminal") {
		t.Fatalf("want refusal on a terminal, got err=%v\n%s", err, out)
	}
}

// TestRestorePromptsOnTTY: the archive arrives on stdin while the passphrase
// is typed on the controlling terminal, never read from stdin.
func TestRestorePromptsOnTTY(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) unavailable for a pty")
	}
	src := baseEnv(t)
	if r := run(t, src, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	r := run(t, withEnv(src, "OVCP_BACKUP_PASSPHRASE=backup-pass-123"), "backup", "create")
	archive := filepath.Join(t.TempDir(), "a.ovcpbak")
	if r.code != 0 || os.WriteFile(archive, []byte(r.stdout), 0o600) != nil {
		t.Fatalf("backup create: %+v", r)
	}
	dst := t.TempDir()
	cmd := exec.Command("script", "-qec", binPath+" backup restore < "+archive, "/dev/null")
	cmd.Env = append(os.Environ(), "OVCP_DATA="+dst)
	cmd.Stdin = strings.NewReader("backup-pass-123\n")
	out, err := cmd.CombinedOutput()
	if _, statErr := os.Stat(filepath.Join(dst, "pki", "ca.crt")); err != nil || statErr != nil {
		t.Fatalf("restore with the passphrase typed on the terminal failed: %v\n%s", err, out)
	}
}
