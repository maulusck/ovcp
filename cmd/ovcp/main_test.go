package main

// Black-box CLI tests: main() calls die() (os.Exit(1)), unsafe in-process,
// so these drive the compiled binary as a subprocess. `serve`/`vpn start`
// spawning real openvpn isn't covered here — internal/api/controller do that.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/store"
)

var binPath string

func TestMain(m *testing.M) {
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
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
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

// TestVersionJSON: -json version must parse, and always carries a version
// (openvpn fields are omitempty — absent, not null/empty-string, when
// openvpn isn't on PATH, which this test env generally doesn't have).
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
// {"error":"..."} on stdout (not stderr's plain "error: ..." text), so a
// script parsing stdout gets a consistent shape on failure too.
func TestJSONErrors(t *testing.T) {
	r := run(t, nil, "-json", "revoke")
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

// TestJSONFullAutomation is the "Ansible module" scenario: every secret a
// command needs supplied only via env var (readSecret's automation path,
// see readSecret's doc comment), -json throughout, zero terminal involved
// (run()'s child gets no tty, same as a real automation environment).
// Guards that no command leaks prompt text onto stdout ahead of its JSON,
// or writes anything to stderr on success — a script parsing stdout by
// position, not just validity, must never see stray bytes.
func TestJSONFullAutomation(t *testing.T) {
	env := withEnv(baseEnv(t), "OVCP_JSON=1")
	assertCleanJSON := func(t *testing.T, r result, v any) {
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

	assertCleanJSON(t, run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", "admin"), &initOut{})
	assertCleanJSON(t, run(t, env, "issue", "-cn", "alice"), &issueOut{})

	var rows []certOut
	assertCleanJSON(t, run(t, env, "list"), &rows)
	var serial string
	for _, c := range rows {
		if c.CN == "alice" {
			serial = c.Serial
		}
	}
	if serial == "" {
		t.Fatalf("alice not found in list output: %+v", rows)
	}
	assertCleanJSON(t, run(t, env, "revoke", "-serial", serial), &revokeOut{})
	assertCleanJSON(t, run(t, env, "renew-server"), &renewOut{})

	rotate := withEnv(env, "OVCP_CA_NEW_PASSPHRASE=a totally different passphrase")
	assertCleanJSON(t, run(t, rotate, "rotate-ca"), &outcome{})

	backupFile := filepath.Join(t.TempDir(), "backup.ovcpbak")
	create := withEnv(env, "OVCP_BACKUP_PASSPHRASE=backup-pass-123")
	assertCleanJSON(t, run(t, create, "backup", "create", "-out", backupFile), &backupCreateOut{})

	addBob := withEnv(env, "OVCP_USER_PASSWORD=bobs-password-1")
	assertCleanJSON(t, run(t, addBob, "user", "add", "-name", "bob", "-role", "operator"), &userAddOut{})
}

// TestJSONMissingSecretNoTTY backs the man page's "no env var, no terminal:
// fails fast, on any command" claim — every readSecret call site is this
// same function, so proving it for both the confirm=false (single prompt:
// issue) and confirm=true (prompt+confirm: rotate-ca) shapes covers every
// call site without re-testing all of them individually.
func TestJSONMissingSecretNoTTY(t *testing.T) {
	env := withEnv(baseEnv(t), "OVCP_JSON=1")
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	noSecrets := []string{"OVCP_DATA=" + dataDir(env), "OVCP_JSON=1"}

	for _, args := range [][]string{
		{"issue", "-cn", "alice"}, // confirm=false: one prompt
		{"rotate-ca"},             // confirm=true: prompt + confirm
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
// commands table (the one dispatch/helpText/completion all already share)
// must have a working, non-empty -h that names itself — table-driven so a
// newly added command is covered for free, not just whichever ones other
// tests happen to exercise. This is exactly the class of bug that motivated
// it: user/backup/telegram's -h used to print nothing at all.
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

// TestDataFlagPosition covers the -data CLI flag itself (every other test
// uses OVCP_DATA instead). -data is parsed before the subcommand name, so
// it must come first: ovcp -data DIR <command>, like git -C / docker -H.
func TestDataFlagPosition(t *testing.T) {
	dir := t.TempDir()
	env := []string{
		"OVCP_CA_PASSPHRASE=correct horse battery staple",
		"OVCP_USER_PASSWORD=admin-password-1",
	}
	if r := run(t, env, "-data", dir, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init with -data flag: %+v", r)
	}
	if r := run(t, env, "-data", dir, "list"); r.code != 0 || len(certLines(r.stdout, "server")) != 1 {
		t.Fatalf("-data flag before the subcommand should target dir: %+v", r)
	}
}

// TestGlobalFlagsBeforeCommand guards the bug this session fixed: several
// global flags stacked before the command (including -debug and -json,
// which replaced -log-json) must still dispatch correctly and be stripped
// the same way completion strips them (see TestCompleteAfterGlobalFlags).
// -mgmt (renamed from -sock, alongside serve's new -ctrl) must still reach
// server.conf.
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

	if r := run(t, env, "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}

	list := run(t, env, "list")
	rows := certLines(list.stdout, "alice")
	if list.code != 0 || len(rows) != 1 {
		t.Fatalf("list after issue: %+v", list)
	}
	serial := serialOf(t, rows[0])

	if r := run(t, env, "export", "-cn", "bob", "-remote", "vpn.example.com"); r.code != 0 ||
		!strings.Contains(r.stdout, "BEGIN CERTIFICATE") || !strings.Contains(r.stdout, "BEGIN PRIVATE KEY") {
		t.Fatalf("export: %+v", r)
	}

	if r := run(t, env, "revoke", "-serial", serial); r.code != 0 {
		t.Fatalf("revoke: %+v", r)
	}
	list = run(t, env, "list")
	if rows := certLines(list.stdout, "alice"); len(rows) != 1 || !strings.Contains(rows[0], "REVOKED") {
		t.Fatalf("expected alice REVOKED: %+v", list)
	}

	audit := run(t, env, "audit")
	if audit.code != 0 || !strings.Contains(audit.stdout, "issue") || !strings.Contains(audit.stdout, "revoke") {
		t.Fatalf("audit: %+v", audit)
	}
}

// TestStats covers the snapshot (non-follow) path against an empty history
// — no live openvpn in this test binary, so samples/sessions are always
// empty, but that's enough to exercise the text/json branches and the
// -follow/-json guard without needing a real mgmt socket.
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

func TestListFilterSort(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "bob"); r.code != 0 {
		t.Fatalf("issue bob: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue alice: %+v", r)
	}
	serial := serialOf(t, certLines(run(t, env, "list").stdout, "bob")[0])
	if r := run(t, env, "revoke", "-serial", serial); r.code != 0 {
		t.Fatalf("revoke: %+v", r)
	}

	if r := run(t, env, "list", "-status", "revoked"); len(certLines(r.stdout, "bob")) != 1 || len(certLines(r.stdout, "alice")) != 0 {
		t.Fatalf("-status revoked should show only bob: %+v", r)
	}
	if r := run(t, env, "list", "-status", "active"); len(certLines(r.stdout, "alice")) != 1 || len(certLines(r.stdout, "bob")) != 0 {
		t.Fatalf("-status active should exclude revoked bob: %+v", r)
	}
	if r := run(t, env, "list", "-kind", "server"); len(certLines(r.stdout, "vpn.example.com")) != 1 || len(certLines(r.stdout, "alice")) != 0 {
		t.Fatalf("-kind server should show only the server cert: %+v", r)
	}

	r := run(t, env, "list", "-status", "all", "-sort", "cn")
	rows := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(rows) != 3 || !strings.Contains(rows[0], "alice") {
		t.Fatalf("-sort cn should put alice first: %+v", r)
	}
	r = run(t, env, "list", "-status", "all", "-sort", "cn", "-desc")
	rows = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(rows) != 3 || !strings.Contains(rows[0], "vpn.example.com") {
		t.Fatalf("-sort cn -desc should put vpn.example.com first: %+v", r)
	}

	// an unrecognized -sort value must error, not silently fall back to
	// unsorted output that looks like it worked.
	if r := run(t, env, "list", "-sort", "name"); r.code == 0 {
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
	if r := run(t, env, "issue", "-cn", "soon", "-days", "10"); r.code != 0 {
		t.Fatalf("issue soon: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "fine", "-days", "400"); r.code != 0 {
		t.Fatalf("issue fine: %+v", r)
	}

	r := run(t, env, "list")
	if rows := certLines(r.stdout, "soon"); len(rows) != 1 || !strings.Contains(rows[0], "expiring") {
		t.Fatalf("expected soon expiring: %+v", r)
	}
	if rows := certLines(r.stdout, "fine"); len(rows) != 1 || !strings.Contains(rows[0], "valid") {
		t.Fatalf("expected fine valid: %+v", r)
	}

	r = run(t, env, "-json", "list")
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
	if !strings.HasPrefix(strings.TrimSpace(r.stdout), "alice") {
		t.Fatalf("-sort username should put alice first: %+v", r)
	}
	r = run(t, env, "user", "list", "-sort", "username", "-desc")
	if !strings.HasPrefix(strings.TrimSpace(r.stdout), "charlie") {
		t.Fatalf("-sort username -desc should put charlie first: %+v", r)
	}
}

// TestIssueValidation covers the two footguns `issue` used to allow
// silently: an encrypted server key (unbootable, openvpn can't prompt for
// it non-interactively) and a non-positive validity (already-expired cert).
func TestIssueValidation(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "vpn.example.com", "-kind", "server", "-key-pass", "hunter2"); r.code == 0 {
		t.Fatalf("server cert with -key-pass should be rejected: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "alice", "-days", "0"); r.code == 0 {
		t.Fatalf("-days 0 should be rejected: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "alice", "-days", "-5"); r.code == 0 {
		t.Fatalf("-days -5 should be rejected: %+v", r)
	}
	// the client-cert / positive-days path itself must still work
	if r := run(t, env, "issue", "-cn", "alice", "-key-pass", "hunter2"); r.code != 0 {
		t.Fatalf("client cert with -key-pass should still work: %+v", r)
	}
}

func TestRenewServerValidation(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "renew-server", "-days", "0"); r.code == 0 {
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

// TestExportFollowsConfig covers the bug where `export` ignored the
// persisted server config (as set via the web UI's Settings tab) and always
// rendered a profile pointing at the hardcoded 1194/udp/AES-256-GCM
// defaults regardless of what the server was actually running.
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
	if err := s.SetSetting("server_config", string(raw)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r := run(t, env, "export", "-cn", "alice", "-remote", "vpn.example.com")
	if r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
	for _, want := range []string{"remote vpn.example.com 51820", "proto tcp", "data-ciphers CHACHA20-POLY1305"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("export should follow the configured server, missing %q: %+v", want, r)
		}
	}

	// an explicit flag still overrides the configured default
	r2 := run(t, env, "export", "-cn", "bob", "-remote", "vpn.example.com", "-port", "1234", "-proto", "udp")
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
	r := run(t, env, "export", "-cn", "alice", "-remote", "vpn.example.com", "-split-tunnel")
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
	if err := s.SetSetting("server_config", string(raw)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	r2 := run(t, env, "export", "-cn", "bob", "-remote", "vpn.example.com", "-split-tunnel")
	if r2.code == 0 {
		t.Fatalf("split-tunnel should be rejected when the server doesn't redirect: %+v", r2)
	}
}

func TestCommaOrLines(t *testing.T) {
	if got := commaOrLines("keepalive 5 30"); got != "keepalive 5 30" {
		t.Fatalf("single directive should pass through unchanged, got %q", got)
	}
	if got := commaOrLines("keepalive 5 30, verb 4"); got != "keepalive 5 30\nverb 4" {
		t.Fatalf("comma list should split into lines, got %q", got)
	}
	if got := commaOrLines("keepalive 5 30\nverb 4"); got != "keepalive 5 30\nverb 4" {
		t.Fatalf("already-newlined text (e.g. $(cat FILE)) must pass through unchanged, got %q", got)
	}
}

func TestExportCustomOpts(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	r := run(t, env, "export", "-cn", "alice", "-remote", "vpn.example.com", "-custom-opts", "keepalive 5 30,verb 4")
	if r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
	for _, want := range []string{"keepalive 5 30", "verb 4"} {
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

	// rotate-ca has no flags of its own, so -h must still exit 0 without
	// falling through to the real (interactive, passphrase-changing) op.
	if r := run(t, env, "rotate-ca", "-h"); r.code != 0 {
		t.Fatalf("rotate-ca -h: %+v", r)
	}
	if r := run(t, env, "issue", "-cn", "presanity"); r.code != 0 {
		t.Fatalf("rotate-ca -h must not have rotated the CA: %+v", r)
	}

	rotate := withEnv(env, "OVCP_CA_NEW_PASSPHRASE=a totally different passphrase")
	if r := run(t, rotate, "rotate-ca"); r.code != 0 {
		t.Fatalf("rotate-ca: %+v", r)
	}

	if r := run(t, env, "issue", "-cn", "carol"); r.code == 0 {
		t.Fatalf("issue with the old CA passphrase should now fail: %+v", r)
	}

	newPass := []string{"OVCP_DATA=" + dataDir(env), "OVCP_CA_PASSPHRASE=a totally different passphrase"}
	if r := run(t, newPass, "issue", "-cn", "carol"); r.code != 0 {
		t.Fatalf("issue with the new CA passphrase should work: %+v", r)
	}
}

// TestNoFlagCommandsAcceptHelp: commands with no flags of their own still
// parse an (empty) FlagSet, so -h and unknown flags behave like every
// other command instead of being silently ignored.
func TestNoFlagCommandsAcceptHelp(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	for _, args := range [][]string{{"version", "-h"}, {"list", "-h"}, {"audit", "-h"}, {"user", "list", "-h"}} {
		if r := run(t, env, args...); r.code != 0 {
			t.Fatalf("%v should exit 0 on -h: %+v", args, r)
		}
	}
	if r := run(t, env, "list", "-bogus"); r.code == 0 {
		t.Fatalf("unknown flag on a no-flag command should still fail: %+v", r)
	}
}

func TestRenewServer(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	before := len(certLines(run(t, env, "list").stdout, "server"))

	if r := run(t, env, "renew-server"); r.code != 0 {
		t.Fatalf("renew-server: %+v", r)
	}

	after := len(certLines(run(t, env, "list").stdout, "server"))
	if after != before+1 {
		t.Fatalf("expected one more server cert row: before=%d after=%d", before, after)
	}
	if r := run(t, env, "audit"); !strings.Contains(r.stdout, "renew_server") {
		t.Fatalf("audit missing renew_server: %+v", r)
	}
}

// TestBackupRestore mirrors the documented disaster-recovery flow: create,
// restore into a fresh dir (wrong passphrase must fail), confirm no server
// cert came along, renew-server, and confirm existing cert metadata survived.
func TestBackupRestore(t *testing.T) {
	src := baseEnv(t)
	if r := run(t, src, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, src, "issue", "-cn", "alice"); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}

	backupFile := filepath.Join(t.TempDir(), "backup.ovcpbak")
	create := withEnv(src, "OVCP_BACKUP_PASSPHRASE=backup-pass-123")
	if r := run(t, create, "backup", "create", "-out", backupFile); r.code != 0 {
		t.Fatalf("backup create: %+v", r)
	}

	dstDir := t.TempDir()
	wrongPass := []string{"OVCP_DATA=" + dstDir, "OVCP_BACKUP_PASSPHRASE=wrong"}
	if r := run(t, wrongPass, "backup", "restore", backupFile); r.code == 0 {
		t.Fatalf("restore with wrong passphrase should fail: %+v", r)
	}

	restore := []string{"OVCP_DATA=" + dstDir, "OVCP_BACKUP_PASSPHRASE=backup-pass-123"}
	if r := run(t, restore, "backup", "restore", backupFile); r.code != 0 {
		t.Fatalf("backup restore: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "pki", "server.crt")); err == nil {
		t.Fatal("server.crt should not exist right after restore")
	}

	renew := []string{"OVCP_DATA=" + dstDir, "OVCP_SERVER_CN=vpn.example.com",
		"OVCP_CA_PASSPHRASE=correct horse battery staple"}
	if r := run(t, renew, "renew-server"); r.code != 0 {
		t.Fatalf("renew-server after restore: %+v", r)
	}
	if r := run(t, renew, "list"); r.code != 0 || len(certLines(r.stdout, "alice")) != 1 {
		t.Fatalf("restored db should still have alice: %+v", r)
	}

	// dstDir is now initialized: restore must refuse without -force, and
	// -force only works before the positional FILE arg (flag.Parse stops at
	// the first non-flag arg) — usage text got that backwards once already.
	if r := run(t, restore, "backup", "restore", backupFile); r.code == 0 {
		t.Fatalf("restore over an initialized dir without -force should fail: %+v", r)
	}
	if r := run(t, restore, "backup", "restore", backupFile, "-force"); r.code == 0 {
		t.Fatalf("-force after FILE is silently ignored by flag.Parse; this must still fail: %+v", r)
	}
	if r := run(t, restore, "backup", "restore", "-force", backupFile); r.code != 0 {
		t.Fatalf("-force before FILE should overwrite: %+v", r)
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
	if r := run(t, env, "user", "list"); !strings.Contains(r.stdout, "DISABLED") {
		t.Fatalf("expected DISABLED: %+v", r)
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

// TestUnreachableServe covers the CLI's error wiring when no `serve` process
// is up: every remote-control command should fail cleanly with a nonzero
// exit rather than hang or panic.
// TestTelegramTokenValidation covers what's reachable without a real
// Telegram API call: -admin is required, and an unknown telegram op errors.
// The success path (valid token accepted, saved) is covered in
// internal/telegram's own tests against a mocked API — this binary talks to
// the real api.telegram.org, which a unit test must not depend on.
func TestTelegramTokenValidation(t *testing.T) {
	env := baseEnv(t)
	if r := run(t, env, "init", "-server-cn", "vpn.example.com", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := run(t, env, "telegram", "token"); r.code == 0 {
		t.Fatalf("telegram token without -admin should fail: %+v", r)
	}
	if r := run(t, env, "telegram", "bogus"); r.code == 0 {
		t.Fatalf("telegram bogus should fail: %+v", r)
	}
}

// TestFlagAfterOp guards against a real bug this exact shape hit once:
// vpn/debug/telegram used to register -ctrl on the FlagSet main()'s
// dispatch loop parses before the op is even known, so "ovcp vpn start
// -ctrl X" (flag after the op — the normal git/docker/kubectl order)
// silently parsed nothing past "start" and fell back to the default
// socket instead of erroring or using X. Asserting the error names the
// bogus path proves -ctrl was actually parsed, not silently dropped.
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
	if r := run(t, env, "debug", "on"); r.code == 0 {
		t.Fatalf("debug on with no serve running should fail: %+v", r)
	}
	if r := run(t, env, "telegram", "status"); r.code == 0 {
		t.Fatalf("telegram status with no serve running should fail: %+v", r)
	}
	// status is deliberately soft: no worker to report on isn't a CLI error.
	if r := run(t, env, "status"); r.code != 0 || !strings.Contains(r.stdout, "OpenVPN: unknown") {
		t.Fatalf("status with no serve running: %+v", r)
	}

	kill := withEnv(env, "OVCP_MGMT_SOCK="+filepath.Join(t.TempDir(), "mgmt.sock"))
	if r := run(t, kill, "kill", "-cn", "nobody"); r.code == 0 {
		t.Fatalf("kill with no mgmt socket should fail: %+v", r)
	}
}
