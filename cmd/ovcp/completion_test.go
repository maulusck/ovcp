package main

import (
	"strings"
	"testing"
)

func TestCompletionScript(t *testing.T) {
	cases := map[string]string{
		"bash": "_ovcp_complete",
		"zsh":  "#compdef ovcp",
		"fish": "complete -c ovcp",
	}
	for shell, marker := range cases {
		if r := run(t, nil, "completion", shell); r.code != 0 || !strings.Contains(r.stdout, marker) {
			t.Fatalf("completion %s: %+v", shell, r)
		}
	}
	if r := run(t, nil, "completion", "tcsh"); r.code == 0 || !strings.Contains(r.stderr, "usage") {
		t.Fatalf("completion tcsh: expected usage error, got %+v", r)
	}
}

func TestCompleteArgs(t *testing.T) {
	if r := run(t, nil, "__complete", "ovcp"); r.code != 0 ||
		!strings.Contains(r.stdout, "vpn") || !strings.Contains(r.stdout, "certificate") {
		t.Fatalf("__complete top-level: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn"); r.code != 0 ||
		!strings.Contains(r.stdout, "restart") || strings.Contains(r.stdout, "certificate") {
		t.Fatalf("__complete vpn subcommands: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "bogus"); r.code != 0 || strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("__complete unknown command: expected no candidates, got %+v", r)
	}
}

// TestCompleteFlags: flags for a flat command, op names then op flags for a
// dispatched one, and one level deeper still for nested ops (`vpn config set`).
func TestCompleteFlags(t *testing.T) {
	if r := run(t, nil, "__complete", "ovcp", "stats"); r.code != 0 ||
		!strings.Contains(r.stdout, "-cn") || !strings.Contains(r.stdout, "-follow") {
		t.Fatalf("__complete stats flags: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "certificate"); r.code != 0 ||
		!strings.Contains(r.stdout, "issue") || strings.Contains(r.stdout, "-cn") {
		t.Fatalf("__complete certificate: subcommands, not flags: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "certificate", "issue"); r.code != 0 ||
		!strings.Contains(r.stdout, "-cn") || !strings.Contains(r.stdout, "-export") {
		t.Fatalf("__complete certificate issue: op-level flags, got %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn"); r.code != 0 ||
		strings.Contains(r.stdout, "-ctrl") || !strings.Contains(r.stdout, "start") {
		t.Fatalf("__complete vpn: subcommands, not flags: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn", "start"); r.code != 0 ||
		!strings.Contains(r.stdout, "-ctrl") {
		t.Fatalf("__complete vpn start: op-level flag -ctrl, got %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn", "config"); r.code != 0 ||
		!strings.Contains(r.stdout, "get") || !strings.Contains(r.stdout, "set") || strings.Contains(r.stdout, "-subnet") {
		t.Fatalf("__complete vpn config: nested op names, not flags yet: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn", "config", "set"); r.code != 0 ||
		!strings.Contains(r.stdout, "-subnet") {
		t.Fatalf("__complete vpn config set: nested op's own flags, got %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "serve"); r.code != 0 ||
		!strings.Contains(r.stdout, "-mgmt") || !strings.Contains(r.stdout, "-ctrl") ||
		strings.Contains(r.stdout, "-sock") {
		t.Fatalf("__complete serve: expected -mgmt and -ctrl, no -sock: %+v", r)
	}
}

// TestCompleteAfterGlobalFlags guards a real bug: a global flag ahead of the
// command used to land in completeArgs' command-name slot, breaking completion after it and hiding the flags themselves.
func TestCompleteAfterGlobalFlags(t *testing.T) {
	if r := run(t, nil, "__complete", "ovcp"); r.code != 0 ||
		!strings.Contains(r.stdout, "-data") || !strings.Contains(r.stdout, "-debug") ||
		!strings.Contains(r.stdout, "-no-color") || !strings.Contains(r.stdout, "-json") {
		t.Fatalf("__complete top-level: global flags missing, got %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "-json", "vpn"); r.code != 0 ||
		!strings.Contains(r.stdout, "restart") || strings.Contains(r.stdout, "issue") {
		t.Fatalf("__complete after one global flag: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "-data", "/tmp/x", "-no-color", "-debug", "vpn"); r.code != 0 ||
		!strings.Contains(r.stdout, "restart") {
		t.Fatalf("__complete after several global flags (one taking a value): %+v", r)
	}
}
