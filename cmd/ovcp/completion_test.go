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
		!strings.Contains(r.stdout, "vpn") || !strings.Contains(r.stdout, "issue") {
		t.Fatalf("__complete top-level: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn"); r.code != 0 ||
		!strings.Contains(r.stdout, "restart") || strings.Contains(r.stdout, "issue") {
		t.Fatalf("__complete vpn subcommands: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "bogus"); r.code != 0 || strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("__complete unknown command: expected no candidates, got %+v", r)
	}
}

// TestCompleteFlags: commands with no fixed subcommand list complete their
// flag names (read off the same FlagSet real parsing uses); commands with
// one complete the subcommand list instead, at every position.
func TestCompleteFlags(t *testing.T) {
	if r := run(t, nil, "__complete", "ovcp", "issue"); r.code != 0 ||
		!strings.Contains(r.stdout, "-cn") || !strings.Contains(r.stdout, "-key-pass") {
		t.Fatalf("__complete issue flags: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn"); r.code != 0 ||
		strings.Contains(r.stdout, "-ctrl") || !strings.Contains(r.stdout, "start") {
		t.Fatalf("__complete vpn: subcommands, not flags: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "vpn", "start"); r.code != 0 || strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("__complete vpn start: out of scope, expected no candidates: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "serve"); r.code != 0 ||
		!strings.Contains(r.stdout, "-mgmt") || !strings.Contains(r.stdout, "-ctrl") ||
		strings.Contains(r.stdout, "-sock") {
		t.Fatalf("__complete serve: expected -mgmt and -ctrl, no -sock: %+v", r)
	}
}

// TestCompleteAfterGlobalFlags guards the exact bug reported: a global flag
// (-data/-no-color/-log-json/-debug) ahead of the command used to land in
// completeArgs' command-name slot and break completion for everything
// after it; the global flags themselves also never appeared as candidates.
func TestCompleteAfterGlobalFlags(t *testing.T) {
	if r := run(t, nil, "__complete", "ovcp"); r.code != 0 ||
		!strings.Contains(r.stdout, "-data") || !strings.Contains(r.stdout, "-debug") ||
		!strings.Contains(r.stdout, "-no-color") || !strings.Contains(r.stdout, "-log-json") {
		t.Fatalf("__complete top-level: global flags missing, got %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "-log-json", "vpn"); r.code != 0 ||
		!strings.Contains(r.stdout, "restart") || strings.Contains(r.stdout, "issue") {
		t.Fatalf("__complete after one global flag: %+v", r)
	}
	if r := run(t, nil, "__complete", "ovcp", "-data", "/tmp/x", "-no-color", "-debug", "vpn"); r.code != 0 ||
		!strings.Contains(r.stdout, "restart") {
		t.Fatalf("__complete after several global flags (one taking a value): %+v", r)
	}
}
