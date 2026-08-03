package controller

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeOpenVPN stands in for the real binary (ignores args, just sleeps) so
// tests can exercise spawn/signal/reap without openvpn or root.
func fakeOpenVPN(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-openvpn.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newSup(t *testing.T) *Supervisor {
	return &Supervisor{
		Name:     "openvpn",
		Bin:      fakeOpenVPN(t),
		Args:     []string{"--config", "/dev/null"},
		LogPath:  filepath.Join(t.TempDir(), "openvpn.log"),
		StopWait: 3 * time.Second,
	}
}

func TestStartStopReaps(t *testing.T) {
	s := newSup(t)
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !s.Running() {
		t.Fatal("expected running after Start")
	}
	pid := s.cmd.Process.Pid
	if err := s.Start(); err != nil || s.cmd.Process.Pid != pid {
		t.Fatal("Start must be idempotent (no second child)")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if s.Running() {
		t.Fatal("still running after Stop")
	}
	// A reaped child is fully gone; a *zombie* would still answer signal 0.
	// This is the regression guard for the container zombie bug.
	if syscall.Kill(pid, 0) == nil {
		t.Fatal("child not reaped — signal 0 still succeeds (zombie)")
	}
}

// TestBusy: a Start genuinely in flight (blocked in PreStart, real opMu hold,
// no synthetic lock/sleep) must reject a concurrent one — and admit a new
// call only once that real op has actually finished.
func TestBusy(t *testing.T) {
	s := newSup(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	s.PreStart = func() []string {
		close(entered)
		<-release
		return []string{"--config", "/dev/null"}
	}
	go func() { done <- s.Start() }()
	<-entered // first Start is now mid-flight, opMu genuinely held

	if err := s.Start(); !errors.Is(err, ErrBusy) {
		t.Fatalf("Start while another is mid-flight: got %v, want ErrBusy", err)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("blocked start: %v", err)
	}
	if !s.Running() {
		t.Fatal("expected running once the blocked op completed")
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start after real completion: %v", err)
	}
}

// TestPreStart: a non-nil PreStart must recompute Args before every launch,
// not just the first one.
func TestPreStart(t *testing.T) {
	firstArgs := []string{"-first"}
	secondArgs := []string{"-second"}
	calls := 0
	s := newSup(t)
	s.PreStart = func() []string {
		calls++
		if calls == 1 {
			return firstArgs
		}
		return secondArgs
	}

	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || s.Args[0] != firstArgs[0] {
		t.Fatalf("after Start: calls=%d args=%v, want calls=1 args=%v", calls, s.Args, firstArgs)
	}

	if err := s.Restart(); err != nil {
		t.Fatal(err)
	}
	s.Stop()
	if calls != 2 || s.Args[0] != secondArgs[0] {
		t.Fatalf("after Restart: calls=%d args=%v, want calls=2 args=%v", calls, s.Args, secondArgs)
	}
}

func TestRestart(t *testing.T) {
	s := newSup(t)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	old := s.cmd.Process.Pid
	if err := s.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !s.Running() || s.cmd.Process.Pid == old {
		t.Fatal("restart must yield a fresh child")
	}
	s.Stop()
	if syscall.Kill(old, 0) == nil {
		t.Fatal("old child not reaped after restart")
	}
}

func TestReconnectRequiresRunning(t *testing.T) {
	s := newSup(t)
	if err := s.Reconnect(); err == nil {
		t.Fatal("reconnect with no process must error")
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if err := s.Reconnect(); err != nil {
		t.Fatalf("reconnect while running: %v", err)
	}
}

// crashingOpenVPN exits immediately every launch, simulating a crash rather
// than a clean, requested stop.
func crashingOpenVPN(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "crashing-openvpn.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCrashLoopBreakerStopsRetrying(t *testing.T) {
	s := &Supervisor{
		Name:              "openvpn",
		Bin:               crashingOpenVPN(t),
		Args:              []string{"--config", "/dev/null"},
		LogPath:           filepath.Join(t.TempDir(), "openvpn.log"),
		CrashRestartDelay: 5 * time.Millisecond,
		CrashLoopWindow:   time.Second,
		CrashLoopMax:      3,
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.stMu.Lock()
		streak := s.crashStreak
		s.stMu.Unlock()
		if streak > s.CrashLoopMax {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.stMu.Lock()
	streak := s.crashStreak
	s.stMu.Unlock()
	if streak <= s.CrashLoopMax {
		t.Fatalf("expected crash-loop breaker to trip within 2s, streak=%d", streak)
	}
	time.Sleep(20 * time.Millisecond) // let any in-flight restart attempt settle
	if s.Running() {
		t.Fatal("should have given up auto-restarting after crash-looping")
	}
}

// TestOnExitFiresOnStopAndCrash: whatever a caller tracked about the child's
// current life must be invalidated the instant that instance is gone —
// covers both an explicit Stop and an unexpected crash, the two ways
// running flips false.
func TestOnExitFiresOnStopAndCrash(t *testing.T) {
	var stopFires int32
	s := newSup(t)
	s.OnExit = func() { atomic.AddInt32(&stopFires, 1) }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := atomic.LoadInt32(&stopFires); got != 1 {
		t.Fatalf("OnExit fired %d times on Stop, want 1", got)
	}

	var crashFires int32
	c := &Supervisor{
		Name:    "openvpn",
		Bin:     crashingOpenVPN(t),
		Args:    []string{"--config", "/dev/null"},
		LogPath: filepath.Join(t.TempDir(), "openvpn.log"),
		OnExit:  func() { atomic.AddInt32(&crashFires, 1) },
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&crashFires) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&crashFires); got == 0 {
		t.Fatal("OnExit must also fire on an unexpected crash, not just Stop")
	}
}

func TestStopDoesNotAutoRestart(t *testing.T) {
	s := &Supervisor{
		Name:              "openvpn",
		Bin:               fakeOpenVPN(t),
		Args:              []string{"--config", "/dev/null"},
		LogPath:           filepath.Join(t.TempDir(), "openvpn.log"),
		CrashRestartDelay: 5 * time.Millisecond,
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // past CrashRestartDelay — must NOT come back
	if s.Running() {
		t.Fatal("an explicit Stop must not trigger auto-restart")
	}
}

// TestOpenVPNVersion stubs a script named "openvpn" on PATH so it never
// depends on the real binary being installed.
func TestOpenVPNVersion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "openvpn")
	script := "#!/bin/sh\necho 'OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)]'\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	version, path, ok := OpenVPNVersion()
	if !ok || version != "OpenVPN 2.6.14" || path != p {
		t.Fatalf("got version=%q path=%q ok=%v, want %q %q true", version, path, ok, "OpenVPN 2.6.14", p)
	}
}

// TestOpenVPNVersionNotFound: no openvpn on PATH must report ok=false, not an error.
func TestOpenVPNVersionNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, ok := OpenVPNVersion(); ok {
		t.Fatal("expected ok=false with no openvpn on PATH")
	}
}

// TestDnsmasqVersion stubs a script named "dnsmasq" on PATH so it never
// depends on the real binary being installed.
func TestDnsmasqVersion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dnsmasq")
	script := "#!/bin/sh\necho 'Dnsmasq version 2.90  Copyright (c) 2000-2023 Simon Kelley'\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	version, path, ok := DnsmasqVersion()
	if !ok || version != "Dnsmasq 2.90" || path != p {
		t.Fatalf("got version=%q path=%q ok=%v, want %q %q true", version, path, ok, "Dnsmasq 2.90", p)
	}
}

// TestDnsmasqVersionNotFound: no dnsmasq on PATH must report ok=false, not an error.
func TestDnsmasqVersionNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, ok := DnsmasqVersion(); ok {
		t.Fatal("expected ok=false with no dnsmasq on PATH")
	}
}

// TestLogLines: every line gets ovcp's own RFC3339 prefix, including an
// unterminated final line — neither worker can be trusted to timestamp its
// own output (dnsmasq's stderr mode doesn't; openvpn's own format doesn't
// match what the web UI parses).
func TestLogLines(t *testing.T) {
	var buf bytes.Buffer
	logLines(strings.NewReader("first line\nsecond line\nno trailing newline"), &buf)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), buf.String())
	}
	stamp := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) `)
	want := []string{"first line", "second line", "no trailing newline"}
	for i, l := range lines {
		if !stamp.MatchString(l) {
			t.Fatalf("line %d missing timestamp prefix: %q", i, l)
		}
		if msg := stamp.ReplaceAllString(l, ""); msg != want[i] {
			t.Fatalf("line %d = %q, want %q", i, msg, want[i])
		}
	}
}

// TestSupervisorLogsAreTimestamped: end to end — a real child process's
// stdout lands in LogPath with the same prefix, not raw passthrough.
func TestSupervisorLogsAreTimestamped(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fake-openvpn.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hello from child\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Supervisor{Name: "openvpn", Bin: p, LogPath: filepath.Join(t.TempDir(), "openvpn.log")}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	for i := 0; i < 50 && s.Running(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	got, err := os.ReadFile(s.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) hello from child\n`).Match(got) {
		t.Fatalf("LogPath = %q, want a timestamped line", got)
	}
}
