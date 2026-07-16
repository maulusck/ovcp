package controller

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeOpenVPN writes a tiny script that ignores openvpn's args and just
// sleeps, standing in for the real binary so we can exercise the child
// lifecycle (spawn, signal, reap) without openvpn or root.
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
		Bin:        fakeOpenVPN(t),
		ConfigPath: "/dev/null",
		LogPath:    filepath.Join(t.TempDir(), "openvpn.log"),
		StopWait:   3 * time.Second,
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

// crashingOpenVPN exits immediately every launch, simulating a crash (or an
// external `kill -9`) rather than a clean, requested stop.
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
		Bin:               crashingOpenVPN(t),
		ConfigPath:        "/dev/null",
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

func TestStopDoesNotAutoRestart(t *testing.T) {
	s := &Supervisor{
		Bin:               fakeOpenVPN(t),
		ConfigPath:        "/dev/null",
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

// TestOpenVPNVersion stubs a script named exactly "openvpn" on PATH (the
// LookPath match), so it never depends on real openvpn being installed.
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

// TestOpenVPNVersionNotFound: no openvpn on PATH must report ok=false, not
// an error — this is advisory, not a precondition.
func TestOpenVPNVersionNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, ok := OpenVPNVersion(); ok {
		t.Fatal("expected ok=false with no openvpn on PATH")
	}
}
