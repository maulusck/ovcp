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
