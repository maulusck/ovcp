package controller

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Supervisor runs openvpn as a foreground child (Pdeathsig ties its life to ours, surviving openvpn's own setuid drop to nobody); no SIGHUP — Restart always re-reads fresh instead.
type Supervisor struct {
	Bin        string        // openvpn binary; "" → resolve from PATH
	ConfigPath string        // rendered server.conf
	LogPath    string        // child stdout/stderr are appended here
	StopWait   time.Duration // graceful SIGTERM timeout; default 5s

	// CrashRestartDelay/CrashLoopWindow/CrashLoopMax tune the auto-restart
	// on an unexpected exit (crash, OOM-kill, `kill -9` from outside us):
	// wait CrashRestartDelay then restart, but give up once CrashLoopMax
	// such exits happen inside one CrashLoopWindow — a bad config that
	// makes openvpn exit immediately shouldn't spin us in a tight loop.
	// Defaults: 3s / 60s / 5.
	CrashRestartDelay time.Duration
	CrashLoopWindow   time.Duration
	CrashLoopMax      int

	opMu sync.Mutex // serializes whole lifecycle operations

	stMu      sync.Mutex // guards the fields below
	cmd       *exec.Cmd
	done      chan struct{} // closed by the reaper once cmd has been Wait()ed
	running   bool
	desired   bool      // true once Start/Restart has been asked for; false after Stop — gates auto-restart
	stopped   bool      // set by stop() just before signaling, so the reaper can tell "we did this" from a crash
	startedAt time.Time // when the current child was launched; zero when not running

	crashAt     time.Time
	crashStreak int
}

func (s *Supervisor) snapshot() (*exec.Cmd, chan struct{}, bool) {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	return s.cmd, s.done, s.running
}

// Running reports whether an openvpn child is currently up.
func (s *Supervisor) Running() bool {
	_, _, r := s.snapshot()
	return r
}

// Pid returns the current openvpn pid, or 0 when not running.
func (s *Supervisor) Pid() int {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	if !s.running || s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// StartedAt returns when the current openvpn child was launched, or the
// zero time when not running — cleared by the reaper on every exit path
// (clean stop or crash) alongside running/cmd, so it never lags Pid().
func (s *Supervisor) StartedAt() time.Time {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	if !s.running {
		return time.Time{}
	}
	return s.startedAt
}

func (s *Supervisor) Start() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.stMu.Lock()
	s.desired = true
	s.stMu.Unlock()
	return s.start()
}

func (s *Supervisor) Stop() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.stMu.Lock()
	s.desired = false
	s.stMu.Unlock()
	return s.stop()
}

func (s *Supervisor) Restart() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.stMu.Lock()
	s.desired = true
	s.stMu.Unlock()
	if err := s.stop(); err != nil {
		return err
	}
	return s.start()
}

func (s *Supervisor) Reconnect() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	cmd, _, running := s.snapshot()
	if !running {
		return fmt.Errorf("controller: openvpn not running")
	}
	return cmd.Process.Signal(syscall.SIGUSR1)
}

// start launches openvpn and blocks only until it is up (or fails to launch).
func (s *Supervisor) start() error {
	if s.Running() {
		return nil
	}
	launched := make(chan error, 1)
	go s.supervise(launched)
	return <-launched
}

// supervise pins its OS thread so Pdeathsig stays armed against the forking thread until the child exits, not an incidental thread teardown.
func (s *Supervisor) supervise(launched chan<- error) {
	runtime.LockOSThread()

	bin := s.Bin
	if bin == "" {
		p, err := exec.LookPath("openvpn")
		if err != nil {
			launched <- fmt.Errorf("controller: openvpn not found on PATH")
			return
		}
		bin = p
	}
	if err := os.MkdirAll(filepath.Dir(s.LogPath), 0o750); err != nil {
		launched <- err
		return
	}
	lf, err := os.OpenFile(s.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		launched <- err
		return
	}
	cmd := exec.Command(bin, "--config", s.ConfigPath)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		lf.Close()
		launched <- fmt.Errorf("controller: openvpn start: %w", err)
		return
	}

	done := make(chan struct{})
	s.stMu.Lock()
	s.cmd, s.done, s.running, s.startedAt = cmd, done, true, time.Now()
	s.stMu.Unlock()
	slog.Info("openvpn started", "pid", cmd.Process.Pid)
	launched <- nil

	err = cmd.Wait() // reap — no zombie can accumulate; runs for both a clean stop() and an unexpected crash
	lf.Close()
	s.stMu.Lock()
	stopped := s.stopped
	s.stopped = false
	startedAt := s.startedAt
	s.running, s.cmd, s.startedAt = false, nil, time.Time{}
	desired := s.desired
	s.stMu.Unlock()
	close(done)

	uptime := time.Since(startedAt).Round(time.Second)
	if stopped {
		slog.Info("openvpn exited", "pid", cmd.Process.Pid, "err", err, "uptime", uptime)
		return
	}
	slog.Error("openvpn exited unexpectedly", "pid", cmd.Process.Pid, "err", err, "uptime", uptime)
	if desired {
		go s.autoRestart()
	}
}

// autoRestart re-launches openvpn after an unexpected exit, unless it's
// crash-looping (CrashLoopMax exits inside CrashLoopWindow) or the VPN has
// been explicitly stopped/restarted in the meantime.
func (s *Supervisor) autoRestart() {
	delay, window, max := s.CrashRestartDelay, s.CrashLoopWindow, s.CrashLoopMax
	if delay == 0 {
		delay = 3 * time.Second
	}
	if window == 0 {
		window = 60 * time.Second
	}
	if max == 0 {
		max = 5
	}

	s.stMu.Lock()
	if time.Since(s.crashAt) > window {
		s.crashStreak = 0
	}
	s.crashStreak++
	s.crashAt = time.Now()
	streak := s.crashStreak
	s.stMu.Unlock()
	if streak > max {
		slog.Error("openvpn crash-looping, giving up auto-restart; run `ovcp vpn start` once the underlying issue is fixed", "streak", streak)
		return
	}

	time.Sleep(delay)
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.stMu.Lock()
	stillWanted := s.desired && !s.running
	s.stMu.Unlock()
	if !stillWanted {
		return
	}
	if err := s.start(); err != nil {
		slog.Error("openvpn auto-restart failed", "err", err)
		return
	}
	slog.Info("openvpn auto-restarted", "streak", streak)
}

// stop sends SIGTERM, waits for the reaper, and escalates to SIGKILL on
// timeout. A child that exits on its own between the snapshot and the signal
// is fine: done is already closed and the select returns at once.
func (s *Supervisor) stop() error {
	cmd, done, running := s.snapshot()
	if !running {
		return nil
	}
	s.stMu.Lock()
	s.stopped = true
	s.stMu.Unlock()
	cmd.Process.Signal(syscall.SIGTERM)
	wait := s.StopWait
	if wait == 0 {
		wait = 5 * time.Second
	}
	select {
	case <-done:
	case <-time.After(wait):
		cmd.Process.Kill()
		<-done
	}
	return nil
}
