package controller

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// binVersion resolves bin from PATH and parses its version line, joining
// fields[0] (the name) with fields[verIdx] (the version number — 1 for
// openvpn's "OpenVPN 2.6.3", 2 for dnsmasq's "Dnsmasq version 2.90").
// ok=false (not an error) if not found or unparseable — advisory only,
// never a hard precondition.
func binVersion(bin string, verIdx int) (version, path string, ok bool) {
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", "", false
	}
	out, _ := exec.Command(p, "--version").Output()
	first, _, _ := strings.Cut(string(out), "\n")
	fields := strings.Fields(first)
	if len(fields) <= verIdx {
		return "", "", false
	}
	return fields[0] + " " + fields[verIdx], p, true
}

// OpenVPNVersion is advisory only (`ovcp version`, admin UI), never a precondition.
func OpenVPNVersion() (version, path string, ok bool) { return binVersion("openvpn", 1) }

// DnsmasqVersion gates the Records tab/CLI; advisory only.
func DnsmasqVersion() (version, path string, ok bool) { return binVersion("dnsmasq", 2) }

// Supervisor runs one worker (openvpn or dnsmasq) as a foreground child (Pdeathsig ties its life to ours, surviving the worker's own setuid drop); no SIGHUP — Restart always re-reads fresh instead.
type Supervisor struct {
	Name     string          // "openvpn" | "dnsmasq" — log lines and the not-found error only
	Bin      string          // resolved worker binary path; caller resolves via exec.LookPath, empty means "not found"
	Args     []string        // full argv (excluding argv[0]) — e.g. openvpn's {"--config", path} or dnsmasq's flag set
	PreStart func() []string // optional: recomputes Args fresh before each launch; nil keeps Args static
	LogPath  string          // child stdout/stderr are appended here
	StopWait time.Duration   // graceful SIGTERM timeout; default 5s

	// CrashRestartDelay/CrashLoopWindow/CrashLoopMax tune auto-restart on an
	// unexpected exit: wait Delay, restart, give up after Max such exits in
	// one Window (so a broken config can't spin-loop us). Defaults: 3s/60s/5.
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

// StartedAt returns when the current child was launched, or zero when not
// running — cleared by the reaper alongside running/cmd, so it never lags Pid().
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

// start launches the worker and blocks only until it is up (or fails to launch).
func (s *Supervisor) start() error {
	if s.Running() {
		return nil
	}
	if s.PreStart != nil {
		s.Args = s.PreStart()
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
		launched <- fmt.Errorf("controller: %s not found on PATH", s.Name)
		return
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
	cmd := exec.Command(bin, s.Args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		lf.Close()
		launched <- fmt.Errorf("controller: %s start: %w", s.Name, err)
		return
	}

	done := make(chan struct{})
	s.stMu.Lock()
	s.cmd, s.done, s.running, s.startedAt = cmd, done, true, time.Now()
	s.stMu.Unlock()
	slog.Info(s.Name+" started", "pid", cmd.Process.Pid, "bin", bin)
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
		slog.Info(s.Name+" exited", "pid", cmd.Process.Pid, "err", err, "uptime", uptime)
		return
	}
	slog.Error(s.Name+" exited unexpectedly", "pid", cmd.Process.Pid, "err", err, "uptime", uptime)
	if desired {
		go s.autoRestart()
	}
}

// autoRestart re-launches the worker after an unexpected exit, unless it's
// crash-looping or was explicitly stopped/restarted meanwhile.
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
		slog.Error(s.Name+" crash-looping, giving up auto-restart until manually restarted once the underlying issue is fixed", "streak", streak)
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
// timeout (a child that already exited just returns via the closed done chan).
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
