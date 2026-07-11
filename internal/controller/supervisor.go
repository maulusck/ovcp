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

	opMu sync.Mutex // serializes whole lifecycle operations

	stMu    sync.Mutex // guards the fields below
	cmd     *exec.Cmd
	done    chan struct{} // closed by the reaper once cmd has been Wait()ed
	running bool
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

func (s *Supervisor) Start() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.start()
}

func (s *Supervisor) Stop() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.stop()
}

func (s *Supervisor) Restart() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
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
	s.cmd, s.done, s.running = cmd, done, true
	s.stMu.Unlock()
	slog.Info("openvpn started", "pid", cmd.Process.Pid)
	launched <- nil

	err = cmd.Wait() // reap — no zombie can accumulate
	lf.Close()
	s.stMu.Lock()
	s.running, s.cmd = false, nil
	s.stMu.Unlock()
	close(done)
	slog.Info("openvpn exited", "pid", cmd.Process.Pid, "err", err)
}

// stop sends SIGTERM, waits for the reaper, and escalates to SIGKILL on
// timeout. A child that exits on its own between the snapshot and the signal
// is fine: done is already closed and the select returns at once.
func (s *Supervisor) stop() error {
	cmd, done, running := s.snapshot()
	if !running {
		return nil
	}
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
