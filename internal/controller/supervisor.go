package controller

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Supervisor is the one and only way ovcp manages the openvpn worker.
//
// openvpn runs as a plain foreground child of `ovcp serve` — never with
// --daemon. A dedicated goroutine sits in cmd.Wait(), so the child is reaped
// the instant it exits: no zombies, even when ovcp is PID 1 in a container,
// and liveness is the real child handle rather than a pidfile guess.
//
//	Start      fork/exec openvpn (idempotent: no-op if already running)
//	Stop       SIGTERM, wait, SIGKILL on timeout — then reaped
//	Restart    Stop + Start (full fresh process, per spec)
//	Reconnect  SIGUSR1 (soft session reset; keeps the process)
//
// The child is spawned with Pdeathsig=SIGTERM so it can never outlive ovcp:
// if ovcp crashes, the kernel takes openvpn down too. (Pdeathsig is cleared
// only by execve of a setuid *binary*; openvpn is a normal binary that drops
// to nobody via setuid() at runtime, which does not clear it.)
//
// SIGHUP / in-place reload is intentionally not implemented: a fresh Restart
// re-reads every controller-owned file as root, which SIGHUP cannot after
// openvpn drops its own privileges.
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

// supervise owns the child for its whole lifetime on a single, pinned OS
// thread. The pin is what makes Pdeathsig reliable under the Go scheduler:
// the signal is armed against the thread that forked, and that thread stays
// alive (blocked in Wait) until the child exits — so it fires on ovcp's
// death, not on an incidental thread teardown. We never UnlockOSThread; when
// this goroutine returns (child already reaped) the runtime discards the
// thread, which is harmless.
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
	log.Printf("controller: openvpn started (pid %d)", cmd.Process.Pid)
	launched <- nil

	err = cmd.Wait() // reap — no zombie can accumulate
	lf.Close()
	s.stMu.Lock()
	s.running, s.cmd = false, nil
	s.stMu.Unlock()
	close(done)
	log.Printf("controller: openvpn exited (pid %d): %v", cmd.Process.Pid, err)
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
