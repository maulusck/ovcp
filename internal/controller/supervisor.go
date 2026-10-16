package controller

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// logLines timestamps every line from r and appends it to w — one format,
// ovcp-owned, not each worker's own (missing/inconsistent) self-stamp. 1MB/line
// ceiling so one pathological line can't silently truncate the rest of the stream.
func logLines(r io.Reader, w io.Writer) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fmt.Fprintf(w, "%s %s\n", time.Now().Format(time.RFC3339), sc.Text())
	}
}

// binVersion resolves bin from PATH and parses its version line, joining
// fields[0] (name) with fields[verIdx] (version — 1 for openvpn, 2 for
// dnsmasq). ok=false (not an error) if not found or unparseable — advisory only.
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

// NftablesVersion gates the Upstreams tab/CLI; advisory only.
func NftablesVersion() (version, path string, ok bool) { return binVersion("nft", 1) }

// ipForwardPath: package var like ipBin/nftBin in internal/upstream, so
// tests can point it at a fixture instead of the real /proc.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// ipForwardEnabled reads the live kernel setting directly — the one thing
// that's ever authoritative for it, no sysctl binary needed.
func ipForwardEnabled() bool {
	b, err := os.ReadFile(ipForwardPath)
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// natConfigured heuristically checks the standard iptables nat table for a
// MASQUERADE/SNAT rule — the setup path most OpenVPN guides document.
// checked=false (verdict ignored by the caller) whenever it can't be sure:
// no iptables on PATH, or the command itself failed (e.g. no permission) —
// an nftables-only/firewalld-only host reads the same as "can't tell", not
// "missing", so this never contradicts a setup it simply didn't recognize.
func natConfigured() (found, checked bool) {
	p, err := exec.LookPath("iptables")
	if err != nil {
		return false, false
	}
	out, err := exec.Command(p, "-t", "nat", "-S", "POSTROUTING").Output()
	if err != nil {
		return false, false
	}
	up := strings.ToUpper(string(out))
	return strings.Contains(up, "MASQUERADE") || strings.Contains(up, "SNAT"), true
}

// RoutingPrereqsWarning flags host routing VPN clients need to reach the
// internet that ovcp doesn't provide: forwarding always, NAT unless ovcpNAT
// (upstreams enabled: ovcp's nft table masquerades ovcp0). Advisory only;
// "" means clean, including "couldn't verify NAT" — see natConfigured.
func RoutingPrereqsWarning(ovcpNAT bool) string {
	var missing []string
	if !ipForwardEnabled() {
		missing = append(missing, "IPv4 forwarding is off (sysctl -w net.ipv4.ip_forward=1)")
	}
	if found, checked := natConfigured(); !ovcpNAT && checked && !found {
		missing = append(missing, "no outbound NAT/masquerade rule found in iptables' nat table")
	}
	if len(missing) == 0 {
		return ""
	}
	return "baseline routing: " + strings.Join(missing, "; ")
}

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

	// OnCrashLoopGiveUp, if set, fires once when auto-restart gives up —
	// the one worker failure that needs a push, not just a log line.
	OnCrashLoopGiveUp func(streak int)

	// OnExit, if set, fires every time the child stops running — explicit
	// Stop/Restart or a crash alike — right as running flips false. Whatever
	// state a caller held about that specific process instance is now
	// unconditionally gone.
	OnExit func()

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

// acquireOp claims opMu for one lifecycle op — held for the op's real
// duration, so the next request is only ever allowed in once this op has
// genuinely reported its finish status (success or error), not a guessed delay.
func (s *Supervisor) acquireOp() error {
	if !s.opMu.TryLock() {
		return fmt.Errorf("controller: %s: %w", s.Name, ErrBusy)
	}
	return nil
}

func (s *Supervisor) Start() error {
	if err := s.acquireOp(); err != nil {
		return err
	}
	defer s.opMu.Unlock()
	s.stMu.Lock()
	s.desired = true
	s.stMu.Unlock()
	return s.start()
}

func (s *Supervisor) Stop() error {
	if err := s.acquireOp(); err != nil {
		return err
	}
	defer s.opMu.Unlock()
	s.stMu.Lock()
	s.desired = false
	s.stMu.Unlock()
	return s.stop()
}

func (s *Supervisor) Restart() error {
	if err := s.acquireOp(); err != nil {
		return err
	}
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
	if err := s.acquireOp(); err != nil {
		return err
	}
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
	// LogPath's directory is assumed to exist — cmd/ovcp's ensureSkeleton owns creating it.
	lf, err := os.OpenFile(s.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		launched <- err
		return
	}
	// combined stdout+stderr through one pipe, same interleaving guarantee a
	// single shared fd gave before — logLines timestamps each line on the way
	// through to lf instead of a raw passthrough.
	pr, pw, err := os.Pipe()
	if err != nil {
		lf.Close()
		launched <- err
		return
	}
	cmd := exec.Command(bin, s.Args...)
	cmd.Stdout, cmd.Stderr = pw, pw
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		lf.Close()
		launched <- fmt.Errorf("controller: %s start: %w", s.Name, err)
		return
	}
	pw.Close() // ovcp's own handle; the child's inherited copy keeps the pipe alive
	logDone := make(chan struct{})
	go func() { defer close(logDone); defer pr.Close(); logLines(pr, lf) }()

	done := make(chan struct{})
	s.stMu.Lock()
	s.cmd, s.done, s.running, s.startedAt = cmd, done, true, time.Now()
	s.stMu.Unlock()
	slog.Info(s.Name+" started", "pid", cmd.Process.Pid, "bin", bin)
	launched <- nil

	err = cmd.Wait() // reap — no zombie can accumulate; runs for both a clean stop() and an unexpected crash
	<-logDone        // drain whatever's still buffered in the pipe before closing lf
	lf.Close()
	s.stMu.Lock()
	stopped := s.stopped
	s.stopped = false
	startedAt := s.startedAt
	s.running, s.cmd, s.startedAt = false, nil, time.Time{}
	desired := s.desired
	s.stMu.Unlock()
	close(done)
	if s.OnExit != nil {
		s.OnExit()
	}

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
		if s.OnCrashLoopGiveUp != nil {
			s.OnCrashLoopGiveUp(streak)
		}
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
