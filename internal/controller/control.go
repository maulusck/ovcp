package controller

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Lifecycle is the openvpn control surface (implemented by *Supervisor).
type Lifecycle interface {
	Start() error
	Stop() error
	Restart() error
	Reconnect() error
	Pid() int // 0 when not running
}

// ControlResult is what a control op reports back: the openvpn pid afterwards
// (0 if stopped) and whether this op actually changed the process (a fresh
// spawn, a replacement, or a stop) versus a no-op.
type ControlResult struct {
	Pid     int
	Changed bool
}

// ServeControl exposes lc and "debug on|off" over a root-only (0600) unix socket, so `ovcp vpn`/`ovcp debug` can drive a running serve.
func ServeControl(sockPath string, lc Lifecycle, level *slog.LevelVar) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o750); err != nil {
		return nil, err
	}
	os.Remove(sockPath) // clear a stale socket from a previous run
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	os.Chmod(sockPath, 0o600)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return // listener closed
			}
			go serveControlConn(c, lc, level)
		}
	}()
	return l, nil
}

func serveControlConn(c net.Conn, lc Lifecycle, level *slog.LevelVar) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // restart may take a few s
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	op := strings.TrimSpace(line)
	before := lc.Pid()
	var opErr error
	switch op {
	case "status": // read-only
	case "start":
		opErr = lc.Start()
	case "stop":
		opErr = lc.Stop()
	case "restart":
		opErr = lc.Restart()
	case "reconnect":
		opErr = lc.Reconnect()
	case "debug on":
		level.Set(slog.LevelDebug)
		slog.Info("debug logging enabled")
	case "debug off":
		slog.Info("debug logging disabled")
		level.Set(slog.LevelInfo)
	default:
		fmt.Fprintln(c, "ERR unknown operation")
		return
	}
	if opErr != nil {
		fmt.Fprintf(c, "ERR %s\n", opErr)
		return
	}
	after := lc.Pid()
	changed := "nochange"
	if before != after {
		changed = "changed"
	}
	fmt.Fprintf(c, "OK %d %s\n", after, changed)
}

// Control sends one op to a running serve process and returns the resulting
// pid/changed state. It is the client half used by the CLI.
func Control(sockPath, op string) (ControlResult, error) {
	var r ControlResult
	c, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return r, fmt.Errorf("controller: ovcp serve not reachable at %s (is it running?): %w", sockPath, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(65 * time.Second))
	if _, err := fmt.Fprintf(c, "%s\n", op); err != nil {
		return r, err
	}
	resp, _ := bufio.NewReader(c).ReadString('\n')
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "ERR ") {
		return r, fmt.Errorf("%s", strings.TrimPrefix(resp, "ERR "))
	}
	var changed string
	if _, err := fmt.Sscanf(resp, "OK %d %s", &r.Pid, &changed); err != nil {
		return r, fmt.Errorf("controller: unexpected control response %q", resp)
	}
	r.Changed = changed == "changed"
	return r, nil
}
