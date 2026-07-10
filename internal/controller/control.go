package controller

import (
	"bufio"
	"fmt"
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
}

// ServeControl exposes lc over a root-only unix socket so a separate
// `ovcp vpn <op>` invocation can drive the openvpn worker owned by the
// running serve process. Filesystem permissions (0600) are the only auth
// needed for a local root admin.
func ServeControl(sockPath string, lc Lifecycle) (net.Listener, error) {
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
			go serveControlConn(c, lc)
		}
	}()
	return l, nil
}

func serveControlConn(c net.Conn, lc Lifecycle) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // restart may take a few s
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	var opErr error
	switch strings.TrimSpace(line) {
	case "start":
		opErr = lc.Start()
	case "stop":
		opErr = lc.Stop()
	case "restart":
		opErr = lc.Restart()
	case "reconnect":
		opErr = lc.Reconnect()
	default:
		fmt.Fprintln(c, "ERR unknown operation")
		return
	}
	if opErr != nil {
		fmt.Fprintf(c, "ERR %s\n", opErr)
		return
	}
	fmt.Fprintln(c, "OK")
}

// Control sends one lifecycle op to a running serve process and reports the
// result. It is the client half used by the CLI.
func Control(sockPath, op string) error {
	c, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("controller: ovcp serve not reachable at %s (is it running?): %w", sockPath, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(65 * time.Second))
	if _, err := fmt.Fprintf(c, "%s\n", op); err != nil {
		return err
	}
	resp, _ := bufio.NewReader(c).ReadString('\n')
	switch resp = strings.TrimSpace(resp); {
	case resp == "OK":
		return nil
	case strings.HasPrefix(resp, "ERR "):
		return fmt.Errorf("%s", strings.TrimPrefix(resp, "ERR "))
	default:
		return fmt.Errorf("controller: unexpected control response %q", resp)
	}
}
