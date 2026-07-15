package controller

import (
	"bufio"
	"encoding/json"
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

// TelegramStatus is telegram.Poller.Status()'s shape — defined here (not in
// package telegram, which already imports controller) so ServeControl can
// serialize it without an import cycle.
type TelegramStatus struct {
	Running  bool   `json:"running"`
	TokenSet bool   `json:"tokenSet"`
	Admin    string `json:"admin"`
}

// TelegramController is the telegram poller's control surface (implemented
// by *telegram.Poller).
type TelegramController interface {
	Start() error
	Stop() error
	Restart() error
	Status() TelegramStatus
}

// ControlResult is what a control op reports back: the openvpn pid afterwards
// (0 if stopped) and whether this op actually changed the process (a fresh
// spawn, a replacement, or a stop) versus a no-op.
type ControlResult struct {
	Pid     int
	Changed bool
}

// ServeControl exposes lc, "debug on|off", and mgmt's live client list/kill
// over a root-only (0600) unix socket, so `ovcp vpn`/`ovcp debug`/`ovcp
// status`/`ovcp kill`/`ovcp stats -follow` can all drive a running serve.
//
// mgmt matters here for a reason that isn't obvious: OpenVPN's own
// management socket serves exactly one connected client, ever — a second
// direct dial doesn't get refused, it just hangs (openvpn's accept loop
// only reads from the first connection). serve already holds mgmt open for
// its own life (RunStatsSampler, /api/status); every other consumer of the
// live client list must go through *this* socket instead of dialing
// mgmt.sock a second time — this net.Listener, unlike openvpn's mgmt
// protocol, is a normal multi-client accept loop.
func ServeControl(sockPath string, lc Lifecycle, mgmt *Client, level *slog.LevelVar, tc TelegramController) (net.Listener, error) {
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
			go serveControlConn(c, lc, mgmt, level, tc)
		}
	}()
	return l, nil
}

func serveControlConn(c net.Conn, lc Lifecycle, mgmt *Client, level *slog.LevelVar, tc TelegramController) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // restart may take a few s
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	op := strings.TrimSpace(line)

	// clients/kill proxy mgmt's already-held connection — their response
	// shape (a client list, nothing) doesn't fit the pid/changed trailer
	// every Lifecycle op below shares, so they return directly.
	if cn, ok := strings.CutPrefix(op, "kill "); ok {
		if err := mgmt.Kill(cn); err != nil {
			fmt.Fprintf(c, "ERR %s\n", err)
			return
		}
		fmt.Fprintln(c, "OK")
		return
	}
	if op == "clients" {
		cl, err := mgmt.Status()
		if err != nil {
			fmt.Fprintf(c, "ERR %s\n", err)
			return
		}
		data, _ := json.Marshal(cl)
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}
	if op == "telegram-status" {
		data, _ := json.Marshal(tc.Status())
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}
	if op == "telegram-start" || op == "telegram-stop" || op == "telegram-restart" {
		var opErr error
		switch op {
		case "telegram-start":
			opErr = tc.Start()
		case "telegram-stop":
			opErr = tc.Stop()
		case "telegram-restart":
			opErr = tc.Restart()
		}
		if opErr != nil {
			fmt.Fprintf(c, "ERR %s\n", opErr)
			return
		}
		data, _ := json.Marshal(tc.Status())
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}

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

// controlRequest sends one op to a running serve process and returns the
// raw payload after "OK " (or an error for an "ERR " response). The shared
// client-half primitive — Control, Clients, and Kill below just parse this
// payload differently depending on the op they sent.
func controlRequest(sockPath, op string) (string, error) {
	c, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("controller: ovcp serve not reachable at %s (is it running?): %w", sockPath, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(65 * time.Second))
	if _, err := fmt.Fprintf(c, "%s\n", op); err != nil {
		return "", err
	}
	resp, _ := bufio.NewReader(c).ReadString('\n')
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "ERR ") {
		return "", fmt.Errorf("%s", strings.TrimPrefix(resp, "ERR "))
	}
	payload, ok := strings.CutPrefix(resp, "OK")
	if !ok {
		return "", fmt.Errorf("controller: unexpected control response %q", resp)
	}
	return strings.TrimSpace(payload), nil
}

// Control sends one vpn-lifecycle op ("status"/"start"/"stop"/"restart"/
// "reconnect"/"debug on"/"debug off") to a running serve process and
// returns the resulting pid/changed state.
func Control(sockPath, op string) (ControlResult, error) {
	var r ControlResult
	payload, err := controlRequest(sockPath, op)
	if err != nil {
		return r, err
	}
	var changed string
	if _, err := fmt.Sscanf(payload, "%d %s", &r.Pid, &changed); err != nil {
		return r, fmt.Errorf("controller: unexpected control response %q", payload)
	}
	r.Changed = changed == "changed"
	return r, nil
}

// Clients asks a running serve for openvpn's live client list, via serve's
// own already-held mgmt connection — see ServeControl for why a second
// direct dial to mgmt.sock isn't an option.
func Clients(sockPath string) ([]VPNClient, error) {
	payload, err := controlRequest(sockPath, "clients")
	if err != nil {
		return nil, err
	}
	var cl []VPNClient
	if err := json.Unmarshal([]byte(payload), &cl); err != nil {
		return nil, fmt.Errorf("controller: bad clients response: %w", err)
	}
	return cl, nil
}

// Kill disconnects a client by CN, via serve's own mgmt connection (same
// reasoning as Clients).
func Kill(sockPath, cn string) error {
	_, err := controlRequest(sockPath, "kill "+cn)
	return err
}

// TelegramStart/Stop/Restart drive the telegram poller in a running serve;
// TelegramGetStatus reports its current state. Same "serve must be
// running" requirement as Control — the poller's live state, like
// openvpn's, only exists in that process.
func TelegramStart(sockPath string) (TelegramStatus, error) {
	return telegramOp(sockPath, "telegram-start")
}
func TelegramStop(sockPath string) (TelegramStatus, error) {
	return telegramOp(sockPath, "telegram-stop")
}
func TelegramRestart(sockPath string) (TelegramStatus, error) {
	return telegramOp(sockPath, "telegram-restart")
}
func TelegramGetStatus(sockPath string) (TelegramStatus, error) {
	return telegramOp(sockPath, "telegram-status")
}

func telegramOp(sockPath, op string) (TelegramStatus, error) {
	var st TelegramStatus
	payload, err := controlRequest(sockPath, op)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(payload), &st); err != nil {
		return st, fmt.Errorf("controller: bad %s response: %w", op, err)
	}
	return st, nil
}
