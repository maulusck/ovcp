package controller

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ProcessStartedAt is set once at package init, so it's only meaningful read
// from inside the `ovcp serve` process itself; a CLI invocation gets its own
// near-zero copy and must read it over the wire instead (ControlResult.ServeStartedAt).
var ProcessStartedAt = time.Now()

// ErrBusy: a lifecycle op rejects instead of queuing behind one already in
// flight — queuing would let repeated calls each fully execute in turn.
var ErrBusy = errors.New("operation already in progress")

// Lifecycle is a supervised worker's control surface (implemented by
// *Supervisor) — shared by openvpn and dnsmasq.
type Lifecycle interface {
	Start() error
	Stop() error
	Restart() error
	Reconnect() error
	Pid() int             // 0 when not running
	StartedAt() time.Time // zero when not running
}

// TelegramStatus mirrors telegram.Poller.Status()'s shape, defined here (not
// in package telegram, which imports controller) to avoid an import cycle.
type TelegramStatus struct {
	Running    bool   `json:"running"`
	TokenSet   bool   `json:"tokenSet"`
	Admin      string `json:"admin"`
	ChatLinked bool   `json:"chatLinked"` // false: admin hasn't messaged the bot yet, push notifications can't reach them
	Changed    bool   `json:"changed"`    // set by start/stop/restart callers; meaningless (and left false) for a plain status read
}

// TelegramController is the telegram poller's control surface (implemented
// by *telegram.Poller).
type TelegramController interface {
	Start() error
	Stop() error
	Restart() error
	Status() TelegramStatus
}

// ControlResult reports the openvpn pid afterwards (0 if stopped), whether
// the op actually changed the process vs. a no-op, when the (possibly
// still-running) child started, and when the answering serve process started.
type ControlResult struct {
	Pid            int
	Changed        bool
	StartedAt      time.Time
	ServeStartedAt time.Time
}

// ServeControl exposes lc (vpn), dc (dnsmasq), "debug on|off", and mgmt's live client list/kill over a root-only (0600) unix
// socket for `ovcp vpn`/`dns`/`debug`/`status`/`kill`/`stats -follow` — mgmt allows only one client, so serve holds it and fans out here.
func ServeControl(sockPath string, lc, dc Lifecycle, mgmt *Client, level *slog.LevelVar, tc TelegramController) (net.Listener, error) {
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
			go serveControlConn(c, lc, dc, mgmt, level, tc)
		}
	}()
	return l, nil
}

func serveControlConn(c net.Conn, lc, dc Lifecycle, mgmt *Client, level *slog.LevelVar, tc TelegramController) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // restart may take a few s
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	op := strings.TrimSpace(line)

	// clients/kill proxy mgmt's connection; their response shape doesn't fit
	// the pid/changed trailer every Lifecycle op below shares, so they return directly.
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
		before := tc.Status().Running
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
		st := tc.Status()
		st.Changed = st.Running != before
		data, _ := json.Marshal(st)
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}

	// dns- prefixed ops target dnsmasq's own Lifecycle instead of vpn's;
	// same switch body runs against whichever target, not a parallel copy.
	target, verb := lc, op
	if rest, ok := strings.CutPrefix(op, "dns-"); ok {
		target, verb = dc, rest
	}
	if verb == "reconnect" && target == dc {
		fmt.Fprintln(c, "ERR unknown operation")
		return
	}

	before := target.Pid()
	var opErr error
	switch verb {
	case "status": // read-only
	case "start":
		opErr = target.Start()
	case "stop":
		opErr = target.Stop()
	case "restart":
		opErr = target.Restart()
	case "reconnect":
		opErr = target.Reconnect()
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
	after := target.Pid()
	changed := "nochange"
	if before != after {
		changed = "changed"
	}
	var startedAtUnix int64
	if after != 0 {
		startedAtUnix = target.StartedAt().Unix()
	}
	fmt.Fprintf(c, "OK %d %s %d %d\n", after, changed, startedAtUnix, ProcessStartedAt.Unix())
}

// controlRequest sends one op to a running serve process and returns the raw
// payload after "OK " (error for "ERR "). Control, Clients, and Kill below
// just parse this payload differently depending on the op.
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

// Control sends one lifecycle op to a running serve; "dns-" prefix (e.g.
// "dns-start") targets dnsmasq instead of vpn — "dns-reconnect" doesn't exist.
func Control(sockPath, op string) (ControlResult, error) {
	var r ControlResult
	payload, err := controlRequest(sockPath, op)
	if err != nil {
		return r, err
	}
	var changed string
	var startedAtUnix, serveStartedAtUnix int64
	if _, err := fmt.Sscanf(payload, "%d %s %d %d", &r.Pid, &changed, &startedAtUnix, &serveStartedAtUnix); err != nil {
		return r, fmt.Errorf("controller: unexpected control response %q", payload)
	}
	r.Changed = changed == "changed"
	if startedAtUnix != 0 {
		r.StartedAt = time.Unix(startedAtUnix, 0)
	}
	r.ServeStartedAt = time.Unix(serveStartedAtUnix, 0)
	return r, nil
}

// Clients asks a running serve for openvpn's live client list, via serve's
// own held mgmt connection (see ServeControl).
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
// TelegramGetStatus reports its state. Requires serve running, like Control —
// the poller's live state only exists in that process.
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
