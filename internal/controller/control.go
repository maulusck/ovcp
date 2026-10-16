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
	"strconv"
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
	Pid            int       `json:"pid"`
	Changed        bool      `json:"changed"`
	StartedAt      time.Time `json:"startedAt"`
	ServeStartedAt time.Time `json:"serveStartedAt"`
}

// ErrUnknownOp: a verb the target has no such operation for.
var ErrUnknownOp = errors.New("unknown operation")

// RunOp is every vpn/dns lifecycle op, control socket or web API alike:
// verb on target (reconnect only where canReconnect), then afterStart once a
// start or restart succeeds (nil: nothing to do).
func RunOp(target Lifecycle, verb string, canReconnect bool, afterStart func() error) (ControlResult, error) {
	before := target.Pid()
	var err error
	switch verb {
	case "status": // read-only
	case "start":
		err = target.Start()
	case "stop":
		err = target.Stop()
	case "restart":
		err = target.Restart()
	case "reconnect":
		if !canReconnect {
			return ControlResult{}, ErrUnknownOp
		}
		err = target.Reconnect()
	default:
		return ControlResult{}, ErrUnknownOp
	}
	if err != nil {
		return ControlResult{}, err
	}
	// A (re)started openvpn needs the upstream rules re-applied and, with
	// per-CN routing, the management connection reattached.
	if afterStart != nil && (verb == "start" || verb == "restart") {
		if err := afterStart(); err != nil {
			return ControlResult{}, fmt.Errorf("upstream reapply: %w", err)
		}
	}
	r := ControlResult{Pid: target.Pid(), ServeStartedAt: ProcessStartedAt}
	r.Changed = r.Pid != before
	if r.Pid != 0 {
		r.StartedAt = target.StartedAt()
	}
	return r, nil
}

// RunTelegramOp is every telegram poller op, control socket or web API alike.
func RunTelegramOp(t TelegramController, verb string) (TelegramStatus, error) {
	before := t.Status().Running
	var err error
	switch verb {
	case "status":
	case "start":
		err = t.Start()
	case "stop":
		err = t.Stop()
	case "restart":
		err = t.Restart()
	default:
		err = ErrUnknownOp
	}
	if err != nil {
		return TelegramStatus{}, err
	}
	st := t.Status()
	st.Changed = st.Running != before
	return st, nil
}

// ControlDeps bundles everything ServeControl proxies over the socket — one
// struct, not a positional param list that grows with every new op.
// UpstreamRewrite: per-CN live rule rewrite. UpstreamReapply: `upstream reconcile`.
type ControlDeps struct {
	VPN, DNS        Lifecycle
	Mgmt            *Client
	Level           *slog.LevelVar
	Telegram        TelegramController
	UpstreamRewrite func(cn string) error
	UpstreamReapply func() error
}

// ServeControl exposes d's workers, mgmt's live client list/kill, and
// per-CN live rule rewrite over a root-only (0600) unix socket — mgmt
// allows only one client, so serve holds it and fans out here.
func ServeControl(sockPath string, d ControlDeps) (net.Listener, error) {
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
			go serveControlConn(c, d)
		}
	}()
	return l, nil
}

// replyOK writes "OK" or "ERR <err>" — the reply shape every fire-and-report op shares.
func replyOK(c net.Conn, err error) {
	if err != nil {
		fmt.Fprintf(c, "ERR %s\n", err)
		return
	}
	fmt.Fprintln(c, "OK")
}

// serveControlConn dispatches one op. A panic in any op (a bug in a
// caller-supplied closure, e.g. UpstreamReapply) costs this one connection,
// never the whole serve process — same reasoning as mgmt.go's callConnect.
func serveControlConn(c net.Conn, d ControlDeps) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("control op panicked", "panic", r)
			fmt.Fprintln(c, "ERR internal error")
		}
	}()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // restart may take a few s
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	op := strings.TrimSpace(line)

	// clients/kill proxy mgmt's connection; their response shape doesn't fit
	// the pid/changed trailer every Lifecycle op below shares, so they return directly.
	if arg, ok := strings.CutPrefix(op, "kill "); ok {
		msg, cn, _ := strings.Cut(arg, " ")
		n, err := d.Mgmt.Kill(cn, msg)
		if err != nil {
			replyOK(c, err)
			return
		}
		fmt.Fprintf(c, "OK %d\n", n)
		return
	}
	if op == "clients" {
		cl, err := d.Mgmt.Status()
		if err != nil {
			fmt.Fprintf(c, "ERR %s\n", err)
			return
		}
		data, _ := json.Marshal(cl)
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}
	if cn, ok := strings.CutPrefix(op, "upstream-assign "); ok {
		replyOK(c, d.UpstreamRewrite(cn))
		return
	}
	if op == "upstream-reapply" {
		replyOK(c, d.UpstreamReapply())
		return
	}
	if verb, ok := strings.CutPrefix(op, "telegram-"); ok {
		replyJSON(c)(RunTelegramOp(d.Telegram, verb))
		return
	}
	switch op {
	case "debug on":
		d.Level.Set(slog.LevelDebug)
		slog.Info("debug logging enabled")
		replyOK(c, nil)
		return
	case "debug off":
		slog.Info("debug logging disabled")
		d.Level.Set(slog.LevelInfo)
		replyOK(c, nil)
		return
	}
	if verb, ok := strings.CutPrefix(op, "dns-"); ok {
		replyJSON(c)(RunOp(d.DNS, verb, false, nil))
		return
	}
	replyJSON(c)(RunOp(d.VPN, op, true, d.UpstreamReapply))
}

// replyJSON answers with v as one JSON line, or the error.
func replyJSON(c net.Conn) func(any, error) {
	return func(v any, err error) {
		if err != nil {
			fmt.Fprintf(c, "ERR %s\n", err)
			return
		}
		data, _ := json.Marshal(v)
		fmt.Fprintf(c, "OK %s\n", data)
	}
}

// controlRequest sends one op to a running serve process and returns the raw
// payload after "OK " (error for "ERR "). Control, Clients, and Kill below
// just parse this payload differently depending on the op.
// ErrServeDown: nothing listens on the control socket, so no serve and no openvpn run.
var ErrServeDown = errors.New("ovcp serve not reachable (is it running?)")

func controlRequest(sockPath, op string) (string, error) {
	c, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("controller: %w at %s: %w", ErrServeDown, sockPath, err)
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
	if err := json.Unmarshal([]byte(payload), &r); err != nil {
		return r, fmt.Errorf("controller: unexpected control response %q", payload)
	}
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

// Kill is Client.Kill via serve's own mgmt connection (same reasoning as Clients).
func Kill(sockPath, cn, msg string) (int, error) {
	payload, err := controlRequest(sockPath, "kill "+msg+" "+cn)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(payload)
}

// UpstreamAssign asks a running serve to instantly rewrite cn's live nft
// rule after `ovcp upstream assign` persists — a no-op if cn isn't
// currently connected (same reasoning as Kill).
func UpstreamAssign(sockPath, cn string) error {
	_, err := controlRequest(sockPath, "upstream-assign "+cn)
	return err
}

// UpstreamReapply asks a running serve to re-apply the persisted upstream
// config — the `upstream reconcile` trigger, after e.g. an egress interface
// that was down at boot/last-apply time comes back up.
func UpstreamReapply(sockPath string) error {
	_, err := controlRequest(sockPath, "upstream-reapply")
	return err
}


// Debug switches a running serve's log level.
func Debug(sockPath string, on bool) error {
	op := "debug off"
	if on {
		op = "debug on"
	}
	_, err := controlRequest(sockPath, op)
	return err
}

// TelegramOp runs RunTelegramOp's verb on a running serve's poller; its live
// state only exists in that process.
func TelegramOp(sockPath, verb string) (TelegramStatus, error) {
	var st TelegramStatus
	op := "telegram-" + verb
	payload, err := controlRequest(sockPath, op)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(payload), &st); err != nil {
		return st, fmt.Errorf("controller: bad %s response: %w", op, err)
	}
	return st, nil
}
