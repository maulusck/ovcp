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
	Pid            int
	Changed        bool
	StartedAt      time.Time
	ServeStartedAt time.Time
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
	if op == "telegram-status" {
		data, _ := json.Marshal(d.Telegram.Status())
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}
	if op == "telegram-start" || op == "telegram-stop" || op == "telegram-restart" {
		before := d.Telegram.Status().Running
		var opErr error
		switch op {
		case "telegram-start":
			opErr = d.Telegram.Start()
		case "telegram-stop":
			opErr = d.Telegram.Stop()
		case "telegram-restart":
			opErr = d.Telegram.Restart()
		}
		if opErr != nil {
			fmt.Fprintf(c, "ERR %s\n", opErr)
			return
		}
		st := d.Telegram.Status()
		st.Changed = st.Running != before
		data, _ := json.Marshal(st)
		fmt.Fprintf(c, "OK %s\n", data)
		return
	}

	// dns- prefixed ops target dnsmasq's own Lifecycle instead of vpn's;
	// same switch body runs against whichever target, not a parallel copy.
	target, verb := d.VPN, op
	if rest, ok := strings.CutPrefix(op, "dns-"); ok {
		target, verb = d.DNS, rest
	}
	if verb == "reconnect" && target == d.DNS {
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
		d.Level.Set(slog.LevelDebug)
		slog.Info("debug logging enabled")
	case "debug off":
		slog.Info("debug logging disabled")
		d.Level.Set(slog.LevelInfo)
	default:
		fmt.Fprintln(c, "ERR unknown operation")
		return
	}
	if opErr != nil {
		fmt.Fprintf(c, "ERR %s\n", opErr)
		return
	}
	// A (re)started openvpn needs the upstream rules re-applied and, with
	// per-CN routing, the management connection reattached. Loud on failure:
	// per-CN routing active means openvpn stays holding until this reconnects.
	if target == d.VPN && (verb == "start" || verb == "restart") && d.UpstreamReapply != nil {
		if err := d.UpstreamReapply(); err != nil {
			fmt.Fprintf(c, "ERR upstream reapply: %s\n", err)
			return
		}
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
