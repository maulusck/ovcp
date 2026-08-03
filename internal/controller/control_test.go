package controller

import (
	"errors"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLife struct{ started, stopped, restarted, reconnected int }

func (f *fakeLife) Start() error     { f.started++; return nil }
func (f *fakeLife) Stop() error      { f.stopped++; return nil }
func (f *fakeLife) Restart() error   { f.restarted++; return nil }
func (f *fakeLife) Reconnect() error { f.reconnected++; return nil }

var fakePid int

func (f *fakeLife) Pid() int             { return fakePid }
func (f *fakeLife) StartedAt() time.Time { return fakeStartedAt }

// fakeStartedAt is zero by default ("not running"); tests set it directly when they care.
var fakeStartedAt time.Time

const fakeTelegramAdmin = "@alice"

type fakeTelegram struct{ started, stopped, restarted int }

func (f *fakeTelegram) Start() error   { f.started++; return nil }
func (f *fakeTelegram) Stop() error    { f.stopped++; return nil }
func (f *fakeTelegram) Restart() error { f.restarted++; return nil }
func (f *fakeTelegram) Status() TelegramStatus {
	return TelegramStatus{Running: f.started > f.stopped, TokenSet: true, Admin: fakeTelegramAdmin}
}

// noMgmt is a never-dialed *Client, for tests that just need a valid argument.
func noMgmt(t *testing.T) *Client {
	t.Helper()
	return NewClient(filepath.Join(t.TempDir(), "unused-mgmt.sock"), "")
}

// noUpstreamRewrite stands in for tests that don't exercise upstream-assign.
func noUpstreamRewrite(string) error { return nil }

func TestControlRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	l, err := ServeControl(sock, ControlDeps{VPN: lc, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamRewrite: noUpstreamRewrite})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	fakePid = 4242
	for _, op := range []string{"start", "stop", "restart", "reconnect", "status"} {
		r, err := Control(sock, op)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if r.Pid != 4242 {
			t.Fatalf("%s: pid=%d, want 4242", op, r.Pid)
		}
	}
	if lc.started != 1 || lc.stopped != 1 || lc.restarted != 1 || lc.reconnected != 1 {
		t.Fatalf("dispatch off: %+v", lc)
	}
	if _, err := Control(sock, "bogus"); err == nil {
		t.Fatal("unknown op must error")
	}
}

// TestControlDNSRouting: "dns-"-prefixed ops must dispatch to dc, not lc,
// and "dns-reconnect" must not exist (dnsmasq has no reconnect signal).
func TestControlDNSRouting(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc, dc := &fakeLife{}, &fakeLife{}
	l, err := ServeControl(sock, ControlDeps{VPN: lc, DNS: dc, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamRewrite: noUpstreamRewrite})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for _, op := range []string{"dns-start", "dns-stop", "dns-restart", "dns-status"} {
		if _, err := Control(sock, op); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if dc.started != 1 || dc.stopped != 1 || dc.restarted != 1 {
		t.Fatalf("dns dispatch off: %+v", dc)
	}
	if lc.started != 0 || lc.stopped != 0 || lc.restarted != 0 {
		t.Fatalf("dns ops leaked to vpn lifecycle: %+v", lc)
	}

	if _, err := Control(sock, "dns-reconnect"); err == nil {
		t.Fatal("dns-reconnect must not exist")
	}
	if dc.reconnected != 0 || lc.reconnected != 0 {
		t.Fatalf("dns-reconnect must not touch either lifecycle: dc=%+v lc=%+v", dc, lc)
	}
}

func TestControlChangedFlag(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	// pid flips 0 -> 100 across the call: reported as changed
	lc := &flipLife{before: 0, after: 100}
	l, _ := ServeControl(sock, ControlDeps{VPN: lc, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamRewrite: noUpstreamRewrite})
	defer l.Close()
	r, err := Control(sock, "start")
	if err != nil || r.Pid != 100 || !r.Changed {
		t.Fatalf("got %+v err=%v; want pid=100 changed=true", r, err)
	}
}

func TestControlDebugToggle(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	level := new(slog.LevelVar)
	l, err := ServeControl(sock, ControlDeps{VPN: lc, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: level, Telegram: &fakeTelegram{}, UpstreamRewrite: noUpstreamRewrite})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if _, err := Control(sock, "debug on"); err != nil {
		t.Fatal(err)
	}
	if level.Level() != slog.LevelDebug {
		t.Fatalf("level = %v, want Debug", level.Level())
	}
	if _, err := Control(sock, "debug off"); err != nil {
		t.Fatal(err)
	}
	if level.Level() != slog.LevelInfo {
		t.Fatalf("level = %v, want Info", level.Level())
	}
}

// TestControlClientsAndKill covers the two ops that proxy live mgmt data
// through serve's control socket instead of a second direct mgmt dial (see ServeControl).
func TestControlClientsAndKill(t *testing.T) {
	mgmtSock, _ := fakeMgmt(t)
	sock := filepath.Join(t.TempDir(), "control.sock")
	l, err := ServeControl(sock, ControlDeps{VPN: &fakeLife{}, DNS: &fakeLife{}, Mgmt: NewClient(mgmtSock, writeStatus(t, oneClientStatus)), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamRewrite: noUpstreamRewrite})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	cl, err := Clients(sock)
	if err != nil || len(cl) != 1 || cl[0].CN != "alice" {
		t.Fatalf("Clients: %+v err=%v", cl, err)
	}
	if err := Kill(sock, "alice"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := Kill(sock, "nobody"); err == nil {
		t.Fatal("Kill of an unknown cn should error")
	}
}

func TestControlTelegramOps(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	tg := &fakeTelegram{}
	l, err := ServeControl(sock, ControlDeps{VPN: &fakeLife{}, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: tg, UpstreamRewrite: noUpstreamRewrite})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	st, err := TelegramStart(sock)
	if err != nil || !st.Running || !st.Changed || tg.started != 1 {
		t.Fatalf("TelegramStart: %+v err=%v tg=%+v", st, err, tg)
	}
	st, err = TelegramGetStatus(sock)
	if err != nil || !st.Running || !st.TokenSet || st.Admin != fakeTelegramAdmin || st.Changed {
		t.Fatalf("TelegramGetStatus: %+v err=%v", st, err)
	}
	if st, err = TelegramStop(sock); err != nil || st.Running || !st.Changed || tg.stopped != 1 {
		t.Fatalf("TelegramStop: %+v err=%v tg=%+v", st, err, tg)
	}
	if _, err := TelegramRestart(sock); err != nil || tg.restarted != 1 {
		t.Fatalf("TelegramRestart: err=%v tg=%+v", err, tg)
	}
}

// TestControlUpstreamAssign covers the op RewriteConnectedClientRule rides
// to reach a running serve from the separate `ovcp upstream assign` process.
func TestControlUpstreamAssign(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	var gotCN string
	rewrite := func(cn string) error {
		gotCN = cn
		if cn == "bob" {
			return errors.New("bob: no longer connected")
		}
		return nil
	}
	l, err := ServeControl(sock, ControlDeps{VPN: &fakeLife{}, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamRewrite: rewrite})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := UpstreamAssign(sock, "alice"); err != nil {
		t.Fatalf("UpstreamAssign: %v", err)
	}
	if gotCN != "alice" {
		t.Fatalf("cn passed through = %q, want alice", gotCN)
	}
	if err := UpstreamAssign(sock, "bob"); err == nil {
		t.Fatal("rewrite error must propagate to the caller")
	}
}

// TestControlOpPanicRecovers: a panicking op (a bug in a caller-supplied
// closure) must cost only that connection — the listener, and every op
// after it, must keep working, not take the whole process down.
func TestControlOpPanicRecovers(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	reapply := func() error { panic("boom") }
	l, err := ServeControl(sock, ControlDeps{VPN: lc, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamReapply: reapply})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := UpstreamReapply(sock); err == nil {
		t.Fatal("want an error reply, not a hang or a crashed process")
	}

	fakePid = 4242
	r, err := Control(sock, "status")
	if err != nil || r.Pid != 4242 {
		t.Fatalf("listener must still serve other ops after a panic: %+v err=%v", r, err)
	}
}

// TestControlUpstreamReapply covers the op `ovcp upstream reconcile` (and
// add/del/set-default's best-effort relay) rides to reach a running serve.
func TestControlUpstreamReapply(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	calls := 0
	reapply := func() error {
		calls++
		return nil
	}
	l, err := ServeControl(sock, ControlDeps{VPN: &fakeLife{}, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamReapply: reapply})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := UpstreamReapply(sock); err != nil {
		t.Fatalf("UpstreamReapply: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

// TestControlVPNStartRestartTriggerUpstreamReapply: nft's Subnet only
// matches reality right after openvpn re-reads server.conf, i.e. start or
// restart — stop/reconnect/dns ops must not trigger it.
func TestControlVPNStartRestartTriggerUpstreamReapply(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	var calls int32
	reapply := func() error { atomic.AddInt32(&calls, 1); return nil }
	l, err := ServeControl(sock, ControlDeps{VPN: &fakeLife{}, DNS: &fakeLife{}, Mgmt: noMgmt(t), Level: new(slog.LevelVar), Telegram: &fakeTelegram{}, UpstreamReapply: reapply})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for _, op := range []string{"start", "restart"} {
		if _, err := Control(sock, op); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls after start+restart = %d, want 2", got)
	}

	for _, op := range []string{"stop", "reconnect", "dns-start", "dns-restart"} {
		if _, err := Control(sock, op); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls after stop/reconnect/dns ops = %d, want still 2", got)
	}
}

func TestControlNoServer(t *testing.T) {
	if _, err := Control(filepath.Join(t.TempDir(), "nope.sock"), "start"); err == nil {
		t.Fatal("expected error when serve is not running")
	}
}

// flipLife reports a different pid before vs after the op, to exercise
// changed/nochange detection without a real process.
type flipLife struct {
	before, after int
	calls         int
}

func (f *flipLife) Start() error     { f.calls++; return nil }
func (f *flipLife) Stop() error      { f.calls++; return nil }
func (f *flipLife) Restart() error   { f.calls++; return nil }
func (f *flipLife) Reconnect() error { f.calls++; return nil }
func (f *flipLife) Pid() int {
	if f.calls == 0 {
		return f.before
	}
	return f.after
}
func (f *flipLife) StartedAt() time.Time { return time.Time{} }
