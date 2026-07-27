package controller

import (
	"log/slog"
	"path/filepath"
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

func TestControlRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	l, err := ServeControl(sock, lc, &fakeLife{}, noMgmt(t), new(slog.LevelVar), &fakeTelegram{})
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
	l, err := ServeControl(sock, lc, dc, noMgmt(t), new(slog.LevelVar), &fakeTelegram{})
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
	l, _ := ServeControl(sock, lc, &fakeLife{}, noMgmt(t), new(slog.LevelVar), &fakeTelegram{})
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
	l, err := ServeControl(sock, lc, &fakeLife{}, noMgmt(t), level, &fakeTelegram{})
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
	l, err := ServeControl(sock, &fakeLife{}, &fakeLife{}, NewClient(mgmtSock, writeStatus(t, oneClientStatus)), new(slog.LevelVar), &fakeTelegram{})
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
	l, err := ServeControl(sock, &fakeLife{}, &fakeLife{}, noMgmt(t), new(slog.LevelVar), tg)
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
