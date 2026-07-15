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

// fakeStartedAt: zero by default (matches "not running"); tests that care
// about the wire format's timestamp field set it directly.
var fakeStartedAt time.Time

const fakeTelegramAdmin = "@alice"

type fakeTelegram struct{ started, stopped, restarted int }

func (f *fakeTelegram) Start() error   { f.started++; return nil }
func (f *fakeTelegram) Stop() error    { f.stopped++; return nil }
func (f *fakeTelegram) Restart() error { f.restarted++; return nil }
func (f *fakeTelegram) Status() TelegramStatus {
	return TelegramStatus{Running: f.started > f.stopped, TokenSet: true, Admin: fakeTelegramAdmin}
}

// noMgmt is a *Client that's never actually dialed — every test below that
// doesn't exercise "clients"/"kill" just needs a valid argument to pass.
func noMgmt(t *testing.T) *Client {
	t.Helper()
	return NewClient(filepath.Join(t.TempDir(), "unused-mgmt.sock"))
}

func TestControlRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	l, err := ServeControl(sock, lc, noMgmt(t), new(slog.LevelVar), &fakeTelegram{})
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

func TestControlChangedFlag(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	// pid flips 0 -> 100 across the call: reported as changed
	lc := &flipLife{before: 0, after: 100}
	l, _ := ServeControl(sock, lc, noMgmt(t), new(slog.LevelVar), &fakeTelegram{})
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
	l, err := ServeControl(sock, lc, noMgmt(t), level, &fakeTelegram{})
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

// TestControlClientsAndKill covers the two ops added so status/kill/stats
// -follow can get live mgmt data through serve's control socket instead of
// dialing openvpn's own management socket a second time (see ServeControl:
// openvpn only ever serves one connected mgmt client, and serve already
// holds that slot).
func TestControlClientsAndKill(t *testing.T) {
	mgmtSock, _ := fakeMgmt(t)
	sock := filepath.Join(t.TempDir(), "control.sock")
	l, err := ServeControl(sock, &fakeLife{}, NewClient(mgmtSock), new(slog.LevelVar), &fakeTelegram{})
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
	l, err := ServeControl(sock, &fakeLife{}, noMgmt(t), new(slog.LevelVar), tg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	st, err := TelegramStart(sock)
	if err != nil || !st.Running || tg.started != 1 {
		t.Fatalf("TelegramStart: %+v err=%v tg=%+v", st, err, tg)
	}
	st, err = TelegramGetStatus(sock)
	if err != nil || !st.Running || !st.TokenSet || st.Admin != fakeTelegramAdmin {
		t.Fatalf("TelegramGetStatus: %+v err=%v", st, err)
	}
	if st, err = TelegramStop(sock); err != nil || st.Running || tg.stopped != 1 {
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

// flipLife reports a different pid before vs after the op (to exercise the
// changed/nochange detection independent of any real process).
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
