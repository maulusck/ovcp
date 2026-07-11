package controller

import (
	"path/filepath"
	"testing"
)

type fakeLife struct{ started, stopped, restarted, reconnected int }

func (f *fakeLife) Start() error     { f.started++; return nil }
func (f *fakeLife) Stop() error      { f.stopped++; return nil }
func (f *fakeLife) Restart() error   { f.restarted++; return nil }
func (f *fakeLife) Reconnect() error { f.reconnected++; return nil }

var fakePid int

func (f *fakeLife) Pid() int { return fakePid }

func TestControlRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	l, err := ServeControl(sock, lc)
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
	l, _ := ServeControl(sock, lc)
	defer l.Close()
	r, err := Control(sock, "start")
	if err != nil || r.Pid != 100 || !r.Changed {
		t.Fatalf("got %+v err=%v; want pid=100 changed=true", r, err)
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
