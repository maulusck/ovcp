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

func TestControlRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	lc := &fakeLife{}
	l, err := ServeControl(sock, lc)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for _, op := range []string{"start", "stop", "restart", "reconnect"} {
		if err := Control(sock, op); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if lc.started != 1 || lc.stopped != 1 || lc.restarted != 1 || lc.reconnected != 1 {
		t.Fatalf("dispatch off: %+v", lc)
	}
	if err := Control(sock, "bogus"); err == nil {
		t.Fatal("unknown op must error")
	}
}

func TestControlNoServer(t *testing.T) {
	if err := Control(filepath.Join(t.TempDir(), "nope.sock"), "start"); err == nil {
		t.Fatal("expected error when serve is not running")
	}
}
