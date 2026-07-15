package telegram

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeLife struct{}

func (fakeLife) Start() error         { return nil }
func (fakeLife) Stop() error          { return nil }
func (fakeLife) Restart() error       { return nil }
func (fakeLife) Reconnect() error     { return nil }
func (fakeLife) Pid() int             { return 0 }
func (fakeLife) StartedAt() time.Time { return time.Time{} }

func TestMatches(t *testing.T) {
	cases := []struct {
		admin string
		u     user
		want  bool
	}{
		{"12345", user{ID: 12345, Username: "alice"}, true},
		{"12345", user{ID: 99999, Username: "alice"}, false},
		{"@alice", user{ID: 999, Username: "alice"}, true},
		{"@alice", user{ID: 999, Username: "Alice"}, true}, // case-insensitive
		{"alice", user{ID: 999, Username: "alice"}, true},  // leading @ optional
		{"@alice", user{ID: 999, Username: "bob"}, false},
		{"@alice", user{ID: 999, Username: ""}, false}, // no username set, never matches
	}
	for _, c := range cases {
		if got := matches(c.admin, c.u); got != c.want {
			t.Errorf("matches(%q, %+v) = %v, want %v", c.admin, c.u, got, c.want)
		}
	}
}

func TestShouldReplyUnauthorized(t *testing.T) {
	p := &Poller{}
	const attacker, other int64 = 111, 222

	for i := 1; i <= unauthorizedBlockThreshold; i++ {
		if !p.shouldReplyUnauthorized(attacker, "eve") {
			t.Fatalf("attempt %d: want reply=true (below/at threshold)", i)
		}
	}
	for i := 0; i < 3; i++ {
		if p.shouldReplyUnauthorized(attacker, "eve") {
			t.Fatalf("post-block attempt %d: want reply=false", i)
		}
	}
	// blocking is per-id: an unrelated sender is unaffected
	if !p.shouldReplyUnauthorized(other, "mallory") {
		t.Fatal("a different id must not be affected by attacker's block")
	}
}

// TestHandleCommandCoversRegisteredSurface guards against the menu (either
// the "/" autocomplete list or the reply-keyboard buttons) listing an op
// handleCommand's switch doesn't actually dispatch — every identifier it
// hands the admin must produce a reply.
func TestHandleCommandCoversRegisteredSurface(t *testing.T) {
	var sent int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendMessage") {
			sent++
		}
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()
	defer SetAPIBaseForTesting(srv.URL + "/bot")()

	p := &Poller{vpn: fakeLife{}}
	b := newBot("t")
	ctx := context.Background()

	var identifiers []string
	for _, c := range botCommands {
		identifiers = append(identifiers, "/"+c.Command, c.Command)
	}
	for _, row := range opsKeyboard.Keyboard {
		identifiers = append(identifiers, row...)
	}

	for _, id := range identifiers {
		before := sent
		p.handleCommand(ctx, b, 1, id)
		if sent == before {
			t.Errorf("handleCommand(%q) produced no reply — menu lists an op the switch doesn't handle", id)
		}
	}
}
