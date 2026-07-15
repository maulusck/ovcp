package telegram

import "testing"

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
