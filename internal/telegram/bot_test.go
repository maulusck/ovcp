package telegram

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ovcp/ovcp/internal/store"
)

const (
	goodToken = "good-token"
	badToken  = "bad-token"
	testAdmin = "@alice"
)

// mockAPI stands in for api.telegram.org: getMe succeeds only for goodToken.
func mockAPI(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, goodToken+"/getMe") {
			w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true}}`))
			return
		}
		w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(SetAPIBaseForTesting(srv.URL + "/bot"))
}

// TestSetTokenAndAdmin covers both independently — setting one must never
// require (or touch) the other.
func TestSetTokenAndAdmin(t *testing.T) {
	mockAPI(t)
	s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()

	if err := SetToken(s, badToken); err == nil {
		t.Fatal("bad token should be rejected")
	}
	if err := SetToken(s, goodToken); err != nil {
		t.Fatalf("good token should be accepted: %v", err)
	}
	if err := SetAdmin(s, testAdmin); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}
	token, _ := s.GetSetting(keyToken)
	admin, _ := s.GetSetting(keyAdmin)
	if token != goodToken || admin != testAdmin {
		t.Fatalf("token=%q admin=%q, want %s/%s", token, admin, goodToken, testAdmin)
	}

	// changing the token alone must leave admin untouched, and vice versa.
	if err := SetToken(s, goodToken); err != nil {
		t.Fatalf("SetToken again: %v", err)
	}
	if admin2, _ := s.GetSetting(keyAdmin); admin2 != testAdmin {
		t.Fatalf("SetToken must not touch admin, got %q", admin2)
	}
}

// TestReSaveDoesNotUnlinkChat: re-submitting the same admin/token (e.g. the
// web UI resubmitting an unchanged field) must not wipe the learned chat —
// only an actual identity change should. Regression for a bug where every
// form save silently broke push notifications.
func TestReSaveDoesNotUnlinkChat(t *testing.T) {
	mockAPI(t)
	s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()

	if err := SetAdmin(s, testAdmin); err != nil {
		t.Fatal(err)
	}
	s.SetSetting(keyChat, "555")

	if err := SetAdmin(s, testAdmin); err != nil {
		t.Fatal(err)
	}
	if chat, _ := s.GetSetting(keyChat); chat != "555" {
		t.Fatalf("re-saving the same admin must not unlink the chat, got %q", chat)
	}

	if err := SetAdmin(s, "@bob"); err != nil {
		t.Fatal(err)
	}
	if chat, _ := s.GetSetting(keyChat); chat != "" {
		t.Fatalf("changing admin must unlink the chat, got %q", chat)
	}

	if err := SetToken(s, goodToken); err != nil {
		t.Fatal(err)
	}
	s.SetSetting(keyChat, "555")
	if err := SetToken(s, goodToken); err != nil {
		t.Fatal(err)
	}
	if chat, _ := s.GetSetting(keyChat); chat != "555" {
		t.Fatalf("re-saving the same token must not unlink the chat, got %q", chat)
	}
}

// TestWarnOldAdminSendsGoodbye: SetAdmin's outgoing-admin notice actually
// reaches the right chat, both when the old admin is a bare numeric id
// (Telegram's private-chat id equals the user id, so no prior message is
// needed) and when it's a @username with a chat already linked from a prior
// message. This is the piece cmdTelegramConfigSet/handleTelegramConfigSet's
// admin-before-token ordering (see their doc comments) depends on: it only
// helps if a goodbye actually gets sent when it's given the chance to run
// before the chat is unlinked.
func TestWarnOldAdminSendsGoodbye(t *testing.T) {
	cases := []struct {
		name         string
		oldAdmin     string
		seedChat     string // "" = nothing seeded (numeric old-admin needs no prior link)
		wantSent     bool
		wantChatSeen string
	}{
		{"numeric old admin, no prior message needed", "111111", "", true, "111111"},
		{"username old admin with a linked chat", "@alice", "555", true, "555"},
		{"username old admin never linked: nothing to send to", "@alice", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gotChat, gotText string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/getMe") {
					w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true}}`))
					return
				}
				if strings.Contains(r.URL.Path, "/sendMessage") {
					var body struct {
						ChatID int64  `json:"chat_id"`
						Text   string `json:"text"`
					}
					json.NewDecoder(r.Body).Decode(&body)
					gotChat = strconv.FormatInt(body.ChatID, 10)
					gotText = body.Text
				}
				w.Write([]byte(`{"ok":true,"result":{}}`))
			}))
			defer srv.Close()
			defer SetAPIBaseForTesting(srv.URL + "/bot")()

			s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
			defer s.Close()
			if err := SetToken(s, goodToken); err != nil {
				t.Fatal(err)
			}
			if err := SetAdmin(s, c.oldAdmin); err != nil {
				t.Fatal(err)
			}
			if c.seedChat != "" {
				s.SetSetting(keyChat, c.seedChat)
			}

			if err := SetAdmin(s, "@newadmin"); err != nil {
				t.Fatal(err)
			}
			if (gotChat != "") != c.wantSent {
				t.Fatalf("goodbye sent=%v (chat=%q), want sent=%v", gotChat != "", gotChat, c.wantSent)
			}
			if c.wantSent && gotChat != c.wantChatSeen {
				t.Fatalf("goodbye went to chat %q, want %q", gotChat, c.wantChatSeen)
			}
			if c.wantSent && !strings.Contains(gotText, "@newadmin") {
				t.Fatalf("goodbye must name the new admin, got %q", gotText)
			}
		})
	}
}

// TestAdminGoodbyeSurvivesCombinedTokenChange: cmdTelegramConfigSet and
// handleTelegramConfigSet both change admin+token in one call by invoking
// SetAdmin then SetToken, in that order — never the reverse. Regression for
// a bug where the reverse order lost the goodbye entirely: SetToken clears
// keyChat on any real token change (its own unlink-on-identity-change rule),
// so if it ran first, SetAdmin's warnOldAdmin would find the chat already
// gone by the time it tried to read it.
func TestAdminGoodbyeSurvivesCombinedTokenChange(t *testing.T) {
	mockAPI(t)
	s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()

	if err := SetToken(s, goodToken); err != nil {
		t.Fatal(err)
	}
	if err := SetAdmin(s, testAdmin); err != nil {
		t.Fatal(err)
	}
	s.SetSetting(keyChat, "555") // alice's chat, learned from a prior message

	var gotChat string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/getMe") {
			w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/sendMessage") {
			var body struct {
				ChatID int64 `json:"chat_id"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			gotChat = strconv.FormatInt(body.ChatID, 10)
		}
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()
	defer SetAPIBaseForTesting(srv.URL + "/bot")()

	// the caller-side order this test guards: admin before token.
	if err := SetAdmin(s, "@bob"); err != nil {
		t.Fatal(err)
	}
	if err := SetToken(s, "a-second-good-token"); err != nil {
		t.Fatal(err)
	}
	if gotChat != "555" {
		t.Fatalf("goodbye did not reach alice's chat (555), got %q — admin must be applied before token", gotChat)
	}
}
