package telegram

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
