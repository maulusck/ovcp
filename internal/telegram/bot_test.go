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

// mockAPI stands in for api.telegram.org: getMe succeeds only for
// goodToken — enough to exercise SetCredentials without a real network
// call or a real bot.
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

func TestSetCredentials(t *testing.T) {
	mockAPI(t)
	s, _ := store.Open(filepath.Join(t.TempDir(), "ovcp.db"))
	defer s.Close()

	if err := SetCredentials(s, badToken, testAdmin); err == nil {
		t.Fatal("bad token should be rejected")
	}
	if err := SetCredentials(s, goodToken, testAdmin); err != nil {
		t.Fatalf("good token should be accepted: %v", err)
	}
	token, _ := s.GetSetting(keyToken)
	admin, _ := s.GetSetting(keyAdmin)
	if token != goodToken || admin != testAdmin {
		t.Fatalf("token=%q admin=%q, want %s/%s", token, admin, goodToken, testAdmin)
	}
}
