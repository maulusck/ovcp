package api

import (
	"path/filepath"
	"testing"

	"github.com/ovcp/ovcp/internal/controller"
)

// TestSamplerTickSkipsOnMgmtDown: VPN down/restarting must leave prev
// untouched and must not panic — same "not an error" tolerance the rest of
// this package gives an unreachable mgmt socket (see TestStatusVPNDown).
func TestSamplerTickSkipsOnMgmtDown(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{Mgmt: controller.NewClient(filepath.Join(dir, "no.sock"), filepath.Join(dir, "no-status.log")), VPN: &fakeVPN{}}
	prev := map[string]controller.VPNClient{"alice": {CN: "alice"}}

	got := srv.samplerTick(true, prev)

	if len(got) != 1 || got["alice"].CN != "alice" {
		t.Fatalf("samplerTick with mgmt down = %v, want prev unchanged", got)
	}
}
