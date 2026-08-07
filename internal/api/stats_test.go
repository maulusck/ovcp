package api

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

// TestSamplerTickSkipsOnMgmtDown: VPN down/restarting must leave prev
// untouched and must not panic — same "not an error" tolerance the rest of
// this package gives an unreachable mgmt socket (see TestStatusVPNDown).
func TestSamplerTickSkipsOnMgmtDown(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{Mgmt: controller.NewClient(filepath.Join(dir, "no.sock"), filepath.Join(dir, "no-status.log")), VPN: &fakeVPN{},
		DefaultRemote: func() string { return "" }}
	prev := map[string]controller.VPNClient{"alice": {CN: "alice"}}

	got := srv.samplerTick(true, 24*time.Hour, prev)

	if len(got) != 1 || got["alice"].CN != "alice" {
		t.Fatalf("samplerTick with mgmt down = %v, want prev unchanged", got)
	}
}

// listenFakeMgmt starts a bare mgmt-socket stand-in at sock (just the
// greeting line, nothing else) and returns its accept counter — proves a
// later Connect() actually dialed, not just that it returned nil.
func listenFakeMgmt(t *testing.T, sock string) *int32 {
	t.Helper()
	var accepts int32
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepts, 1)
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
				bufio.NewReader(c).ReadString('\n') // "hold release"
				c.Write([]byte("SUCCESS: hold release succeeded\r\n"))
				bufio.NewReader(c).ReadString('\n') // keep the conn open, ignore further input
			}(c)
		}
	}()
	return &accepts
}

// TestSamplerTickRetriesMgmtConnect proves the eager-connect-vs-openvpn-boot
// race self-heals: first tick against nothing listening must not get stuck;
// second tick, socket now up, must actually dial it.
func TestSamplerTickRetriesMgmtConnect(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := SaveUpstreamConfig(s, upstream.Config{
		Upstreams: []upstream.Upstream{{ID: "wan2", Iface: "eth1", Table: 100}},
		PerCN:     map[string]string{"alice": "wan2"},
	}); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	srv := &Server{Store: s, VPN: &fakeVPN{}, UpstreamsEnabled: true,
		Mgmt:          controller.NewClient(sock, filepath.Join(t.TempDir(), "no-status.log")),
		DefaultRemote: func() string { return "" }}

	srv.samplerTick(false, 24*time.Hour, map[string]controller.VPNClient{})

	accepts := listenFakeMgmt(t, sock)
	srv.samplerTick(false, 24*time.Hour, map[string]controller.VPNClient{})

	if got := atomic.LoadInt32(accepts); got != 1 {
		t.Fatalf("retry tick must dial the now-available mgmt socket exactly once, got %d accepts", got)
	}
}

// writeStatus writes a status-version-3 file for cn (or none, for "");
// same format openvpn itself writes, minimal enough for samplerTick's parse.
func writeStatus(t *testing.T, cn string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status.log")
	body := "HEADER\tCLIENT_LIST\t...\r\nEND\r\n"
	if cn != "" {
		body = "HEADER\tCLIENT_LIST\t...\r\n" +
			"CLIENT_LIST\t" + cn + "\t203.0.113.7:1\t10.8.0.2\t\t100\t200\tSat Jul 5 11:00:00 2026\t1783080000\tUNDEF\t0\t0\tAES-256-GCM\r\n" +
			"END\r\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSamplerTickShortSessionNotLost: a client connecting and disconnecting
// within one non-sample tick must still get an EndSession row, not vanish.
func TestSamplerTickShortSessionNotLost(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	srv := &Server{Store: s, VPN: &fakeVPN{}, Mgmt: controller.NewClient("", writeStatus(t, "alice")),
		DefaultRemote: func() string { return "" }}

	prev := srv.samplerTick(false, 24*time.Hour, map[string]controller.VPNClient{})
	if len(prev) != 1 {
		t.Fatalf("want alice tracked after connect tick, got %v", prev)
	}

	srv.Mgmt = controller.NewClient("", writeStatus(t, ""))
	srv.samplerTick(false, 24*time.Hour, prev) // sampleStats=false — the tick that used to drop the disconnect

	sessions, err := s.Sessions(10)
	if err != nil || len(sessions) != 1 || sessions[0].CN != "alice" {
		t.Fatalf("disconnect on a non-sample tick must still record a session, got %v err=%v", sessions, err)
	}
}
