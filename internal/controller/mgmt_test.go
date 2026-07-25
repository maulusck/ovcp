package controller

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeMgmt emulates openvpn's mgmt interface on a unix socket, returning the
// socket path and an accept counter so tests can assert reuse vs. reconnects.
// Only "kill" is emulated — Status() no longer talks to this socket at all.
func fakeMgmt(t *testing.T) (string, *int32) {
	t.Helper()
	var accepts int32
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
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
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch cmd := strings.TrimSpace(line); {
					case strings.HasPrefix(cmd, "kill alice"):
						c.Write([]byte("SUCCESS: common name 'alice' found, 1 client(s) killed\r\n"))
					case strings.HasPrefix(cmd, "kill "):
						c.Write([]byte("ERROR: common name not found\r\n"))
					}
				}
			}(c)
		}
	}()
	return sock, &accepts
}

// writeStatus writes a status-version-3 file (same format the mgmt socket's
// "status 3" reply uses — see multi_print_status in openvpn's source, shared
// by both) and returns its path.
func writeStatus(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "status.log")
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

const oneClientStatus = "TITLE\tOpenVPN 2.6.12\r\n" +
	"TIME\t2026-07-05 12:00:00\t1783000000\r\n" +
	"HEADER\tCLIENT_LIST\t...\r\n" +
	"CLIENT_LIST\talice\t203.0.113.7:55010\t10.8.0.2\t\t1024\t2048\tSat Jul  5 11:00:00 2026\t1783080000\tUNDEF\t0\t0\tAES-256-GCM\r\n" +
	"HEADER\tROUTING_TABLE\t...\r\n" +
	"ROUTING_TABLE\t10.8.0.2\talice\t203.0.113.7:55010\t...\r\n" +
	"GLOBAL_STATS\tMax bcast/mcast queue length\t0\r\n" +
	"END\r\n"

func TestStatusFromFile(t *testing.T) {
	c := &Client{StatusPath: writeStatus(t, oneClientStatus)}
	cl, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(cl) != 1 || cl[0].CN != "alice" || cl[0].BytesSent != 2048 ||
		cl[0].VirtualAddress != "10.8.0.2" || cl[0].Cipher != "AES-256-GCM" {
		t.Fatalf("parsed: %+v", cl)
	}
}

func TestStatusNoClients(t *testing.T) {
	body := "TITLE\tOpenVPN 2.6.12\r\n" +
		"TIME\t2026-07-05 12:00:00\t1783000000\r\n" +
		"HEADER\tCLIENT_LIST\t...\r\n" +
		"HEADER\tROUTING_TABLE\t...\r\n" +
		"GLOBAL_STATS\tMax bcast/mcast queue length\t0\r\n" +
		"END\r\n"
	c := &Client{StatusPath: writeStatus(t, body)}
	cl, err := c.Status()
	if err != nil || len(cl) != 0 {
		t.Fatalf("cl=%+v err=%v, want empty/no error", cl, err)
	}
}

func TestStatusFileMissing(t *testing.T) {
	c := &Client{StatusPath: filepath.Join(t.TempDir(), "nope.log")}
	if _, err := c.Status(); err == nil {
		t.Fatal("want error for missing status file")
	}
}

// TestStatusTornRead: a file with no terminating END line — whatever the
// reason — must error, never return a partial (and therefore wrong) list.
func TestStatusTornRead(t *testing.T) {
	torn := strings.TrimSuffix(oneClientStatus, "END\r\n") // cut mid-write, no END
	c := &Client{StatusPath: writeStatus(t, torn)}
	cl, err := c.Status()
	if err == nil {
		t.Fatalf("want error for torn read, got clients: %+v", cl)
	}
	if cl != nil {
		t.Fatalf("want nil clients on error, got: %+v", cl)
	}
}

func TestKill(t *testing.T) {
	sock, _ := fakeMgmt(t)
	c := NewClient(sock, "")
	if err := c.Kill("alice"); err != nil {
		t.Fatal(err)
	}
	if err := c.Kill("nobody"); err == nil {
		t.Fatal("want error for unknown cn")
	}
}

func TestKillRejectsInjection(t *testing.T) {
	sock, _ := fakeMgmt(t)
	c := NewClient(sock, "")
	if err := c.Kill("alice\nsignal SIGTERM"); err == nil {
		t.Fatal("want error for cn containing newline")
	}
}

// TestAppErrorKeepsConnection ensures a well-formed "ERROR: ..." reply
// doesn't trigger a reconnect — only actual connection failures should.
func TestAppErrorKeepsConnection(t *testing.T) {
	sock, accepts := fakeMgmt(t)
	c := NewClient(sock, "")
	if err := c.Kill("nobody"); err == nil {
		t.Fatal("want error for unknown cn")
	}
	if err := c.Kill("alice"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(accepts); got != 1 {
		t.Fatalf("accepts = %d, want 1 (app-level error should not reconnect)", got)
	}
}

// TestReconnectsAfterDrop ensures a dead held connection self-heals: the
// next call transparently redials and succeeds.
func TestReconnectsAfterDrop(t *testing.T) {
	sock, accepts := fakeMgmt(t)
	c := NewClient(sock, "")
	if err := c.Kill("alice"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.conn.Close() // simulate the peer going away
	c.mu.Unlock()

	if err := c.Kill("alice"); err != nil {
		t.Fatalf("expected transparent reconnect, got error: %v", err)
	}
	if got := atomic.LoadInt32(accepts); got != 2 {
		t.Fatalf("accepts = %d, want 2 (one reconnect after drop)", got)
	}
}
