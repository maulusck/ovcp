package controller

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// fakeMgmt emulates the openvpn management interface on a unix socket.
func fakeMgmt(t *testing.T) string {
	t.Helper()
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
					case cmd == "status 3":
						c.Write([]byte(
							"TITLE\tOpenVPN 2.6.12\r\n" +
								"TIME\t2026-07-05 12:00:00\t1783000000\r\n" +
								"HEADER\tCLIENT_LIST\t...\r\n" +
								"CLIENT_LIST\talice\t203.0.113.7:55010\t10.8.0.2\t\t1024\t2048\tSat Jul  5 11:00:00 2026\t1783080000\tUNDEF\t0\t0\tAES-256-GCM\r\n" +
								"HEADER\tROUTING_TABLE\t...\r\n" +
								"ROUTING_TABLE\t10.8.0.2\talice\t203.0.113.7:55010\t...\r\n" +
								"GLOBAL_STATS\tMax bcast/mcast queue length\t0\r\n" +
								"END\r\n"))
					case strings.HasPrefix(cmd, "kill alice"):
						c.Write([]byte("SUCCESS: common name 'alice' found, 1 client(s) killed\r\n"))
					case strings.HasPrefix(cmd, "kill "):
						c.Write([]byte("ERROR: common name not found\r\n"))
					}
				}
			}(c)
		}
	}()
	return sock
}

func TestStatusKill(t *testing.T) {
	c := NewClient(fakeMgmt(t))
	cl, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(cl) != 1 || cl[0].CN != "alice" || cl[0].BytesSent != 2048 ||
		cl[0].VirtualAddress != "10.8.0.2" || cl[0].Cipher != "AES-256-GCM" {
		t.Fatalf("parsed: %+v", cl)
	}
	if err := c.Kill("alice"); err != nil {
		t.Fatal(err)
	}
	if err := c.Kill("nobody"); err == nil {
		t.Fatal("want error for unknown cn")
	}
}

func TestSocketGone(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "nope.sock"))
	if _, err := c.Status(); err == nil {
		t.Fatal("want dial error")
	}
}
