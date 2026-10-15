package controller

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMgmt emulates openvpn's mgmt interface on a unix socket, returning the
// socket path and an accept counter so tests can assert reuse vs. reconnects.
// Only client-kill is emulated: CID 7 (alice) succeeds, any other (ghost's 99) errors.
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
					case cmd == "hold release":
						c.Write([]byte("SUCCESS: hold release succeeded\r\n"))
					case cmd == "client-kill 7 HALT", cmd == "client-kill 7 RESTART":
						c.Write([]byte("SUCCESS: client-kill command succeeded\r\n"))
					case strings.HasPrefix(cmd, "client-kill "):
						c.Write([]byte("ERROR: client-kill command failed\r\n"))
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

// killStatus is oneClientStatus plus ghost (CID 99), whose client-kill fakeMgmt refuses.
var killStatus = strings.Replace(oneClientStatus, "END\r\n",
	"CLIENT_LIST\tghost\t203.0.113.9:1\t10.8.0.9\t\t0\t0\tSat Jul  5 11:00:00 2026\t1783080000\tUNDEF\t99\t0\tAES-256-GCM\r\nEND\r\n", 1)

const oneClientStatus = "TITLE\tOpenVPN 2.6.12\r\n" +
	"TIME\t2026-07-05 12:00:00\t1783000000\r\n" +
	"HEADER\tCLIENT_LIST\t...\r\n" +
	"CLIENT_LIST\talice\t203.0.113.7:55010\t10.8.0.2\t\t1024\t2048\tSat Jul  5 11:00:00 2026\t1783080000\tUNDEF\t7\t0\tAES-256-GCM\r\n" +
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
	if len(cl) != 1 || cl[0].CID != "7" || cl[0].CN != "alice" || cl[0].BytesSent != 2048 ||
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

// TestKill: client-kill by the live session's CID, with either message;
// the fake only accepts "client-kill 7 HALT|RESTART".
func TestKill(t *testing.T) {
	sock, _ := fakeMgmt(t)
	c := NewClient(sock, writeStatus(t, killStatus))
	for _, msg := range []string{"HALT", "RESTART"} {
		if err := c.Kill("alice", msg); err != nil {
			t.Fatalf("%s: %v", msg, err)
		}
	}
	if err := c.Kill("nobody", "HALT"); err == nil {
		t.Fatal("want error for a cn with no session")
	}
	if err := c.Kill("alice", "SIGTERM"); err == nil {
		t.Fatal("want error for an unknown message")
	}
}

// TestAppErrorKeepsConnection ensures a well-formed "ERROR: ..." reply
// doesn't trigger a reconnect — only actual connection failures should.
func TestAppErrorKeepsConnection(t *testing.T) {
	sock, accepts := fakeMgmt(t)
	c := NewClient(sock, writeStatus(t, killStatus))
	if err := c.Kill("ghost", "HALT"); err == nil {
		t.Fatal("want the fake's ERROR reply for ghost")
	}
	if err := c.Kill("alice", "HALT"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(accepts); got != 1 {
		t.Fatalf("accepts = %d, want 1 (app-level error should not reconnect)", got)
	}
}

// fakeMgmtNotify accepts one connection and hands the server-side conn
// back (post-banner) for the test to script >CLIENT:... notifications on.
func fakeMgmtNotify(t *testing.T) (sock string, onConn <-chan net.Conn) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "mgmt.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
		// consume+ack connect()'s "hold release" handshake before handing
		// the raw conn off — same sequence real openvpn does.
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("SUCCESS: hold release succeeded\r\n"))
		ch <- c
	}()
	return sock, ch
}

// Every >CLIENT:CONNECT is auto-approved, handler or not — ovcp never
// chooses or denies a client's address here.
func TestClientConnectAlwaysApproves(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, "")
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	server := <-onConn
	defer server.Close()
	r := bufio.NewReader(server)

	server.Write([]byte(">CLIENT:CONNECT,5,0\r\n>CLIENT:ENV,common_name=bob\r\n>CLIENT:ENV,END\r\n"))
	if got := readLine(t, server, r); got != "client-auth-nt 5 0" {
		t.Fatalf("got %q, want client-auth-nt 5 0", got)
	}
}

func TestClientEstablishedCallsHandler(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, "")
	type established struct{ cid, cn, ip string }
	done := make(chan established, 1)
	c.OnClientEstablished = func(cid, cn, ip string, env map[string]string) {
		done <- established{cid, cn, ip}
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	server := <-onConn
	defer server.Close()

	server.Write([]byte(">CLIENT:ESTABLISHED,1\r\n>CLIENT:ENV,common_name=alice\r\n>CLIENT:ENV,ifconfig_pool_remote_ip=10.8.0.9\r\n>CLIENT:ENV,END\r\n"))
	select {
	case got := <-done:
		if got.cid != "1" || got.cn != "alice" || got.ip != "10.8.0.9" {
			t.Fatalf("got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnClientEstablished never called")
	}
}

// A panicking OnClientEstablished must not kill the reader goroutine —
// proven by a second, healthy notification landing right after.
func TestClientEstablishedPanicRecovers(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, "")
	c.OnClientEstablished = func(cid, cn, ip string, env map[string]string) { panic("boom") }
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	server := <-onConn
	defer server.Close()
	r := bufio.NewReader(server)

	server.Write([]byte(">CLIENT:ESTABLISHED,1\r\n>CLIENT:ENV,common_name=alice\r\n>CLIENT:ENV,END\r\n"))
	server.Write([]byte(">CLIENT:CONNECT,2,0\r\n>CLIENT:ENV,common_name=bob\r\n>CLIENT:ENV,END\r\n"))
	if got := readLine(t, server, r); got != "client-auth-nt 2 0" {
		t.Fatalf("got %q, want the reader still alive after the established-handler panic", got)
	}
}

// A panicking OnClientDisconnect must not kill the reader — proven the
// same way, by a healthy connect landing right after it.
func TestClientDisconnectPanicRecovers(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, "")
	c.OnClientDisconnect = func(cid string, env map[string]string) { panic("boom") }
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	server := <-onConn
	defer server.Close()
	r := bufio.NewReader(server)

	server.Write([]byte(">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,common_name=alice\r\n>CLIENT:ENV,END\r\n"))
	server.Write([]byte(">CLIENT:CONNECT,2,0\r\n>CLIENT:ENV,common_name=bob\r\n>CLIENT:ENV,END\r\n"))
	if got := readLine(t, server, r); got != "client-auth-nt 2 0" {
		t.Fatalf("got %q, want the reader still alive after the disconnect panic", got)
	}
}

func TestClientDisconnectCallsHandler(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, "")
	done := make(chan map[string]string, 1)
	var gotCID string
	c.OnClientDisconnect = func(cid string, env map[string]string) { gotCID = cid; done <- env }
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	server := <-onConn
	defer server.Close()

	server.Write([]byte(">CLIENT:DISCONNECT,3\r\n>CLIENT:ENV,common_name=dave\r\n>CLIENT:ENV,ifconfig_pool_remote_ip=10.8.0.4\r\n>CLIENT:ENV,END\r\n"))
	select {
	case env := <-done:
		if gotCID != "3" || env["common_name"] != "dave" || env["ifconfig_pool_remote_ip"] != "10.8.0.4" {
			t.Fatalf("cid=%q env=%+v", gotCID, env)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnClientDisconnect never called")
	}
}

// A CLIENT:CONNECT notification during Kill's in-flight exec() must not
// deadlock — the reader needs writeMu, not c.mu, to answer it.
func TestClientConnectDuringKillDoesNotDeadlock(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, writeStatus(t, killStatus))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	server := <-onConn
	defer server.Close()

	killDone := make(chan error, 1)
	go func() { killDone <- c.Kill("alice", "HALT") }()

	r := bufio.NewReader(server)
	if got := readLine(t, server, r); got != "client-kill 7 HALT" {
		t.Fatalf("got %q, want client-kill 7 HALT", got)
	}
	// push the notification before answering kill — the reader must handle
	// it (and write back) without Kill's own in-flight exec() blocking it.
	server.Write([]byte(">CLIENT:CONNECT,9,0\r\n>CLIENT:ENV,common_name=eve\r\n>CLIENT:ENV,END\r\n"))
	if got := readLine(t, server, r); got != "client-auth-nt 9 0" {
		t.Fatalf("got %q, want client-auth-nt 9 0", got)
	}
	server.Write([]byte("SUCCESS: client-kill command succeeded\r\n"))

	select {
	case err := <-killDone:
		if err != nil {
			t.Fatalf("Kill: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock: Kill never completed after the CLIENT:CONNECT notification")
	}
}

// Hammers write() against drop() directly and concurrently — real protocol
// timing is too fast/slow to reliably land them in the same instant. Run
// with -race; nothing here asserts correctness, only absence of a race.
func TestWriteDropNoRace(t *testing.T) {
	sock, onConn := fakeMgmtNotify(t)
	c := NewClient(sock, "")
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	<-onConn

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			c.write("noop\n")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			c.drop()
		}
	}()
	wg.Wait()
}

// readLine reads one line off r (must wrap conn, reused across calls so
// nothing already buffered gets dropped), with a deadline so a deadlock
// fails this test fast instead of hanging the whole suite.
func readLine(t *testing.T, conn net.Conn, r *bufio.Reader) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// TestReconnectsAfterDrop ensures a dead held connection self-heals: the
// next call transparently redials and succeeds.
func TestReconnectsAfterDrop(t *testing.T) {
	sock, accepts := fakeMgmt(t)
	c := NewClient(sock, writeStatus(t, killStatus))
	if err := c.Kill("alice", "HALT"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.conn.Close() // simulate the peer going away
	c.mu.Unlock()

	if err := c.Kill("alice", "HALT"); err != nil {
		t.Fatalf("expected transparent reconnect, got error: %v", err)
	}
	if got := atomic.LoadInt32(accepts); got != 2 {
		t.Fatalf("accepts = %d, want 2 (one reconnect after drop)", got)
	}
}

// TestConnectRedialsAfterPeerCloses: samplerTick's own passive retry loop
// (see stats.go) only ever calls Connect(), never an exec()-based command —
// unlike TestReconnectsAfterDrop, nothing here forces a reconnect via a
// failed write. If readLoop doesn't notice the peer going away (e.g. openvpn
// restarting with a fresh mgmt listener) and clear c.conn itself, Connect()
// wrongly no-ops forever and every future >CLIENT:CONNECT is lost until the
// whole ovcp process restarts — a real bug found on hardware.
func TestConnectRedialsAfterPeerCloses(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
			bufio.NewReader(c).ReadString('\n') // "hold release"
			c.Write([]byte("SUCCESS: hold release succeeded\r\n"))
			accepted <- c
		}
	}()

	c := NewClient(sock, "")
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	first := <-accepted
	first.Close() // simulate openvpn exiting: the peer, not us, hangs up

	// readLoop's blocked read must unblock on the peer close and drop c.conn
	// — poll instead of a fixed sleep, since that's inherently racy either way.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-accepted:
			return // redialed successfully
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Connect() never redialed after the peer closed its end")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestConnectRetrySucceedsOnceSocketAppears: socket doesn't exist yet, then
// appears — ConnectRetry must succeed once it does, not just once at the
// first attempt (found via an E2E flake: a single Connect() right after
// `vpn restart` was too early, every time).
func TestConnectRetrySucceedsOnceSocketAppears(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	c := NewClient(sock, "")

	// Nothing listening yet — Connect() fails immediately (ENOENT-style),
	// same as right after Supervisor.Restart() launches the new process.
	if err := c.Connect(); err == nil {
		t.Fatal("Connect() succeeded against a socket that doesn't exist yet")
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		l, err := net.Listen("unix", sock)
		if err != nil {
			return
		}
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
		bufio.NewReader(conn).ReadString('\n') // "hold release"
		conn.Write([]byte("SUCCESS: hold release succeeded\r\n"))
		<-make(chan struct{}) // hold the connection open for the test's duration
	}()

	if err := c.ConnectRetry(2 * time.Second); err != nil {
		t.Fatalf("ConnectRetry never succeeded once the socket appeared: %v", err)
	}
}

// TestConnectRetryBoundedWhenNeverAvailable: ConnectRetry must give up and
// report the failure, not hang forever, when the socket never appears.
func TestConnectRetryBoundedWhenNeverAvailable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock") // nothing ever listens here
	c := NewClient(sock, "")

	start := time.Now()
	err := c.ConnectRetry(300 * time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("ConnectRetry succeeded against a socket that was never created")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ConnectRetry took %s to give up — not bounded", elapsed)
	}
}

// TestConnectFailsWhenHoldReleaseErrors: the crux of the fix — Connect()
// must fail, not silently succeed, if openvpn's own reply to "hold release"
// says ERROR. A caller trusting a nil error here must actually be governed,
// never mid-handshake with hold still up.
func TestConnectFailsWhenHoldReleaseErrors(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))
		bufio.NewReader(c).ReadString('\n') // "hold release"
		c.Write([]byte("ERROR: hold flag not set\r\n"))
	}()

	if err := NewClient(sock, "").Connect(); err == nil {
		t.Fatal("Connect() succeeded despite an ERROR reply to hold release")
	}
}
