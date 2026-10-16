package upstream

import (
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestEnvSeconds(t *testing.T) {
	const key = "OVCP_TEST_ENV_SECONDS"
	cases := map[string]time.Duration{
		"":    5 * time.Second,  // unset
		"20":  20 * time.Second, // valid override
		"0":   5 * time.Second,  // zero, not positive: falls back
		"-3":  5 * time.Second,  // negative: falls back
		"abc": 5 * time.Second,  // unparseable: falls back
	}
	for v, want := range cases {
		t.Run(v, func(t *testing.T) {
			t.Setenv(key, v) // "" counts as unset for os.Getenv
			if got := envSeconds(key, 5); got != want {
				t.Errorf("envSeconds(%q, 5) = %v, want %v", v, got, want)
			}
		})
	}
}

// TestSyncSOCKSRelaysIsIdempotent: calling sync twice with the identical
// config must not touch the listener at all — not just leave an equivalent
// one in its place. Reconfiguring the same upstream (or removing it) must
// still close the old one.
func TestSyncSOCKSRelaysIsIdempotent(t *testing.T) {
	defer syncSOCKSRelays(Config{}) // cleanup, whatever state the test ends in

	u1 := Upstream{ID: "tor", SOCKS: "socks5://127.0.0.1:9050", Table: tableBase}
	if err := syncSOCKSRelays(Config{Upstreams: []Upstream{u1}}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	port := u1.socksPort()
	first := socksRelays[port].ln
	if first == nil {
		t.Fatal("sync did not start a relay")
	}

	if err := syncSOCKSRelays(Config{Upstreams: []Upstream{u1}}); err != nil {
		t.Fatalf("sync (repeat): %v", err)
	}
	if socksRelays[port].ln != first {
		t.Fatal("syncSOCKSRelays must not restart an unchanged relay")
	}

	u2 := u1
	u2.SOCKS = "socks5://127.0.0.1:9051" // same port/table, different backend
	if err := syncSOCKSRelays(Config{Upstreams: []Upstream{u2}}); err != nil {
		t.Fatalf("sync (reconfigure): %v", err)
	}
	if socksRelays[port].ln == first {
		t.Fatal("syncSOCKSRelays must restart a relay whose config changed")
	}
	if err := first.Close(); err == nil {
		t.Fatal("the old listener should already be closed by sync")
	}

	if err := syncSOCKSRelays(Config{}); err != nil {
		t.Fatalf("sync (removed): %v", err)
	}
	if _, ok := socksRelays[port]; ok {
		t.Fatal("syncSOCKSRelays must remove a relay whose upstream is gone")
	}
}

func TestResolveTimeout(t *testing.T) {
	cases := []struct {
		name        string
		perUpstream int
		def         time.Duration
		want        time.Duration
	}{
		{"unset falls back to default", 0, 10 * time.Second, 10 * time.Second},
		{"negative falls back to default", -1, 10 * time.Second, 10 * time.Second},
		{"positive override wins", 5, 10 * time.Second, 5 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveTimeout(c.perUpstream, c.def); got != c.want {
				t.Errorf("resolveTimeout(%d, %v) = %v, want %v", c.perUpstream, c.def, got, c.want)
			}
		})
	}
}

// TestRelayToDstRefusesLoopback: a loopback destination must never reach
// the backend at all (SSRF guard) — asserts the handler never even runs,
// not just that the client connection gets closed.
func TestRelayToDstRefusesLoopback(t *testing.T) {
	called := false
	backend := fakeSOCKSServer(t, func(conn net.Conn) { called = true })
	_, srv := net.Pipe()

	relayToDst(srv, backend, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443})

	if called {
		t.Fatal("relayToDst must refuse a loopback destination before ever dialing the backend")
	}
}

// TestPipeClosesBothOnEitherSideFinishing: pipe used to CloseWrite (half-
// close) instead of fully closing, leaking the other leg against an
// unresponsive peer. Proves pipe returns promptly and the far side closes.
func TestPipeClosesBothOnEitherSideFinishing(t *testing.T) {
	aClient, aServer := net.Pipe() // stands in for relayConn's client leg
	bClient, bServer := net.Pipe() // stands in for relayConn's backend leg

	done := make(chan struct{})
	go func() {
		pipe(aServer, bServer)
		close(done)
	}()

	aClient.Close() // simulate the client disconnecting

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not return after one side closed — the other leg leaked")
	}

	bClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the backend leg to be force-closed, read succeeded instead")
	}
}

// TestRelayConnRejectsDirectConnection: a connection nft never redirected
// (no conntrack entry, or original dst == the relay itself) never reaches the backend.
func TestRelayConnRejectsDirectConnection(t *testing.T) {
	called := false
	backend := fakeSOCKSServer(t, func(conn net.Conn) { called = true })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	relayConn(server.(*net.TCPConn), backend)
	if called {
		t.Fatal("relayConn must refuse a direct, non-redirected connection before ever dialing the backend")
	}
}

// fakeSOCKSServer accepts one connection and runs handle against it —
// enough to drive socksHandshake's exact wire format from the other side.
func fakeSOCKSServer(t *testing.T, handle func(conn net.Conn)) socksBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handle(conn)
	}()
	u, err := url.Parse("socks5://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return socksBackend{url: u, dialTimeout: 2 * time.Second, handshakeTimeout: 2 * time.Second}
}

func TestSOCKSConnectNoAuth(t *testing.T) {
	backend := fakeSOCKSServer(t, func(conn net.Conn) {
		greeting := make([]byte, 3)
		io.ReadFull(conn, greeting)
		if greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00 {
			t.Errorf("bad greeting, want ver=5 nmethods=1 method=noauth: % x", greeting)
		}
		conn.Write([]byte{0x05, 0x00})
		req := make([]byte, 10) // ver,cmd,rsv,atyp,ipv4(4),port(2)
		io.ReadFull(conn, req)
		if req[0] != 0x05 || req[1] != 0x01 || req[3] != 0x01 {
			t.Errorf("bad connect request, want ver=5 cmd=connect atyp=ipv4: % x", req)
		}
		if req[4] != 93 || req[5] != 184 || req[6] != 216 || req[7] != 34 {
			t.Errorf("bad dest ip in request: % x", req[4:8])
		}
		if req[8] != 0x01 || req[9] != 0xBB { // 443
			t.Errorf("bad dest port in request: % x", req[8:10])
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
	dst := &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}
	conn, err := socksConnect(backend, dst)
	if err != nil {
		t.Fatalf("socksConnect: %v", err)
	}
	conn.Close()
}

func TestSOCKSConnectWithAuth(t *testing.T) {
	backend := fakeSOCKSServer(t, func(conn net.Conn) {
		greeting := make([]byte, 3)
		io.ReadFull(conn, greeting)
		if greeting[2] != 0x02 {
			t.Errorf("client must offer user/pass method when backend has credentials: % x", greeting)
		}
		conn.Write([]byte{0x05, 0x02}) // choose user/pass
		authHead := make([]byte, 2)
		io.ReadFull(conn, authHead)
		user := make([]byte, authHead[1])
		io.ReadFull(conn, user)
		passLen := make([]byte, 1)
		io.ReadFull(conn, passLen)
		pass := make([]byte, passLen[0])
		io.ReadFull(conn, pass)
		if string(user) != "alice" || string(pass) != "hunter2" {
			t.Errorf("got user=%q pass=%q, want alice/hunter2", user, pass)
		}
		conn.Write([]byte{0x01, 0x00}) // auth ok
		req := make([]byte, 10)
		io.ReadFull(conn, req)
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
	backend.url.User = url.UserPassword("alice", "hunter2")
	dst := &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}
	conn, err := socksConnect(backend, dst)
	if err != nil {
		t.Fatalf("socksConnect: %v", err)
	}
	conn.Close()
}

func TestSOCKSConnectAuthRejected(t *testing.T) {
	backend := fakeSOCKSServer(t, func(conn net.Conn) {
		io.ReadFull(conn, make([]byte, 3))
		conn.Write([]byte{0x05, 0x02})
		authHead := make([]byte, 2)
		io.ReadFull(conn, authHead)
		io.ReadFull(conn, make([]byte, int(authHead[1])+1))
		conn.Write([]byte{0x01, 0x01}) // auth failed
	})
	backend.url.User = url.UserPassword("alice", "wrong")
	if _, err := socksConnect(backend, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 80}); err == nil {
		t.Fatal("expected error on rejected auth")
	}
}

func TestSOCKSConnectRefused(t *testing.T) {
	backend := fakeSOCKSServer(t, func(conn net.Conn) {
		io.ReadFull(conn, make([]byte, 3))
		conn.Write([]byte{0x05, 0x00})
		io.ReadFull(conn, make([]byte, 10))
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 0x05 = connection refused
	})
	if _, err := socksConnect(backend, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 80}); err == nil {
		t.Fatal("expected error when backend refuses the connect")
	}
}

func TestSOCKSConnectIPv6Dest(t *testing.T) {
	backend := fakeSOCKSServer(t, func(conn net.Conn) {
		io.ReadFull(conn, make([]byte, 3))
		conn.Write([]byte{0x05, 0x00})
		req := make([]byte, 22) // ver,cmd,rsv,atyp,ipv6(16),port(2)
		io.ReadFull(conn, req)
		if req[3] != 0x04 {
			t.Errorf("want atyp=ipv6 (0x04), got %#x", req[3])
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80}
	conn, err := socksConnect(backend, dst)
	if err != nil {
		t.Fatalf("socksConnect: %v", err)
	}
	conn.Close()
}
