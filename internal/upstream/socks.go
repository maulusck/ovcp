package upstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// socksRelay is one live relay listener plus the exact Upstream it was
// started from — compared by value on every sync so an unrelated Apply
// call, or a repeat of the same one, never touches a relay that hasn't
// actually changed. Upstream has no slice/map/pointer fields, so == is a
// real deep comparison, not identity.
type socksRelay struct {
	ln net.Listener
	u  Upstream
}

// socksRelays tracks the live per-upstream relays, keyed by local relay
// port. Touched only from Apply (via syncSOCKSRelays), which already holds
// applyMu for its whole run — no separate lock needed here.
var socksRelays = map[int]socksRelay{}

// socksBackend bundles a SOCKS backend's connection target with its
// resolved timeouts — one value threaded through the relay chain instead of
// three positional params growing at every call site.
type socksBackend struct {
	url              *url.URL
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
}

// syncSOCKSRelays reconciles the live relay set with cfg's SOCKS upstreams:
// stops what's gone or reconfigured, starts what's missing, leaves every
// unchanged relay untouched — calling this twice with the same cfg is a
// real no-op, not just one with an equivalent end state.
func syncSOCKSRelays(cfg Config) error {
	want := map[int]Upstream{}
	for _, u := range cfg.Upstreams {
		if u.IsSOCKS() {
			want[u.socksPort()] = u
		}
	}
	for port, r := range socksRelays {
		if want[port] != r.u {
			r.ln.Close()
			delete(socksRelays, port)
		}
	}
	var errs []error
	for port, u := range want {
		if _, live := socksRelays[port]; live {
			continue // already running with this exact config
		}
		parsed, err := url.Parse(u.SOCKS) // shape already checked by Config.Validate
		if err != nil {
			// Not %w-wrapped: raw URL may carry a password, and this can
			// reach slog via Apply's caller. Unreachable in practice.
			errs = append(errs, fmt.Errorf("upstream: %q: unparseable socks url", u.ID))
			continue
		}
		backend := socksBackend{
			url:              parsed,
			dialTimeout:      resolveTimeout(u.DialTimeout, dialTimeout),
			handshakeTimeout: resolveTimeout(u.HandshakeTimeout, handshakeTimeout),
		}
		// 0.0.0.0, not 127.0.0.1: nft's redirect always targets the packet's
		// own inbound interface address (the tunnel), never loopback — a listener
		// bound to 127.0.0.1 never receives redirected traffic. A direct,
		// non-redirected connection to this port is still rejected, by
		// relayConn (see its own comment), not by the bind address.
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			errs = append(errs, fmt.Errorf("upstream: %q: socks relay listen: %w", u.ID, err))
			continue
		}
		socksRelays[port] = socksRelay{ln: ln, u: u}
		go relayLoop(ln, backend)
	}
	return errors.Join(errs...)
}

// resolveTimeout: an upstream's own override (seconds, positive) if set,
// else the server-wide default.
func resolveTimeout(perUpstream int, def time.Duration) time.Duration {
	if perUpstream <= 0 {
		return def
	}
	return time.Duration(perUpstream) * time.Second
}

// relayLoop accepts until ln is closed (by the next Apply/Teardown rebuild),
// which is the normal, expected way this loop ends.
func relayLoop(ln net.Listener, backend socksBackend) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go relayConn(conn.(*net.TCPConn), backend)
	}
}

// relayConn recovers the real destination and hands off to relayToDst —
// any failure just drops the connection, never falls through to a leak.
// Listening on 0.0.0.0 (needed because nft's redirect targets the inbound
// interface's own address, never loopback) means a direct, non-redirected
// connection can reach this port too; SO_ORIGINAL_DST for one of those
// equals the socket's own local address rather than some other real
// destination (proven by TestGetOriginalDst), which is exactly how this
// tells the two apart.
func relayConn(conn *net.TCPConn, backend socksBackend) {
	defer conn.Close()
	dst, err := getOriginalDst(conn)
	if err != nil {
		return
	}
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok && dst.IP.Equal(local.IP) && dst.Port == local.Port {
		return // not actually redirected — a direct connection to the relay itself
	}
	relayToDst(conn, backend, dst)
}

// relayToDst is relayConn's testable half (getOriginalDst needs a real
// SO_ORIGINAL_DST-tagged connection, this doesn't) — pipes bytes through a
// fresh SOCKS5 CONNECT to backend for dst, unless refused first.
func relayToDst(conn net.Conn, backend socksBackend, dst *net.TCPAddr) {
	// SSRF guard: userspace net.Dial (unlike kernel routing) can reach
	// loopback — a same-host self-hosted backend would let any client
	// reach whatever else is bound there. Refused unconditionally.
	if dst.IP.IsLoopback() {
		return
	}
	up, err := socksConnect(backend, dst)
	if err != nil {
		return
	}
	pipe(conn, up)
}

// pipe relays both directions, full-closing both when either finishes —
// a half-close (CloseWrite) left the other io.Copy blocked on Read()
// forever against an unresponsive peer: a goroutine+fd leak, now fixed.
func pipe(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	go func() {
		io.Copy(b, a)
		b.Close()
	}()
	io.Copy(a, b)
}

// getOriginalDst recovers the pre-redirect destination via SO_ORIGINAL_DST,
// same as iptables/nft REDIRECT — no typed wrapper in x/sys/unix, so this
// goes straight to the syscall.
func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	sc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var addr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))
	var errno unix.Errno
	if err := sc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IP, unix.SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		return nil, err
	}
	if errno != 0 {
		return nil, errno
	}
	port := int(addr.Port>>8 | addr.Port<<8) // network byte order -> host
	return &net.TCPAddr{IP: net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3]), Port: port}, nil
}

// dialTimeout/handshakeTimeout: server-wide defaults, env-var overridable
// (same shape as OVCP_STATS_SAMPLE_INTERVAL) and further per-upstream
// (resolveTimeout) — unbounded, a stuck handshake leaks a goroutine+fd forever.
var (
	dialTimeout      = envSeconds("OVCP_UPSTREAM_SOCKS_DIAL_TIMEOUT", 10)
	handshakeTimeout = envSeconds("OVCP_UPSTREAM_SOCKS_HANDSHAKE_TIMEOUT", 30)
)

// envSeconds reads key as a positive integer number of seconds, def if unset
// or invalid.
func envSeconds(key string, def int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(def) * time.Second
}

// socksConnect dials backend and performs a SOCKS5 CONNECT handshake for
// dst (RFC 1928/1929). CONNECT-only — no BIND/UDP ASSOCIATE needed, and
// dst is always a raw IP (from SO_ORIGINAL_DST), never a domain name.
func socksConnect(backend socksBackend, dst *net.TCPAddr) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", backend.url.Host, backend.dialTimeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(backend.handshakeTimeout))
	if err := socksHandshake(conn, backend, dst); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksHandshake(conn net.Conn, backend socksBackend, dst *net.TCPAddr) error {
	methods := []byte{0x00} // no-auth
	if backend.url.User != nil {
		methods = []byte{0x02} // user/pass, offered only when the URL carries credentials
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("socks: bad version %#x in method reply", reply[0])
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if err := socksAuth(conn, backend.url.User); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks: server chose unsupported method %#x", reply[1])
	}
	return socksRequestConnect(conn, dst)
}

func socksAuth(conn net.Conn, user *url.Userinfo) error {
	name := user.Username()
	pass, _ := user.Password()
	req := []byte{0x01, byte(len(name))}
	req = append(req, name...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		return err
	}
	if status[1] != 0x00 {
		return fmt.Errorf("socks: auth rejected")
	}
	return nil
}

func socksRequestConnect(conn net.Conn, dst *net.TCPAddr) error {
	var req []byte
	if ip4 := dst.IP.To4(); ip4 != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
	} else {
		req = append([]byte{0x05, 0x01, 0x00, 0x04}, dst.IP.To16()...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(dst.Port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	// ver, rep, rsv, atyp — bound addr/port follow, length depends on atyp, unused either way.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks: connect refused, code %#x", head[1])
	}
	var addrLen int
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		addrLen = int(lenByte[0])
	default:
		return fmt.Errorf("socks: unknown address type %#x in reply", head[3])
	}
	_, err := io.CopyN(io.Discard, conn, int64(addrLen+2))
	return err
}
