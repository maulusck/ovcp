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

// socksRelays tracks the live per-upstream listeners, keyed by local relay
// port. Touched only from Apply (via startSOCKSRelays), which already holds
// applyMu for its whole run — no separate lock needed here.
var socksRelays = map[int]net.Listener{}

// startSOCKSRelays tears down every relay and starts one fresh per
// SOCKS-kind upstream in cfg — the same tear-down-then-rebuild shape Apply
// already uses for routes and the nft table.
func startSOCKSRelays(cfg Config) error {
	stopSOCKSRelays()
	var errs []error
	for _, u := range cfg.Upstreams {
		if !u.IsSOCKS() {
			continue
		}
		backend, err := url.Parse(u.SOCKS) // shape already checked by Config.Validate
		if err != nil {
			// Not %w-wrapped: see validateSOCKSURL's identical note — this
			// error can reach slog via Apply's caller, a credential-bearing
			// URL must never get there even indirectly. Unreachable in
			// practice (Validate already guarantees a successful parse
			// before any config is stored), kept safe anyway.
			errs = append(errs, fmt.Errorf("upstream: %q: unparseable socks url", u.ID))
			continue
		}
		port := u.socksPort()
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			errs = append(errs, fmt.Errorf("upstream: %q: socks relay listen: %w", u.ID, err))
			continue
		}
		socksRelays[port] = ln
		go relayLoop(ln, backend)
	}
	return errors.Join(errs...)
}

func stopSOCKSRelays() {
	for port, ln := range socksRelays {
		ln.Close()
		delete(socksRelays, port)
	}
}

// relayLoop accepts until ln is closed (by the next Apply/Teardown rebuild),
// which is the normal, expected way this loop ends.
func relayLoop(ln net.Listener, backend *url.URL) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go relayConn(conn.(*net.TCPConn), backend)
	}
}

// relayConn recovers the client's real destination (rewritten to this
// listener's own address by nft's redirect) and hands off to relayToDst.
// Any failure just drops the connection — the client's TCP connect times
// out/resets, never falls through to a leak.
func relayConn(conn *net.TCPConn, backend *url.URL) {
	defer conn.Close()
	dst, err := getOriginalDst(conn)
	if err != nil {
		return
	}
	relayToDst(conn, backend, dst)
}

// relayToDst is relayConn's testable half (getOriginalDst needs a real
// SO_ORIGINAL_DST-tagged connection, this doesn't) — pipes bytes through a
// fresh SOCKS5 CONNECT to backend for dst, unless refused first.
func relayToDst(conn net.Conn, backend *url.URL, dst *net.TCPAddr) {
	// A client can pick any destination, including the ovcp host's own
	// loopback — normally unreachable from a VPN client no matter which
	// upstream carries their traffic, since the kernel never routes to
	// 127.0.0.0/8 via a real interface. This relay dials via userspace
	// net.Dial instead of kernel routing, which does not carry that
	// protection: a self-hosted SOCKS backend running on the same host
	// (one of the three documented backend types) would otherwise let any
	// VPN client reach whatever else is bound to loopback on that host —
	// the admin UI, or any other locally-bound service. Refused here,
	// unconditionally, the same fail-closed treatment as every other error
	// in this file.
	if dst.IP.IsLoopback() {
		return
	}
	up, err := socksConnect(backend, dst)
	if err != nil {
		return
	}
	pipe(conn, up)
}

// pipe relays bytes both directions until either side finishes, then closes
// both — full close, not half: a half-close (CloseWrite) left the other
// direction's io.Copy blocked forever on Read() whenever that peer didn't
// respond to a FIN by closing its own side — goroutine + fd leaked per
// client that disconnects against an idle/unresponsive backend, until the
// backend eventually timed out on its own (if ever).
func pipe(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	go func() {
		io.Copy(b, a)
		b.Close()
	}()
	io.Copy(a, b)
}

// getOriginalDst recovers the pre-redirect destination via SO_ORIGINAL_DST —
// the same mechanism iptables/nft REDIRECT has always exposed for this.
// x/sys/unix has no typed wrapper for it, so this goes straight to the
// syscall it already provides (Syscall6, SO_ORIGINAL_DST, RawSockaddrInet4).
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

// dialTimeout/handshakeTimeout: package vars, not consts, so
// OVCP_UPSTREAM_SOCKS_DIAL_TIMEOUT/OVCP_UPSTREAM_SOCKS_HANDSHAKE_TIMEOUT
// (seconds) can override the sane default for a slower or faster network —
// same override-by-env-var shape OVCP_STATS_SAMPLE_INTERVAL etc. already use
// elsewhere. dialTimeout bounds the raw TCP connect only — should never
// legitimately take long regardless of backend type. handshakeTimeout bounds
// the SOCKS negotiation once connected, in particular the CONNECT reply
// wait — for a Tor backend specifically that covers real circuit-build time,
// which can legitimately run well past dialTimeout under network load, so it
// stays separate and more generous by default. Without any bound here, a
// slow or malicious backend that never completes the handshake leaks one
// goroutine and one fd per stuck client connection, forever (no cap on
// concurrent attempts either). Cleared once the handshake succeeds: the
// relay phase (pipe) is meant to be long-lived, unlike the handshake.
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
// dst (RFC 1928, plus RFC 1929 user/pass auth when backend carries
// credentials). CONNECT is the only command implemented — ovcp never needs
// BIND or UDP ASSOCIATE, and dst always comes from SO_ORIGINAL_DST, never a
// domain name, so the request side only ever emits an IPv4/IPv6 address.
func socksConnect(backend *url.URL, dst *net.TCPAddr) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", backend.Host, dialTimeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := socksHandshake(conn, backend, dst); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksHandshake(conn net.Conn, backend *url.URL, dst *net.TCPAddr) error {
	methods := []byte{0x00} // no-auth
	if backend.User != nil {
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
		if err := socksAuth(conn, backend.User); err != nil {
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
