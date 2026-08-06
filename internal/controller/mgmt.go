// Package controller talks to openvpn's management socket over one held
// connection instead of dialing per op, which spammed openvpn.log with
// connect/CMD/disconnect triples every poll.
package controller

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	SocketPath string
	StatusPath string        // openvpn's periodically-rewritten status file (status-version 3); see Status()
	Timeout    time.Duration // per-op; default 5s

	// OnClientConnect/OnClientDisconnect, if set, handle each >CLIENT:
	// CONNECT/DISCONNECT — nil means no-op. Called synchronously, one at a
	// time (ponytail: fine at VPN rates, not a web server's).
	OnClientConnect    func(cid, kid string, env map[string]string) AuthReply
	OnClientDisconnect func(cid string, env map[string]string)

	mu      sync.Mutex // serializes exec(): one command's request/response cycle at a time
	writeMu sync.Mutex // serializes raw writes — exec()'s command vs. the reader's async replies
	conn    net.Conn
	resp    chan string // non->CLIENT: lines, fed by the reader goroutine to exec()
}

func NewClient(socketPath, statusPath string) *Client {
	return &Client{SocketPath: socketPath, StatusPath: statusPath, Timeout: 5 * time.Second}
}

type VPNClient struct {
	CN             string
	RealAddress    string
	VirtualAddress string
	BytesRecv      uint64
	BytesSent      uint64
	ConnectedSince time.Time
	Cipher         string
}

// AuthReply is OnClientConnect's return value: approve (optionally pushing
// directives like ifconfig-push) or deny with a reason. Not a general
// directive-injection API — Directives is the one thing it's for.
type AuthReply struct {
	Deny       string   // non-empty = deny this connection, this is the reason
	Directives []string // approve: extra client-connect directives to push
}

// command renders the mgmt-protocol reply for cid/kid — client-deny,
// client-auth-nt (plain approve), or client-auth (approve + directives).
func (a AuthReply) command(cid, kid string) string {
	if a.Deny != "" {
		return fmt.Sprintf("client-deny %s %s %q", cid, kid, a.Deny)
	}
	if len(a.Directives) == 0 {
		return fmt.Sprintf("client-auth-nt %s %s", cid, kid)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "client-auth %s %s\n", cid, kid)
	for _, d := range a.Directives {
		b.WriteString(d + "\n")
	}
	b.WriteString("END")
	return b.String()
}

// Connect ensures the connection (and its background reader) is live —
// call eagerly at startup when OnClientConnect is set, so an early client
// can't race a connection that would otherwise only start lazily.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getConn() != nil {
		return nil
	}
	return c.connect()
}

// ConnectRetry blocks until Connect succeeds or timeout elapses. A
// reconnecting client is admitted ungoverned (no rule, not a denial) until
// some management client attaches — RunSampler's own poll is too slow for
// callers about to let clients back in (serve's boot, `vpn start/restart`).
func (c *Client) ConnectRetry(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var err error
	for {
		if err = c.Connect(); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// connect dials a fresh connection, consumes the greeting banner, and
// starts the background reader. Caller must hold c.mu with no live c.conn.
func (c *Client) connect() error {
	conn, err := net.DialTimeout("unix", c.SocketPath, c.Timeout)
	if err != nil {
		return fmt.Errorf("controller: mgmt socket unavailable: %w", err)
	}
	conn.SetDeadline(time.Now().Add(c.Timeout))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // >INFO: banner
		conn.Close()
		return err
	}
	conn.SetDeadline(time.Time{}) // reader blocks indefinitely between notifications, not a hang
	resp := make(chan string, 8)
	c.resp = resp
	c.setConn(conn)
	go c.readLoop(r, resp)
	return nil
}

// c.conn has exactly one lock, writeMu — every read and write goes through
// it (getConn/setConn/drop/write), so c.mu-held callers must use getConn,
// never read c.conn directly.
func (c *Client) getConn() net.Conn {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn
}

func (c *Client) setConn(conn net.Conn) {
	c.writeMu.Lock()
	c.conn = conn
	c.writeMu.Unlock()
}

// drop closes and forgets the held connection. Guarded by writeMu alone
// (not c.mu), so both exec()'s c.mu-held retries and readLoop's own
// goroutine can call it safely.
func (c *Client) drop() {
	c.writeMu.Lock()
	conn := c.conn
	c.conn = nil
	c.writeMu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// write serializes raw writes to conn — exec()'s own command and the
// reader goroutine's async client-auth replies share one connection.
func (c *Client) write(s string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("controller: mgmt not connected")
	}
	_, err := c.conn.Write([]byte(s))
	return err
}

// readLoop is the connection's sole reader for its whole life: >CLIENT:
// blocks go to the connect/disconnect handlers, everything else is
// forwarded to resp for whichever exec() call is waiting on it.
func (c *Client) readLoop(r *bufio.Reader, resp chan<- string) {
	defer close(resp)
	for {
		raw, err := r.ReadString('\n')
		if err != nil {
			// The peer (openvpn) hung up — e.g. it restarted with a fresh
			// mgmt listener. Without this, c.conn stays non-nil forever and
			// Connect()'s passive retry (samplerTick) no-ops permanently,
			// silently losing every future >CLIENT:CONNECT.
			c.drop()
			return
		}
		line := strings.TrimRight(raw, "\r\n")
		switch {
		case strings.HasPrefix(line, ">CLIENT:CONNECT,"), strings.HasPrefix(line, ">CLIENT:REAUTH,"):
			c.handleConnect(r, line)
		case strings.HasPrefix(line, ">CLIENT:DISCONNECT,"):
			c.handleDisconnect(r, line)
		default:
			select {
			case resp <- raw: // raw, not line: ReadString('\n') on the other end needs the delimiter
			default: // nobody listening (timed out or stray) — drop, never block the reader
			}
		}
	}
}

// readClientEnv reads >CLIENT:ENV,... lines up to the terminating
// >CLIENT:ENV,END, called synchronously from the reader goroutine.
func readClientEnv(r *bufio.Reader) (map[string]string, error) {
	env := map[string]string{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		rest, ok := strings.CutPrefix(line, ">CLIENT:ENV,")
		if !ok {
			return nil, fmt.Errorf("controller: expected >CLIENT:ENV, got %q", line)
		}
		if rest == "END" {
			return env, nil
		}
		name, val, _ := strings.Cut(rest, "=")
		env[name] = val
	}
}

// handleConnect replies client-auth-nt (no handler / nil), or whatever
// OnClientConnect decides — approve with directives, or deny.
func (c *Client) handleConnect(r *bufio.Reader, header string) {
	parts := strings.SplitN(header, ",", 3)
	if len(parts) != 3 {
		return
	}
	cid, kid := parts[1], parts[2]
	env, err := readClientEnv(r)
	if err != nil {
		return // connection is likely dying; readLoop's next read will notice
	}
	reply := AuthReply{}
	if c.OnClientConnect != nil {
		reply = c.callConnect(cid, kid, env)
	}
	if err := c.write(reply.command(cid, kid) + "\n"); err != nil {
		slog.Warn("mgmt client-auth reply failed", "err", err)
	}
}

// callConnect recovers a panic in OnClientConnect into a deny — a bug in
// the handler must cost one client, never crash the whole process.
func (c *Client) callConnect(cid, kid string, env map[string]string) (reply AuthReply) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("mgmt OnClientConnect panicked", "panic", r)
			reply = AuthReply{Deny: "internal error"}
		}
	}()
	return c.OnClientConnect(cid, kid, env)
}

func (c *Client) handleDisconnect(r *bufio.Reader, header string) {
	_, cid, ok := strings.Cut(header, ",")
	if !ok {
		return
	}
	env, err := readClientEnv(r)
	if err != nil {
		return
	}
	if c.OnClientDisconnect != nil {
		c.callDisconnect(cid, env)
	}
}

// callDisconnect recovers a panic in OnClientDisconnect — same reasoning
// as callConnect, just no reply to send back.
func (c *Client) callDisconnect(cid string, env map[string]string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("mgmt OnClientDisconnect panicked", "panic", r)
		}
	}()
	c.OnClientDisconnect(cid, env)
}

// chanReader presents resp's lines as an io.Reader so exec()'s existing
// *bufio.Reader parsers (simple) work unchanged against the demuxed stream.
type chanReader struct {
	lines <-chan string
	buf   []byte
}

func (r *chanReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		line, ok := <-r.lines
		if !ok {
			return 0, io.EOF
		}
		r.buf = []byte(line)
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// appErr marks a parse failure as an OpenVPN application-level response
// (e.g. "ERROR: ...") rather than a connection failure, so exec won't drop
// and reconnect for it.
type appErr struct{ error }

// exec runs cmd on the held connection, retrying once on a fresh dial after
// any I/O failure (self-heals a stale connection, e.g. after openvpn
// restarts) — but not on an appErr, whose round trip already succeeded.
func (c *Client) exec(cmd string, parse func(*bufio.Reader) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		err = c.tryExec(cmd, parse)
		if err == nil {
			return nil
		}
		if ae, ok := err.(appErr); ok {
			return ae.error
		}
		c.drop()
	}
	return err
}

// tryExec times out via select, not conn.SetDeadline: the connection is
// shared with the reader's indefinite wait for the next notification.
func (c *Client) tryExec(cmd string, parse func(*bufio.Reader) error) error {
	if c.getConn() == nil {
		if err := c.connect(); err != nil {
			return err
		}
	}
	if err := c.write(cmd + "\n"); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- parse(bufio.NewReader(&chanReader{lines: c.resp})) }()
	select {
	case err := <-done:
		return err
	case <-time.After(c.Timeout):
		c.drop()
		return fmt.Errorf("controller: mgmt command timed out")
	}
}

// Status reads openvpn's own periodic status file instead of querying the
// mgmt socket — polling "status 3" there logs a line per poll. Requires a
// terminating "END" line to succeed; a torn read errors, never partial data.
func (c *Client) Status() ([]VPNClient, error) {
	f, err := os.Open(c.StatusPath)
	if err != nil {
		return nil, fmt.Errorf("controller: status file: %w", err)
	}
	defer f.Close()
	return parseStatusFile(bufio.NewReader(f))
}

// parseStatusFile parses status-version-3 lines up to and including a
// terminating "END" — see Status()'s doc comment for why END is required.
func parseStatusFile(r *bufio.Reader) ([]VPNClient, error) {
	var out []VPNClient
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("controller: status file: no END line (torn read): %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "END":
			return out, nil
		case strings.HasPrefix(line, "CLIENT_LIST\t"):
			f := strings.Split(line, "\t")
			// CLIENT_LIST CN Real Virt Virt6 BRecv BSent Since SinceT User CID PID Cipher
			if len(f) < 12 {
				continue
			}
			vc := VPNClient{
				CN:             f[1],
				RealAddress:    f[2],
				VirtualAddress: f[3],
			}
			vc.BytesRecv, _ = strconv.ParseUint(f[5], 10, 64)
			vc.BytesSent, _ = strconv.ParseUint(f[6], 10, 64)
			if ts, err := strconv.ParseInt(f[8], 10, 64); err == nil {
				vc.ConnectedSince = time.Unix(ts, 0)
			}
			if len(f) >= 13 {
				vc.Cipher = f[12]
			}
			out = append(out, vc)
		}
	}
}

// Kill disconnects all sessions for a CN (mgmt `kill`). cn is rejected if it
// could smuggle extra lines into the newline-delimited mgmt protocol.
func (c *Client) Kill(cn string) error {
	if strings.ContainsAny(cn, "\r\n") {
		return fmt.Errorf("controller: invalid cn %q", cn)
	}
	return c.simple("kill " + cn)
}

func (c *Client) simple(cmd string) error {
	return c.exec(cmd, func(r *bufio.Reader) error {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, ">") {
				continue
			}
			if strings.HasPrefix(line, "SUCCESS") {
				return nil
			}
			if strings.HasPrefix(line, "ERROR") {
				return appErr{fmt.Errorf("controller: %s", line)}
			}
		}
	})
}
