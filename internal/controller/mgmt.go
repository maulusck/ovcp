// Package controller talks to openvpn's management socket over one held
// connection, reconnecting on demand if it drops (e.g. openvpn restarts and
// recreates the socket). Holding the connection avoids a fresh
// connect/disconnect on every status poll, which otherwise spams
// openvpn.log with a MANAGEMENT connect/CMD/disconnect triple every few
// seconds.
package controller

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	SocketPath string
	Timeout    time.Duration // per-op; default 5s

	mu   sync.Mutex // serializes access to conn: the mgmt protocol is one command/response stream, not safe for concurrent use
	conn net.Conn
	r    *bufio.Reader
}

func NewClient(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: 5 * time.Second}
}

type VPNClient struct {
	CN             string
	RealAddress    string
	VirtualAddress string
	BytesRecv      uint64
	BytesSent      uint64
	ConnectedSince time.Time
	ClientID       string
	Cipher         string
}

// connect dials a fresh connection and consumes the greeting banner. Caller
// must hold c.mu and must not already have a live c.conn.
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
	c.conn, c.r = conn, r
	return nil
}

// drop closes and forgets the held connection. Caller must hold c.mu.
func (c *Client) drop() {
	if c.conn != nil {
		c.conn.Close()
		c.conn, c.r = nil, nil
	}
}

// appErr marks a parse failure as an OpenVPN application-level response
// (e.g. an "ERROR: ..." reply) rather than a connection/protocol failure —
// the round trip succeeded, so exec must not drop and reconnect for these.
type appErr struct{ error }

// exec runs cmd on the held connection, reading the response via parse.
// Any connection-level failure (dial, write, or read) drops the connection
// and retries once against a freshly dialed one, so a stale connection
// (e.g. openvpn restarted and recreated the socket) self-heals within the
// same call. An appErr from parse is returned as-is without retrying.
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

func (c *Client) tryExec(cmd string, parse func(*bufio.Reader) error) error {
	if c.conn == nil {
		if err := c.connect(); err != nil {
			return err
		}
	}
	c.conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := c.conn.Write([]byte(cmd + "\n")); err != nil {
		return err
	}
	return parse(c.r)
}

// Status returns currently connected clients (mgmt `status 3`).
func (c *Client) Status() ([]VPNClient, error) {
	var out []VPNClient
	err := c.exec("status 3", func(r *bufio.Reader) error {
		out = nil // discard any partial parse from a failed first attempt
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "END":
				return nil
			case strings.HasPrefix(line, ">"): // async event, ignore
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
					ClientID:       f[10],
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
	})
	return out, err
}

// Kill disconnects all sessions for a CN (mgmt `kill`).
// cn is rejected if it could smuggle extra lines into the management
// protocol (which is newline-delimited and has no other escaping).
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
