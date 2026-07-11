// Package controller talks to openvpn via its management unix socket.
//
// The mgmt interface accepts one client at a time and the socket can
// vanish/reappear whenever the controller restarts openvpn. We therefore
// dial per operation with a short timeout and hold no state. It is used
// only for read/query commands (status, kill); lifecycle signals are sent
// straight to the pid by the Supervisor.
package controller

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	SocketPath string
	Timeout    time.Duration // per-op; default 5s
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

// dial connects and consumes the greeting banner.
func (c *Client) dial() (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("unix", c.SocketPath, c.Timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("controller: mgmt socket unavailable: %w", err)
	}
	conn.SetDeadline(time.Now().Add(c.Timeout))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // >INFO: banner
		conn.Close()
		return nil, nil, err
	}
	return conn, r, nil
}

// Status returns currently connected clients (mgmt `status 3`).
func (c *Client) Status() ([]VPNClient, error) {
	conn, r, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("status 3\n")); err != nil {
		return nil, err
	}
	var out []VPNClient
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "END":
			return out, nil
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
}

// Kill disconnects all sessions for a CN (mgmt `kill`).
func (c *Client) Kill(cn string) error {
	return c.simple("kill " + cn)
}

func (c *Client) simple(cmd string) error {
	conn, r, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return err
	}
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
			return fmt.Errorf("controller: %s", line)
		}
	}
}
