package main

// upstream_test.go: local, offline, end-to-end coverage of every upstream
// mode — the real ovcp binary (serve + CLI) plus real openvpn client(s),
// real nft, ovcp's real per-CN rule installation reacting to OpenVPN's own
// ifconfig-pool — with zero real upstreams (no Tor, no second interface,
// no remote host, no root). Backends are tiny local stand-ins (below); the
// network is a rootless nested set of Linux network namespaces (below too).
//
// Every "does traffic reach the right place" assertion dials the target
// through the real, currently-connected openvpn client and reads back the
// backend's own bind address — the same proof a manual live test session
// against a real box used (a real second interface's own distinct exit
// IP), just against local, deterministic backends instead of Tor/a second
// host.
//
// Needs on PATH: unshare, nsenter, ip, nft, openvpn (in addition to what
// main_test.go already needs). No PATH is set or guessed here — whatever
// the invoking shell provides is what's used; skips cleanly if any of the
// above aren't found. On distros where /usr/sbin isn't on a normal user's
// PATH by default, export it yourself before running this suite.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- rootless nested-namespace harness ----
//
// One outer `unshare --user --net --map-root-user` holder (no real root:
// the mapped "root" only has capabilities scoped to this new namespace),
// with every namespace under test (clients, backends) as its --net-only
// children. Moving a veth end into another namespace needs both ends
// under the same owning user namespace, which is exactly what nesting
// --net-only children under one --user holder gives; two separate --user
// unshares are sibling, unrelated user namespaces and moving a device
// between them fails.

type netNS struct {
	prefix []string
	pid    string
}

func (ns netNS) cmd(name string, args ...string) *exec.Cmd {
	full := append(append([]string{}, ns.prefix...), name)
	return exec.Command(full[0], append(full[1:], args...)...)
}

func (ns netNS) run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := ns.cmd(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v in ns: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// requireNetNS returns the outer, rootless namespace everything else
// nests under — skips cleanly (never needs real root) if unshare/nsenter/
// ip/nft/openvpn aren't available.
func requireNetNS(t *testing.T) netNS {
	t.Helper()
	for _, bin := range []string{"unshare", "nsenter", "ip", "nft", "openvpn"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	holder := exec.Command("unshare", "--user", "--net", "--map-root-user", "--", "sleep", "3600")
	if err := holder.Start(); err != nil {
		t.Skipf("rootless netns unavailable (unshare): %v", err)
	}
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	outer := netNS{
		prefix: []string{"nsenter", "--target", strconv.Itoa(holder.Process.Pid), "--net", "--user", "--preserve-credentials", "--"},
		pid:    strconv.Itoa(holder.Process.Pid),
	}
	// holder needs a moment to finish unshare's own setup before nsenter
	// can reassociate into it — poll instead of a fixed sleep.
	if !retry(20, 50*time.Millisecond, func() error {
		out, err := outer.cmd("ip", "link", "set", "lo", "up").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w\n%s", err, out)
		}
		return nil
	}) {
		t.Skip("rootless netns: lo up never succeeded (unprivileged user namespaces may be disabled on this host)")
	}
	if out, err := outer.cmd("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("rootless netns: nft probe failed: %v\n%s", err, out)
	}
	return outer
}

// child creates a --net-only namespace nested inside outer.
func (outer netNS) child(t *testing.T) netNS {
	t.Helper()
	holder := outer.cmd("unshare", "--net", "--", "sleep", "3600")
	if err := holder.Start(); err != nil {
		t.Fatalf("inner netns: %v", err)
	}
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	pid := strconv.Itoa(holder.Process.Pid)
	ns := netNS{
		prefix: append(append([]string{}, outer.prefix...), "nsenter", "--target", pid, "--net", "--"),
		pid:    pid,
	}
	if !retry(20, 50*time.Millisecond, func() error {
		out, err := ns.cmd("ip", "link", "set", "lo", "up").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w\n%s", err, out)
		}
		return nil
	}) {
		t.Fatal("inner netns: lo up never succeeded")
	}
	return ns
}

// veth wires a<->b with a fresh point-to-point link — aIface/bIface must
// be unique per outer, aAddr/bAddr a /30 (or wider) CIDR each.
func (outer netNS) veth(t *testing.T, a netNS, aIface, aAddr string, b netNS, bIface, bAddr string) {
	t.Helper()
	outer.run(t, "ip", "link", "add", aIface, "type", "veth", "peer", "name", bIface)
	outer.run(t, "ip", "link", "set", aIface, "netns", a.pid)
	outer.run(t, "ip", "link", "set", bIface, "netns", b.pid)
	a.run(t, "ip", "addr", "add", aAddr, "dev", aIface)
	a.run(t, "ip", "link", "set", aIface, "up")
	b.run(t, "ip", "addr", "add", bAddr, "dev", bIface)
	b.run(t, "ip", "link", "set", bIface, "up")
}

func retry(n int, delay time.Duration, f func() error) bool {
	for range n {
		if f() == nil {
			return true
		}
		time.Sleep(delay)
	}
	return false
}

// ---- tiny local backends, standing in for real upstreams ----
//
// A re-exec'd copy of this same test binary, dispatched from TestMain
// before it's a test binary at all (see main_test.go): "sink" (dumb TCP
// accept, replies with its own bind address — proof of which backend real
// traffic reached), "socks5mock" (minimal RFC1928 no-auth CONNECT ack,
// then sink — a local stand-in for a real SOCKS5 backend like Tor), and
// "dial" (one-shot TCP client reading one line back — this suite's
// stand-in for curl/nc, which shouldn't need to be installed).

const e2eHelperEnv = "OVCP_E2E_HELPER"

func runE2EHelper(mode, addr string) {
	if mode == "dial" {
		timeout := 5 * time.Second
		if v, err := time.ParseDuration(os.Getenv("OVCP_E2E_HELPER_DIALTIMEOUT")); err == nil {
			timeout = v
		}
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dial:", err)
			os.Exit(1)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		fmt.Print(line)
		os.Exit(0)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e helper listen:", err)
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go serveE2EHelper(mode, conn)
	}
}

// serveE2EHelper answers one connection: for socks5mock, does the minimal
// no-auth SOCKS5 CONNECT handshake first (RFC 1928) so ovcp's relay gets a
// real success reply before piping bytes through; either way, the payload
// the far end (the VPN client) actually reads back is this listener's own
// bind address — proof of which backend the traffic really reached.
func serveE2EHelper(mode string, conn net.Conn) {
	defer conn.Close()
	if mode == "socks5mock" {
		buf := make([]byte, 262)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		conn.Write([]byte{0x05, 0x00}) // no-auth selected
		if _, err := conn.Read(buf); err != nil {
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // CONNECT ok
	}
	fmt.Fprintf(conn, "reached %s\n", conn.LocalAddr())
}

// reexecCmd builds a copy of this same test binary, re-exec'd inside ns
// with env appended, as a plain non-test process (see runE2EHelper).
func (ns netNS) reexecCmd(t *testing.T, env ...string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	c := ns.cmd(self, "-test.run=^$")
	c.Env = append(os.Environ(), env...)
	return c
}

// startHelper launches this same test binary, re-exec'd in helper mode,
// inside ns.
func (ns netNS) startHelper(t *testing.T, mode, addr string) {
	t.Helper()
	c := ns.reexecCmd(t, e2eHelperEnv+"="+mode, "OVCP_E2E_HELPER_ADDR="+addr)
	if err := c.Start(); err != nil {
		t.Fatalf("start helper %s at %s: %v", mode, addr, err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
}

// dial re-execs the test binary in "dial" mode inside ns, connects to
// target (waiting up to connTimeout for the TCP handshake), and returns the
// first line it read (or the error).
func (ns netNS) dial(t *testing.T, target string, connTimeout time.Duration) (string, error) {
	t.Helper()
	c := ns.reexecCmd(t, e2eHelperEnv+"=dial", "OVCP_E2E_HELPER_ADDR="+target,
		"OVCP_E2E_HELPER_DIALTIMEOUT="+connTimeout.String())
	out, err := c.CombinedOutput()
	return string(out), err
}

// dialRetry is dial, retried until timeout, 1s per attempt — client-side
// settling (tun recreate, PUSH_REPLY) after a vpn restart can lag what
// waitConnected already sees as "connected" in the status file.
func (ns netNS) dialRetry(t *testing.T, target string, timeout time.Duration) (string, error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got string
	var err error
	for {
		got, err = ns.dial(t, target, time.Second)
		if err == nil || time.Now().After(deadline) {
			return got, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- real ovcp host + real openvpn client(s) ----

const e2ePassphrase = "e2e-test-passphrase-1!"

// e2eHost is one running "ovcp host": the real ovcp binary, both `serve`
// (nsenter'd into outer — every socket/route/nft rule it touches,
// including the SOCKS relay's own listener, is genuinely scoped to
// outer's namespace) and every other CLI call (unix-socket/sqlite only,
// never network-namespace-scoped, so run() drives them directly).
type e2eHost struct {
	t        *testing.T
	outer    netNS
	dataDir  string
	env      []string
	ctrlSock string
}

func newE2EHost(t *testing.T, outer netNS) *e2eHost {
	t.Helper()
	dataDir := t.TempDir()
	// Unix socket paths are capped at ~108 bytes (sun_path) — t.TempDir()
	// nests under the test's own (often long) name, so control/mgmt sockets
	// get a short, separate base dir instead of living under dataDir.
	sockDir, err := os.MkdirTemp("", "ovcp-e2e-sock")
	if err != nil {
		t.Fatalf("MkdirTemp for sockets: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	env := []string{
		"OVCP_DATA=" + dataDir, "OVCP_CA_PASSPHRASE=" + e2ePassphrase,
		"OVCP_CTRL_SOCK=" + sockDir + "/c",
		"OVCP_MGMT_SOCK=" + sockDir + "/m",
		// The rootless netns maps exactly one uid/gid (0, via
		// --map-root-user) with setgroups() left denied (the kernel's own
		// unprivileged-userns restriction) — nobody/nogroup (the real
		// default) can't be dropped to, and neither can any other identity,
		// same-user included. No privilege drop at all, opted out via "".
		"OVCP_OPENVPN_USER=", "OVCP_OPENVPN_GROUP=",
		// DNS isn't exercised by this suite and dnsmasq's pidfile isn't
		// test-scoped (a real, shared system path) — skip starting it
		// rather than risk colliding with a real dnsmasq elsewhere.
		"OVCP_DNSMASQ_AUTOSTART=false",
	}
	if r := run(t, env, "init", "-server-cn", "e2e-server", "-admin", ""); r.code != 0 {
		t.Fatalf("init: %s", r.stderr)
	}
	h := &e2eHost{t: t, outer: outer, dataDir: dataDir, env: env, ctrlSock: sockDir + "/c"}
	h.startServe(t)
	return h
}

func (h *e2eHost) startServe(t *testing.T) {
	t.Helper()
	full := append(append([]string{}, h.outer.prefix...), binPath, "-data", h.dataDir, "serve")
	c := exec.Command(full[0], full[1:]...)
	c.Env = append(os.Environ(), h.env...)
	if err := c.Start(); err != nil {
		t.Fatalf("start ovcp serve: %v", err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	if !retry(100, 100*time.Millisecond, func() error {
		r := run(t, h.env, "status")
		if r.code != 0 {
			return fmt.Errorf("not ready: %s", r.stderr)
		}
		return nil
	}) {
		t.Fatal("ovcp serve never became ready")
	}
	// `status` succeeding doesn't guarantee the control socket is listening
	// yet — without this, upstream add/set-default/reconcile (which all
	// need it) can run before it's ready and silently fall back to a
	// same-process, un-namespaced Apply instead of reaching serve at all.
	if !retry(100, 100*time.Millisecond, func() error {
		_, err := os.Stat(h.ctrlSock)
		return err
	}) {
		t.Fatal("ovcp serve's control socket never appeared")
	}
}

// vpnRestart restarts the openvpn worker and waits for it to be back up —
// needed whenever management-client-auth flips (first-ever PerCN
// assignment), same rule `upstream assign`'s own CLI warning documents.
func (h *e2eHost) vpnRestart(t *testing.T) {
	t.Helper()
	if r := run(t, h.env, "vpn", "restart"); r.code != 0 {
		t.Fatalf("vpn restart: %s", r.stderr)
	}
}

// upstreamAdd/setDefault trigger a live re-apply via the control socket
// (applyUpstreamsCLI -> UpstreamReapply -> upstream.Apply) — Apply now
// waits for applyMu rather than giving up if another Apply is mid-run
// (see upstream.go), so a plain, single call here is enough; no retry
// scaffolding needed now that the race it would have been working around
// is fixed at the source.
func (h *e2eHost) upstreamAdd(t *testing.T, args ...string) {
	t.Helper()
	if r := run(t, h.env, append([]string{"upstream", "add"}, args...)...); r.code != 0 {
		t.Fatalf("upstream add %v: %s", args, r.stderr)
	}
}

func (h *e2eHost) setDefault(t *testing.T, id string) {
	t.Helper()
	if r := run(t, h.env, "upstream", "set-default", "-id", id); r.code != 0 {
		t.Fatalf("upstream set-default %s: %s", id, r.stderr)
	}
}

// assign runs `upstream assign`. The very first assignment ever (no CN
// previously overridden) flips management-client-auth, which needs a full
// `vpn restart` to take effect — that drops every connected client's
// session, so callers must wait for whichever CNs matter to them to
// reconnect afterward (see waitConnected).
func (h *e2eHost) assign(t *testing.T, cn, id string) {
	t.Helper()
	before := h.perCNActive(t)
	if r := run(t, h.env, "upstream", "assign", "-cn", cn, "-id", id); r.code != 0 {
		t.Fatalf("upstream assign %s -> %s: %s", cn, id, r.stderr)
	}
	if !before {
		h.vpnRestart(t)
	}
}

func (h *e2eHost) perCNActive(t *testing.T) bool {
	t.Helper()
	r := run(t, h.env, "-json", "upstream", "list")
	var out struct{ PerCN map[string]string }
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &out) != nil {
		return false
	}
	return len(out.PerCN) > 0
}

// newBackend wires a fresh child namespace to h.outer over its own /30 and
// starts mode ("sink" or "socks5mock") there — the local stand-in for a
// real egress target (a real second interface, or a SOCKS5 backend like
// Tor). Returns the interface name on h.outer's side (what -iface points at).
func (h *e2eHost) newBackend(t *testing.T, suffix, mode, hostIP, dstIP string, port int) (hostIface string) {
	t.Helper()
	dst := h.outer.child(t)
	hostIface, dstIface := "veh"+suffix, "ved"+suffix
	h.outer.veth(t, h.outer, hostIface, hostIP+"/30", dst, dstIface, dstIP+"/30")
	dst.startHelper(t, mode, fmt.Sprintf("%s:%d", dstIP, port))
	return hostIface
}

// newClient issues cn a real cert, wires a veth to h.outer, exports a real
// .ovpn (the same `certificate issue -export` a real admin uses), and
// starts a real openvpn client against it inside its own netns.
func (h *e2eHost) newClient(t *testing.T, cn, suffix, hostIP, clientIP string) netNS {
	t.Helper()
	ns := h.outer.child(t)
	hostIface, clientIface := "veh"+suffix, "vec"+suffix
	h.outer.veth(t, h.outer, hostIface, hostIP+"/30", ns, clientIface, clientIP+"/30")

	outPrefix := t.TempDir() + "/" + cn
	if r := run(t, h.env, "certificate", "issue", "-cn", cn, "-export", "-remote", hostIP, "-out", outPrefix); r.code != 0 {
		t.Fatalf("issue+export %s: %s", cn, r.stderr)
	}

	full := append(append([]string{}, ns.prefix...), "openvpn", "--config", outPrefix+".ovpn")
	c := exec.Command(full[0], full[1:]...)
	if err := c.Start(); err != nil {
		t.Fatalf("start openvpn client %s: %v", cn, err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })

	h.waitConnected(t, cn, 8*time.Second)
	return ns
}

// waitConnected polls `ovcp status` until cn shows up connected — the
// same data a real admin's polling would read, no arbitrary sleep.
func (h *e2eHost) waitConnected(t *testing.T, cn string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r := run(t, h.env, "status")
		if r.code == 0 && strings.Contains(r.stdout, cn) {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("%s never showed up connected within %s", cn, timeout)
}

// ---- the test matrix ----

// TestE2ETransparent: no upstream configured at all — a client's traffic
// must still flow (masqueraded via the host's own path), reaching the
// "normal route" backend.
func TestE2ETransparent(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	h.newBackend(t, "n", "sink", "10.90.1.1", "10.90.1.2", 9000)

	client := h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2")
	got, err := client.dial(t, "10.90.1.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("dial normal-route backend: %v\n%s", err, got)
	}
	if got != "reached 10.90.1.2:9000\n" {
		t.Fatalf("got %q, want the normal-route backend's own address", got)
	}
}

// TestE2EIfaceMode: server-wide default upstream is iface-mode, pointed at
// a local backend standing in for a real second interface — traffic must
// reach that backend specifically, proving real nft mark+route+masquerade
// plumbing, not just that traffic flows at all.
func TestE2EIfaceMode(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	ifaceHost := h.newBackend(t, "i", "sink", "10.90.2.1", "10.90.2.2", 9000)
	h.upstreamAdd(t, "-id", "wan1", "-iface", ifaceHost)
	h.setDefault(t, "wan1")

	client := h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2")
	got, err := client.dial(t, "10.90.2.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("dial iface-mode backend: %v\n%s", err, got)
	}
	if got != "reached 10.90.2.2:9000\n" {
		t.Fatalf("got %q, want the iface-mode backend's own address", got)
	}
}

// TestE2ESocksMode: server-wide default upstream is socks-mode, pointed at
// a local SOCKS5 mock standing in for a real backend like Tor — proves the
// exact bug class found this session (the relay's own listener must
// actually receive nft-redirected traffic, not just look right on paper).
func TestE2ESocksMode(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	outer.startHelper(t, "socks5mock", "127.0.0.1:19050")
	h.upstreamAdd(t, "-id", "tor", "-socks", "socks5://127.0.0.1:19050")
	h.setDefault(t, "tor")

	client := h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2")
	got, err := client.dial(t, "203.0.113.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("dial through socks relay: %v\n%s", err, got)
	}
	if got != "reached 127.0.0.1:19050\n" {
		t.Fatalf("got %q, want the socks5mock backend's own address", got)
	}
}

// TestE2EPerCNOverride: two real, simultaneously-connected clients — one
// overridden to socks-mode, the other left on the server-wide iface-mode
// default. Proves both the routing split and the collision fix (their
// VPN-assigned IPs must differ) at once.
func TestE2EPerCNOverride(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	ifaceHost := h.newBackend(t, "i", "sink", "10.90.2.1", "10.90.2.2", 9000)
	h.upstreamAdd(t, "-id", "wan1", "-iface", ifaceHost)
	h.setDefault(t, "wan1")
	outer.startHelper(t, "socks5mock", "127.0.0.1:19050")
	h.upstreamAdd(t, "-id", "tor", "-socks", "socks5://127.0.0.1:19050")

	alice := h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2")
	bob := h.newClient(t, "bob", "2", "10.90.11.1", "10.90.11.2")
	h.assign(t, "alice", "tor")
	// The first-ever assignment restarts the openvpn worker (see assign's
	// doc comment) — both real client processes reconnect on their own,
	// but the test needs to wait for that before dialing either of them.
	h.waitConnected(t, "alice", 8*time.Second)
	h.waitConnected(t, "bob", 8*time.Second)

	// dialRetry, not dial: right after this restart, openvpn's status file
	// (what waitConnected polls) can report a client connected slightly
	// before that client's own local tun/routes are actually usable — see
	// dialRetry's doc comment. Only this test hits that window (the only
	// one that reconnects already-live clients mid-test).
	aliceGot, err := alice.dialRetry(t, "1.1.1.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("alice dial (expect socks): %v\n%s", err, aliceGot)
	}
	if aliceGot != "reached 127.0.0.1:19050\n" {
		t.Fatalf("alice: got %q, want the socks backend (per-CN override)", aliceGot)
	}
	bobGot, err := bob.dialRetry(t, "10.90.2.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("bob dial (expect iface default): %v\n%s", err, bobGot)
	}
	if bobGot != "reached 10.90.2.2:9000\n" {
		t.Fatalf("bob: got %q, want the iface-mode backend (server default, no override)", bobGot)
	}

	// The actual collision-fix proof: both clients must show up connected
	// with distinct VPN-assigned IPs, not the same one.
	status := run(t, h.env, "status")
	if strings.Count(status.stdout, "alice") == 0 || strings.Count(status.stdout, "bob") == 0 {
		t.Fatalf("both clients should be connected:\n%s", status.stdout)
	}
}

// TestE2EAssignLiveToAlreadyConnectedPlainClient: bob connects with no
// override while per-CN routing is already active for someone else (no
// restart involved for him). Assigning bob his own override afterward must
// reroute his traffic immediately, with no reconnect — the one guarantee
// RewriteConnectedClientRule's Status()-based lookup exists for, and the
// one path no test exercised through a real client before this.
func TestE2EAssignLiveToAlreadyConnectedPlainClient(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	h.newBackend(t, "n", "sink", "10.90.1.1", "10.90.1.2", 9000)
	ifaceHost := h.newBackend(t, "i", "sink", "10.90.2.1", "10.90.2.2", 9000)
	h.upstreamAdd(t, "-id", "wan1", "-iface", ifaceHost)

	h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2") // just needs to exist and hold an override; never dialed
	bob := h.newClient(t, "bob", "2", "10.90.11.1", "10.90.11.2")
	h.assign(t, "alice", "wan1") // first-ever assign: restarts openvpn, both reconnect
	h.waitConnected(t, "alice", 8*time.Second)
	h.waitConnected(t, "bob", 8*time.Second)

	bobGot, err := bob.dialRetry(t, "10.90.1.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("bob dial before assign (expect transparent): %v\n%s", err, bobGot)
	}
	if bobGot != "reached 10.90.1.2:9000\n" {
		t.Fatalf("bob before assign: got %q, want the normal-route backend", bobGot)
	}

	// Second-ever assign: per-CN routing is already active, so this must NOT
	// restart openvpn — bob's session, and his tun/routes, never drop.
	h.assign(t, "bob", "wan1")

	bobGot, err = bob.dial(t, "10.90.2.2:9000", 5*time.Second) // plain dial: no restart, no reconnect window to retry through
	if err != nil {
		t.Fatalf("bob dial after live assign (expect iface override): %v\n%s", err, bobGot)
	}
	if bobGot != "reached 10.90.2.2:9000\n" {
		t.Fatalf("bob after assign: got %q, want the iface backend — live reassignment of an already-connected, previously-plain client failed", bobGot)
	}
}

// TestE2EPerCNOverrideNoDefault: no server-wide default at all — only a
// per-CN override. The overridden client must reach its own upstream,
// while every other client falls through to the same transparent,
// host-routed path TestE2ETransparent proves, not to any upstream.
func TestE2EPerCNOverrideNoDefault(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	h.newBackend(t, "n", "sink", "10.90.1.1", "10.90.1.2", 9000)
	ifaceHost := h.newBackend(t, "i", "sink", "10.90.2.1", "10.90.2.2", 9000)
	h.upstreamAdd(t, "-id", "wan1", "-iface", ifaceHost)

	alice := h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2")
	bob := h.newClient(t, "bob", "2", "10.90.11.1", "10.90.11.2")
	h.assign(t, "alice", "wan1")
	h.waitConnected(t, "alice", 8*time.Second)
	h.waitConnected(t, "bob", 8*time.Second)

	aliceGot, err := alice.dialRetry(t, "10.90.2.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("alice dial (expect iface override): %v\n%s", err, aliceGot)
	}
	if aliceGot != "reached 10.90.2.2:9000\n" {
		t.Fatalf("alice: got %q, want the iface-mode backend (per-CN override)", aliceGot)
	}
	bobGot, err := bob.dialRetry(t, "10.90.1.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("bob dial (expect transparent, no default set): %v\n%s", err, bobGot)
	}
	if bobGot != "reached 10.90.1.2:9000\n" {
		t.Fatalf("bob: got %q, want the normal-route backend (no default, no override)", bobGot)
	}
}

// TestE2EIfaceKillSwitch: the backing interface disappears entirely (see
// routeArgs) while a client is routed through it — must fail closed, never
// leak out via the normal-route path instead.
func TestE2EIfaceKillSwitch(t *testing.T) {
	outer := requireNetNS(t)
	h := newE2EHost(t, outer)
	h.newBackend(t, "n", "sink", "10.90.1.1", "10.90.1.2", 9000)
	ifaceHost := h.newBackend(t, "i", "sink", "10.90.2.1", "10.90.2.2", 9000)
	h.upstreamAdd(t, "-id", "wan1", "-iface", ifaceHost)
	h.setDefault(t, "wan1")

	client := h.newClient(t, "alice", "1", "10.90.10.1", "10.90.10.2")
	got, err := client.dial(t, "10.90.2.2:9000", 5*time.Second)
	if err != nil || got != "reached 10.90.2.2:9000\n" {
		t.Fatalf("sanity check before killing the link failed: %v, %q", err, got)
	}

	// Delete the backing interface outright — kernel-guaranteed to purge
	// routes bound to that ifindex, unlike admin-down alone.
	h.outer.run(t, "ip", "link", "del", ifaceHost)

	if got, err := client.dial(t, "10.90.2.2:9000", 5*time.Second); err == nil {
		t.Fatalf("client must fail to reach the dead upstream's backend, got %q", got)
	}
	if got, err := client.dial(t, "10.90.1.2:9000", 5*time.Second); err == nil {
		t.Fatalf("client must NOT silently leak to the normal-route backend when its upstream is down, got %q", got)
	}
}
