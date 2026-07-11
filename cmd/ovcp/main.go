// ovcp — OpenVPN Control Panel. One static binary.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"os/signal"
	"syscall"

	"rsc.io/qr"

	"github.com/ovcp/ovcp/internal/api"
	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/backup"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/web"
)

var version = "dev"

// logLevel backs the default logger; "ovcp debug on|off" flips it at
// runtime via the control socket, no restart needed.
var logLevel = new(slog.LevelVar)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))
	dataDir := flag.String("data", envOr("OVCP_DATA", "/var/lib/ovcp"), "data directory")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	p := pki.New(filepath.Join(*dataDir, "pki"))
	openStore := func() *store.Store {
		s, err := store.Open(filepath.Join(*dataDir, "ovcp.db"))
		die(err)
		return s
	}

	switch args[0] {
	case "version":
		fmt.Println("ovcp", version)

	case "issue":
		fs := flag.NewFlagSet("issue", flag.ExitOnError)
		cn := fs.String("cn", "", "common name (required)")
		kindS := fs.String("kind", "client", "client|server")
		days := fs.Int("days", 365, "validity (days)")
		out := fs.String("out", "", "write key+cert to files with this prefix (server certs)")
		keyPass := fs.String("key-pass", "", "encrypt private key with this password (client certs)")
		fs.Parse(args[1:])
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		kind := pki.KindClient
		if *kindS == "server" {
			kind = pki.KindServer
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := p.Issue(kind, *cn, *days, pass)
		die(err)
		if *keyPass != "" {
			ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, *keyPass)
			die(err)
		}
		s := openStore()
		defer s.Close()
		die(s.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: *kindS,
			CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter}))
		s.Audit("cli", "issue", fmt.Sprintf("cn=%s kind=%s serial=%s", *cn, *kindS, ic.SerialHex))
		if *out != "" {
			die(os.WriteFile(*out+".crt", ic.CertPEM, 0o644))
			die(os.WriteFile(*out+".key", ic.KeyPEM, 0o600))
			fmt.Println("wrote", *out+".crt", *out+".key")
		} else {
			os.Stdout.Write(ic.CertPEM)
			os.Stdout.Write(ic.KeyPEM)
		}
		fmt.Fprintln(os.Stderr, "serial:", ic.SerialHex)

	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		serial := fs.String("serial", "", "serial (hex, required)")
		fs.Parse(args[1:])
		if *serial == "" {
			die(fmt.Errorf("-serial required"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		s := openStore()
		defer s.Close()
		die(s.Revoke(*serial, time.Now()))
		rev, err := s.RevokedCerts()
		die(err)
		entries := make([]pki.RevokedEntry, len(rev))
		for i, c := range rev {
			entries[i] = pki.RevokedEntry{SerialHex: c.Serial, RevokedAt: *c.RevokedAt}
		}
		die(p.RegenCRL(entries, pass))
		s.Audit("cli", "revoke", "serial="+*serial)
		fmt.Println("revoked; CRL regenerated:", p.CRLPath())

	case "list":
		s := openStore()
		defer s.Close()
		certs, err := s.ListCerts()
		die(err)
		for _, c := range certs {
			status := "valid"
			if c.RevokedAt != nil {
				status = "REVOKED"
			} else if time.Now().After(c.NotAfter) {
				status = "expired"
			}
			fmt.Printf("%-8s %-10s %-24s expires %s  %s\n",
				status, c.Kind, c.CN, c.NotAfter.Format("2006-01-02"), c.Serial)
		}

	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		cn := fs.String("cn", "", "client CN (issues fresh cert, required)")
		remote := fs.String("remote", "", "server host clients connect to (default: OVCP_SERVER_CN / server cert CN)")
		port := fs.Int("port", 1194, "server port")
		proto := fs.String("proto", "udp", "udp|tcp")
		serverCN := fs.String("server-cn", "", "verify-x509-name value")
		keyPass := fs.String("key-pass", "", "encrypt embedded private key with this password")
		fs.Parse(args[1:])
		if *remote == "" {
			*remote = adminCertCN(*dataDir)
		}
		if *serverCN == "" {
			*serverCN = adminCertCN(*dataDir)
		}
		if *cn == "" || *remote == "" {
			die(fmt.Errorf("-cn required; -remote required (no server CN found)"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := p.Issue(pki.KindClient, *cn, 365, pass)
		die(err)
		if *keyPass != "" {
			ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, *keyPass)
			die(err)
		}
		s := openStore()
		defer s.Close()
		die(s.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: "client",
			CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter}))
		s.Audit("cli", "issue", "cn="+*cn+" (export)")
		caPEM, err := p.CACertPEM()
		die(err)
		tc, err := loadOrCreateTLSCrypt(filepath.Join(*dataDir, "pki", "tls-crypt.key"))
		die(err)
		bundle, err := pki.RenderOVPN(pki.BundleParams{
			Remote: *remote, Port: *port, Proto: *proto, ServerCN: *serverCN,
			CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
			TLSCrypt: tc, Cipher: "AES-256-GCM",
		})
		die(err)
		os.Stdout.Write(bundle)

	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		caCN := fs.String("ca-cn", "OVCP CA", "CA common name")
		serverCN := fs.String("server-cn", "", "server cert CN / public hostname (required)")
		years := fs.Int("ca-years", 10, "CA validity")
		days := fs.Int("server-days", 825, "server cert validity (days)")
		admin := fs.String("admin", "admin", "initial admin username ('' to skip)")
		sock := fs.String("sock", envOr("OVCP_MGMT_SOCK", "/run/ovcp/mgmt.sock"), "mgmt socket")
		fs.Parse(args[1:])
		if *serverCN == "" {
			die(fmt.Errorf("-server-cn required (public hostname clients connect to)"))
		}
		pp := dataPaths(*dataDir)
		s := openStore()
		defer s.Close()

		// 1) CA
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", true)
		switch err := p.InitCA(*caCN, *years, pass); err {
		case nil:
			s.Audit("system", "ca_init", "cn="+*caCN)
			fmt.Println("[1/5] CA initialized:", pp.CACert)
		case pki.ErrCAExists:
			die2(p.CheckPassphrase(pass), "existing CA")
			fmt.Println("[1/5] CA exists, passphrase ok")
		default:
			die(err)
		}

		// 2) server certificate
		if _, err := os.Stat(pp.ServerCert); err == nil {
			fmt.Println("[2/5] server cert exists:", pp.ServerCert)
		} else {
			ic, err := p.Issue(pki.KindServer, *serverCN, *days, pass)
			die(err)
			die(writeServerCert(pp, s, ic))
			s.Audit("system", "issue", "cn="+*serverCN+" kind=server (init)")
			fmt.Println("[2/5] server cert issued:", pp.ServerCert)
		}

		// 3) tls-crypt
		_, err := loadOrCreateTLSCrypt(pp.TLSCrypt)
		die(err)
		fmt.Println("[3/5] tls-crypt key:", pp.TLSCrypt)

		// 4) server.conf from defaults
		cfg := ovpnconf.Default()
		fillPaths(&cfg, *dataDir, *sock)
		raw, _ := json.Marshal(cfg)
		die(s.SetSetting("server_config", string(raw)))
		die(cfg.WriteAtomic(pp.ServerConf))
		fmt.Println("[4/5] server config:", pp.ServerConf)

		// 5) admin user
		if *admin != "" {
			if _, err := s.GetUser(*admin); err == nil {
				fmt.Println("[5/5] admin user exists:", *admin)
			} else {
				fmt.Fprintf(os.Stderr, "create admin user %q\n", *admin)
				pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
				h, err := auth.HashPassword(pw)
				die(err)
				_, err = s.AddUser(*admin, h, "admin")
				die(err)
				s.Audit("system", "user_add", "name="+*admin+" role=admin (init)")
				fmt.Println("[5/5] admin user created:", *admin)
			}
		} else {
			fmt.Println("[5/5] admin user skipped")
		}
		fmt.Println("\ndone. start the server:  ovcp serve")
		fmt.Printf("admin UI:                https://%s\n", envOr("OVCP_LISTEN", "127.0.0.1:8443"))

	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		listen := fs.String("listen", envOr("OVCP_LISTEN", "127.0.0.1:8443"), "admin UI listen addr(s), comma-separated")
		sock := fs.String("sock", envOr("OVCP_MGMT_SOCK", "/run/ovcp/mgmt.sock"), "mgmt socket")
		fs.Parse(args[1:])
		runServe(*dataDir, *listen, *sock, p)

	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		sock := fs.String("sock", envOr("OVCP_MGMT_SOCK", "/run/ovcp/mgmt.sock"), "mgmt socket")
		ctrl := fs.String("ctrl", ctrlSock(), "serve control socket")
		fs.Parse(args[1:])
		// process line first (from serve); if serve/openvpn is down, there
		// are no clients to list, so stop here.
		r, err := controller.Control(*ctrl, "status")
		if err != nil {
			fmt.Println("OpenVPN: unknown —", err)
			return
		}
		if r.Pid == 0 {
			fmt.Println("OpenVPN: stopped")
			return
		}
		fmt.Printf("OpenVPN: running (pid %d)\n", r.Pid)
		cl, err := controller.NewClient(*sock).Status()
		if err != nil {
			fmt.Println("Clients: unavailable —", err)
			return
		}
		fmt.Printf("Clients: %d connected\n", len(cl))
		for _, c := range cl {
			fmt.Printf("  %-20s %-22s %-12s rx %d tx %d since %s\n",
				c.CN, c.RealAddress, c.VirtualAddress, c.BytesRecv, c.BytesSent,
				c.ConnectedSince.Format(time.RFC3339))
		}

	case "kill":
		fs := flag.NewFlagSet("kill", flag.ExitOnError)
		sock := fs.String("sock", envOr("OVCP_MGMT_SOCK", "/run/ovcp/mgmt.sock"), "mgmt socket")
		cn := fs.String("cn", "", "client CN (required)")
		fs.Parse(args[1:])
		if *cn == "" {
			die(fmt.Errorf("-cn required"))
		}
		die(controller.NewClient(*sock).Kill(*cn))
		s := openStore()
		defer s.Close()
		s.Audit("cli", "kill", "cn="+*cn)
		fmt.Println("killed", *cn)

	case "vpn":
		fs := flag.NewFlagSet("vpn", flag.ExitOnError)
		ctrl := fs.String("ctrl", ctrlSock(), "serve control socket")
		fs.Parse(args[1:])
		op := fs.Arg(0)
		switch op {
		case "start", "stop", "restart", "reconnect", "status":
		default:
			die(fmt.Errorf("usage: ovcp vpn start|stop|restart|reconnect|status"))
		}
		r, err := controller.Control(*ctrl, op)
		die(err)
		if op != "status" { // status is read-only, don't audit
			s := openStore()
			s.Audit("cli", "vpn_"+op, fmt.Sprintf("pid=%d", r.Pid))
			s.Close()
		}
		switch {
		case op == "status" && r.Pid == 0:
			fmt.Println("vpn stopped")
		case op == "status":
			fmt.Printf("vpn running (pid %d)\n", r.Pid)
		case op == "start" && !r.Changed:
			fmt.Printf("vpn already started (pid %d)\n", r.Pid)
		case op == "start":
			fmt.Printf("vpn started (pid %d)\n", r.Pid)
		case op == "stop" && !r.Changed:
			fmt.Println("vpn already stopped")
		case op == "stop":
			fmt.Println("vpn stopped")
		case op == "restart":
			fmt.Printf("vpn restarted (pid %d)\n", r.Pid)
		case op == "reconnect":
			fmt.Printf("vpn reconnect sent (pid %d)\n", r.Pid)
		}

	case "renew-server":
		fs := flag.NewFlagSet("renew-server", flag.ExitOnError)
		days := fs.Int("days", 825, "validity (days)")
		serverCNFlag := fs.String("server-cn", "", "server CN (default: current server cert's CN / OVCP_SERVER_CN)")
		fs.Parse(args[1:])
		serverCN := *serverCNFlag
		if serverCN == "" {
			serverCN = adminCertCN(*dataDir)
		}
		if serverCN == "" {
			die(fmt.Errorf("no server certificate found; pass -server-cn (e.g. right after a backup restore) or run ovcp init first"))
		}
		pass := readSecret("CA passphrase", "OVCP_CA_PASSPHRASE", false)
		ic, err := p.Issue(pki.KindServer, serverCN, *days, pass)
		die(err)
		s := openStore()
		defer s.Close()
		die(writeServerCert(dataPaths(*dataDir), s, ic))
		s.Audit("cli", "renew_server", "cn="+serverCN+" serial="+ic.SerialHex)
		fmt.Println("server cert renewed:", ic.SerialHex)
		fmt.Println("run `ovcp vpn restart` to apply")

	case "rotate-ca":
		oldPass := readSecret("Current CA passphrase", "OVCP_CA_PASSPHRASE", false)
		newPass := readSecret("New CA passphrase", "OVCP_CA_NEW_PASSPHRASE", true)
		die(p.Rotate(oldPass, newPass))
		s := openStore()
		defer s.Close()
		s.Audit("cli", "ca_rotate", "")
		fmt.Println("CA passphrase rotated")

	case "backup":
		if len(args) < 2 {
			die(fmt.Errorf("usage: ovcp backup create [-out FILE] | ovcp backup restore [-force] FILE"))
		}
		switch args[1] {
		case "create":
			fs := flag.NewFlagSet("backup create", flag.ExitOnError)
			out := fs.String("out", "", "output file (default: ovcp-backup-<timestamp>.ovcpbak)")
			fs.Parse(args[2:])
			if *out == "" {
				*out = "ovcp-backup-" + time.Now().Format("20060102-150405") + ".ovcpbak"
			}
			pass := readSecret("Backup passphrase", "OVCP_BACKUP_PASSPHRASE", true)
			s := openStore()
			defer s.Close()
			f, err := os.Create(*out)
			die(err)
			defer f.Close()
			die(backup.Create(*dataDir, s, f, pass))
			s.Audit("cli", "backup_create", "file="+*out)
			fmt.Println("backup written:", *out)
			fmt.Println("keep the passphrase safe: it cannot be recovered, and the archive is unreadable without it")

		case "restore":
			fs := flag.NewFlagSet("backup restore", flag.ExitOnError)
			force := fs.Bool("force", false, "overwrite an already-initialized data directory")
			fs.Parse(args[2:])
			file := fs.Arg(0)
			if file == "" {
				die(fmt.Errorf("usage: ovcp backup restore [-force] FILE"))
			}
			pass := readSecret("Backup passphrase", "OVCP_BACKUP_PASSPHRASE", false)
			f, err := os.Open(file)
			die(err)
			defer f.Close()
			die(backup.Restore(*dataDir, f, pass, *force))
			fmt.Println("[1/2] restored CA, CRL, tls-crypt key, config, and database into", *dataDir)
			fmt.Println("[2/2] next: OVCP_SERVER_CN=<host> ovcp renew-server   (issues the openvpn server cert)")
			fmt.Println("      then: ovcp vpn start")

		default:
			die(fmt.Errorf("unknown: backup %s", args[1]))
		}

	case "debug":
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		ctrl := fs.String("ctrl", ctrlSock(), "serve control socket")
		fs.Parse(args[1:])
		op := fs.Arg(0)
		if op != "on" && op != "off" {
			die(fmt.Errorf("usage: ovcp debug on|off"))
		}
		_, err := controller.Control(*ctrl, "debug "+op)
		die(err)
		fmt.Println("debug logging", op)

	case "user":
		if len(args) < 2 {
			die(fmt.Errorf("user add|list|del|disable|enable|passwd|totp [-off]"))
		}
		s := openStore()
		defer s.Close()
		switch args[1] {
		case "add":
			fs := flag.NewFlagSet("user add", flag.ExitOnError)
			name := fs.String("name", "", "username (required)")
			role := fs.String("role", "operator", "admin|operator|readonly")
			fs.Parse(args[2:])
			if *name == "" || !auth.ValidRole(*role) {
				die(fmt.Errorf("-name required; role admin|operator|readonly"))
			}
			pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
			h, err := auth.HashPassword(pw)
			die(err)
			_, err = s.AddUser(*name, h, *role)
			die(err)
			s.Audit("cli", "user_add", "name="+*name+" role="+*role)
			fmt.Println("user added:", *name, "("+*role+")")
		case "list":
			users, err := s.ListUsers()
			die(err)
			for _, u := range users {
				st := "enabled"
				if u.Disabled {
					st = "DISABLED"
				}
				tf := "-"
				if u.TOTPSecret != "" {
					tf = "2fa"
				}
				fmt.Printf("%-20s %-9s %-8s %s\n", u.Username, u.Role, st, tf)
			}
		case "del":
			fs := flag.NewFlagSet("user del", flag.ExitOnError)
			name := fs.String("name", "", "username")
			fs.Parse(args[2:])
			die(s.DeleteUser(*name))
			s.Audit("cli", "user_del", "name="+*name)
			fmt.Println("deleted:", *name)
		case "disable", "enable":
			fs := flag.NewFlagSet("user "+args[1], flag.ExitOnError)
			name := fs.String("name", "", "username")
			fs.Parse(args[2:])
			die(s.SetUserDisabled(*name, args[1] == "disable"))
			s.Audit("cli", "user_"+args[1], "name="+*name)
			fmt.Println(args[1]+"d:", *name)
		case "passwd":
			fs := flag.NewFlagSet("user passwd", flag.ExitOnError)
			name := fs.String("name", "", "username")
			fs.Parse(args[2:])
			pw := string(readSecret("Password", "OVCP_USER_PASSWORD", true))
			h, err := auth.HashPassword(pw)
			die(err)
			die(s.SetUserPassword(*name, h))
			s.Audit("cli", "user_passwd", "name="+*name)
			fmt.Println("password updated:", *name)
		case "totp":
			fs := flag.NewFlagSet("user totp", flag.ExitOnError)
			name := fs.String("name", "", "username")
			off := fs.Bool("off", false, "disable 2FA")
			fs.Parse(args[2:])
			if *off {
				die(s.SetUserTOTP(*name, ""))
				s.Audit("cli", "user_totp_off", "name="+*name)
				fmt.Println("2FA disabled:", *name)
				break
			}
			sec, err := auth.TOTPGenerateSecret()
			die(err)
			die(s.SetUserTOTP(*name, sec))
			s.Audit("cli", "user_totp_enroll", "name="+*name)
			url := auth.TOTPProvisioningURL(sec, *name)
			printQR(url)
			fmt.Println("scan with your authenticator, or enter manually:")
			fmt.Println("  secret:", sec)
			fmt.Println("  url:   ", url)
		default:
			die(fmt.Errorf("unknown: user %s", args[1]))
		}

	case "audit":
		s := openStore()
		defer s.Close()
		tail, err := s.AuditTail(50)
		die(err)
		for i := len(tail) - 1; i >= 0; i-- {
			e := tail[i]
			fmt.Printf("%s %-12s %-16s %s\n", e.TS.Format(time.RFC3339), e.Actor, e.Action, e.Detail)
		}

	default:
		usage()
	}
}

func runServe(dataDir, listen, sock string, p *pki.PKI) {
	// tee ovcp's own log to a file (alongside stderr/journal) so the UI can
	// tail it; unbounded growth, same as openvpn.log — no rotation here either.
	if lf, err := os.OpenFile(filepath.Join(dataDir, "ovcp.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, lf), &slog.HandlerOptions{Level: logLevel})))
	}
	if os.Geteuid() != 0 {
		slog.Warn("not root; ovcp owns the PKI and starts openvpn, both need root")
	}
	s, err := store.Open(filepath.Join(dataDir, "ovcp.db"))
	die(err)
	defer s.Close()

	sup := newSupervisor(dataDir)
	pp := dataPaths(dataDir)
	srv := &api.Server{
		Store: s, Auth: auth.NewService(s), PKI: p,
		Mgmt:       controller.NewClient(sock),
		VPN:        sup,
		DataDir:    dataDir,
		ConfigPath: pp.ServerConf,
		TLSCrypt:   pp.TLSCrypt,
		ServerCert: pp.ServerCert,
		ServerKey:  pp.ServerKey,
		UI:         web.Dist(),
		DebugLevel: logLevel,
	}
	srv.DefaultRemote = adminCertCN(dataDir)

	die(preflight(dataDir))
	// render server.conf from persisted settings (paths are controller-owned)
	cfg := srv.LoadConfig()
	fillPaths(&cfg, dataDir, sock)
	raw, _ := json.Marshal(cfg)
	die(s.SetSetting("server_config", string(raw)))
	die(cfg.WriteAtomic(srv.ConfigPath))

	crt, key, err := api.EnsureAdminTLS(filepath.Join(dataDir, "admin-tls"), adminCertCN(dataDir))
	die(err)
	hs := &http.Server{Handler: srv.Handler()}
	// IP_FREEBIND lets us bind the VPN-side address (e.g. 10.8.0.1) before
	// tun0 exists — the kernel already solves this, no retry loop needed.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, unix.IP_FREEBIND, 1)
		})
	}}
	for _, addr := range strings.Split(listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		die(err)
		go func(a string, l net.Listener) {
			if err := hs.ServeTLS(l, crt, key); err != http.ErrServerClosed {
				die(err)
			}
		}(addr, ln)
	}

	// bring the worker up as a reaped foreground child, and expose the
	// control socket so `ovcp vpn <op>` can drive it while we run.
	ctl, err := controller.ServeControl(ctrlSock(), sup, logLevel)
	die(err)
	defer ctl.Close()
	if err := sup.Start(); err != nil {
		slog.Warn("openvpn start", "err", err)
	}
	slog.Info("ovcp started", "version", version, "listen", listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctl.Close()
	if err := sup.Stop(); err != nil {
		slog.Warn("openvpn stop", "err", err)
	}
	hs.Close()
}

// ctrlSock is the serve control socket path (CLI ↔ serve for vpn ops).
func ctrlSock() string {
	return envOr("OVCP_CTRL_SOCK", "/run/ovcp/control.sock")
}

// newSupervisor wires the single openvpn worker controller from data paths.
func newSupervisor(dataDir string) *controller.Supervisor {
	return &controller.Supervisor{
		ConfigPath: dataPaths(dataDir).ServerConf,
		LogPath:    filepath.Join(dataDir, "openvpn.log"),
	}
}

type paths struct {
	PKIDir, CACert, ServerCert, ServerKey, CRL, TLSCrypt, ServerConf, DB string
}

func dataPaths(dataDir string) paths {
	pd := filepath.Join(dataDir, "pki")
	return paths{
		PKIDir: pd,
		CACert: filepath.Join(pd, "ca.crt"), ServerCert: filepath.Join(pd, "server.crt"),
		ServerKey: filepath.Join(pd, "server.key"), CRL: filepath.Join(pd, "crl.pem"),
		TLSCrypt:   filepath.Join(pd, "tls-crypt.key"),
		ServerConf: filepath.Join(dataDir, "server.conf"),
		DB:         filepath.Join(dataDir, "ovcp.db"),
	}
}

// writeServerCert persists a freshly issued server cert+key to the paths
// `serve` reads and records it in the store. Shared by init (first issue)
// and renew-server (reissue in place); takes effect on the next `vpn restart`.
func writeServerCert(pp paths, s *store.Store, ic *pki.IssuedCert) error {
	if err := os.WriteFile(pp.ServerCert, ic.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(pp.ServerKey, ic.KeyPEM, 0o600); err != nil {
		return err
	}
	return s.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: "server",
		CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter})
}

// fillPaths sets the server-owned path fields on a config.
func fillPaths(cfg *ovpnconf.Config, dataDir, sock string) {
	pp := dataPaths(dataDir)
	cfg.CACert, cfg.ServerCert, cfg.ServerKey = pp.CACert, pp.ServerCert, pp.ServerKey
	cfg.CRL, cfg.TLSCrypt = pp.CRL, pp.TLSCrypt
	cfg.MgmtSocket = sock
	cfg.StatusLog = filepath.Join(dataDir, "status.log")
}

// preflight verifies init artifacts exist, with an actionable error.
func preflight(dataDir string) error {
	pp := dataPaths(dataDir)
	var missing []string
	for _, f := range []string{pp.CACert, pp.ServerCert, pp.ServerKey, pp.TLSCrypt} {
		if _, err := os.Stat(f); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not initialized, missing:\n  %s\nrun: ovcp init -server-cn <public-hostname>",
			strings.Join(missing, "\n  "))
	}
	return nil
}

// adminCertCN: OVCP_SERVER_CN env, else the VPN server cert's CN.
func adminCertCN(dataDir string) string {
	if v := os.Getenv("OVCP_SERVER_CN"); v != "" {
		return v
	}
	if data, err := os.ReadFile(dataPaths(dataDir).ServerCert); err == nil {
		if c, err := parseFirstCert(data); err == nil {
			return c.Subject.CommonName
		}
	}
	return ""
}

func parseFirstCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadOrCreateTLSCrypt(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	}
	k, err := pki.GenTLSCryptKey()
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, k, 0o600)
}

// readSecret prompts for a secret (env override for automation).
func readSecret(label, env string, confirm bool) []byte {
	if v := os.Getenv(env); v != "" {
		return []byte(v)
	}
	prompt := func(p string) []byte {
		fmt.Fprint(os.Stderr, p+": ")
		v, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		die(err)
		return v
	}
	v := prompt(label)
	if confirm && string(v) != string(prompt("Confirm")) {
		die(fmt.Errorf("mismatch"))
	}
	if len(v) < 8 {
		die(fmt.Errorf("%s too short (min 8)", label))
	}
	return v
}

// printQR renders a QR code as terminal background-color blocks (the one
// thing qrterminal added over rsc.io/qr itself — not worth a dependency).
func printQR(text string) {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return
	}
	const black, white = "\033[40m  \033[0m", "\033[47m  \033[0m"
	fmt.Println(strings.Repeat(white, code.Size+2))
	for y := 0; y <= code.Size; y++ {
		fmt.Print(white)
		for x := 0; x <= code.Size; x++ {
			if code.Black(x, y) {
				fmt.Print(black)
			} else {
				fmt.Print(white)
			}
		}
		fmt.Println()
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func die2(err error, ctx string) {
	if err != nil {
		die(fmt.Errorf("%s: %w", ctx, err))
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `ovcp <command>
  init      -server-cn HOST [-admin NAME]   one-shot setup: CA, server cert,
                                        tls-crypt, config, admin user
  issue     -cn NAME [-kind client|server] [-days N] [-out PREFIX] [-key-pass PW]
  revoke    -serial HEX                revoke + regenerate CRL
  rotate-ca                            re-encrypt the CA key under a new passphrase
  renew-server [-days N] [-server-cn CN]   reissue the openvpn server cert (needs vpn restart)
  backup    create [-out FILE]         encrypted export: CA, CRL, tls-crypt, config, database
  backup    restore [-force] FILE      import into a fresh (or -force) data dir; then renew-server
  list                                 list certificates
  export    -cn NAME [-remote HOST] [-port N] [-proto udp|tcp] [-server-cn CN] [-key-pass PW]
  status                               VPN process + connected clients
  kill      -cn NAME [-sock PATH]      disconnect client
  vpn       start|stop|restart|reconnect|status   manage/inspect the openvpn worker
  debug     on|off                     toggle verbose logging on a running serve (no restart)
  user      add|list|del|disable|enable|passwd|totp[-off]
  audit                                last 50 audit entries
  serve     [-listen ADDR] [-sock PATH]   run admin UI + API
  version`)
	os.Exit(2)
}
