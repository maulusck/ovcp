// ovcp — OpenVPN Control Panel. One static binary.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
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

	"github.com/mdp/qrterminal/v3"

	"github.com/ovcp/ovcp/internal/api"
	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/web"
)

var version = "dev"

func main() {
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
		os.Stdout.Write(pki.RenderOVPN(pki.BundleParams{
			Remote: *remote, Port: *port, Proto: *proto, ServerCN: *serverCN,
			CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
			TLSCrypt: tc, Cipher: "AES-256-GCM",
		}))

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
			die(os.WriteFile(pp.ServerCert, ic.CertPEM, 0o644))
			die(os.WriteFile(pp.ServerKey, ic.KeyPEM, 0o600))
			s.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: "server",
				CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter})
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
		fs.Parse(args[1:])
		cl, err := controller.NewClient(*sock).Status()
		die(err)
		for _, c := range cl {
			fmt.Printf("%-20s %-22s %-12s rx %d tx %d since %s\n",
				c.CN, c.RealAddress, c.VirtualAddress, c.BytesRecv, c.BytesSent,
				c.ConnectedSince.Format(time.RFC3339))
		}
		if len(cl) == 0 {
			fmt.Println("no clients connected")
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
		case "start", "stop", "restart", "reconnect":
		default:
			die(fmt.Errorf("usage: ovcp vpn start|stop|restart|reconnect"))
		}
		die(controller.Control(*ctrl, op))
		s := openStore()
		defer s.Close()
		s.Audit("cli", "vpn_"+op, "")
		fmt.Println("vpn", op, "ok")

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
			qrterminal.GenerateWithConfig(url, qrterminal.Config{
				Writer: os.Stdout, Level: qrterminal.L,
				BlackChar: qrterminal.BLACK, WhiteChar: qrterminal.WHITE, QuietZone: 1,
			})
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
	if os.Geteuid() != 0 {
		log.Print("warn: not root; ovcp owns the PKI and starts openvpn, both need root")
	}
	s, err := store.Open(filepath.Join(dataDir, "ovcp.db"))
	die(err)
	defer s.Close()

	sup := newSupervisor(dataDir)
	srv := &api.Server{
		Store: s, Auth: auth.NewService(s), PKI: p,
		Mgmt:       controller.NewClient(sock),
		VPN:        sup,
		ConfigPath: dataPaths(dataDir).ServerConf,
		TLSCrypt:   dataPaths(dataDir).TLSCrypt,
		UI:         web.Dist(),
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
	ctl, err := controller.ServeControl(ctrlSock(), sup)
	die(err)
	defer ctl.Close()
	if err := sup.Start(); err != nil {
		log.Printf("warn: openvpn start: %v", err)
	}
	log.Printf("ovcp %s | admin UI https://{%s}", version, listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctl.Close()
	if err := sup.Stop(); err != nil {
		log.Printf("warn: openvpn stop: %v", err)
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
//
// Note: ovcp runs as root and is the sole owner of the PKI (0600 root:root),
// so it never drops privileges. A future unprivileged IPC worker will be a
// separate process that talks to this one — not a privilege drop here.
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
  list                                 list certificates
  export    -cn NAME [-remote HOST] [-port N] [-proto udp|tcp] [-server-cn CN] [-key-pass PW]
  status    [-sock PATH]               connected clients (mgmt)
  kill      -cn NAME [-sock PATH]      disconnect client
  vpn       start|stop|restart|reconnect   manage the openvpn worker
  user      add|list|del|disable|enable|passwd|totp[-off]
  audit                                last 50 audit entries
  serve     [-listen ADDR] [-sock PATH]   run admin UI + API
  version`)
	os.Exit(2)
}
