package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/backup"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

// handleHealthz is unauthenticated: systemd/container probes have no
// session to offer. A DB ping is the cheapest real signal that serve is
// actually working, not just that the listener is up.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Ping(); err != nil {
		jsonErr(w, 503, "db unreachable")
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password, TOTP string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	token, u, err := s.Auth.Login(in.Username, in.Password, in.TOTP, clientIP(r))
	switch err {
	case nil:
	case auth.ErrTOTPRequired:
		jsonErr(w, 401, "totp required")
		return
	case auth.ErrRateLimited:
		slog.Warn("login rate limited", "user", in.Username, "remote", clientIP(r))
		jsonErr(w, 429, "too many attempts, try again later")
		return
	default:
		slog.Warn("login failed", "user", in.Username, "remote", clientIP(r))
		jsonErr(w, 401, "invalid credentials")
		return
	}
	csrf := randToken()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(auth.SessionTTL.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/",
		Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(auth.SessionTTL.Seconds())})
	jsonOK(w, map[string]string{"username": u.Username, "role": u.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, u *store.User) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Auth.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, map[string]string{"username": u.Username, "role": u.Role})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, u *store.User) {
	clients, err := s.Mgmt.Status()
	if err != nil {
		// VPN down/restarting is a normal state for the panel, not a 500.
		jsonOK(w, map[string]any{"vpn_up": false, "clients": []any{}})
		return
	}
	if clients == nil {
		clients = []controller.VPNClient{}
	}
	jsonOK(w, map[string]any{"vpn_up": true, "clients": clients})
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ CN string }
	if !decode(r, &in) || in.CN == "" {
		jsonErr(w, 400, "cn required")
		return
	}
	if err := s.Mgmt.Kill(in.CN); err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	s.Store.Audit(u.Username, "kill", "cn="+in.CN)
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request, u *store.User) {
	certs, err := s.Store.ListCerts()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	type row struct {
		Serial, CN, Kind string
		IssuedAt         time.Time
		NotAfter         time.Time
		Revoked          bool
	}
	out := []row{}
	for _, c := range certs {
		out = append(out, row{c.Serial, c.CN, c.Kind, c.IssuedAt, c.NotAfter, c.RevokedAt != nil})
	}
	jsonOK(w, out)
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		CN, Passphrase, KeyPassphrase string
		Days                          int
	}
	if !decode(r, &in) || in.CN == "" || in.Passphrase == "" {
		jsonErr(w, 400, "cn and passphrase required")
		return
	}
	if in.Days <= 0 {
		in.Days = 365
	}
	ic, err := s.PKI.Issue(pki.KindClient, in.CN, in.Days, []byte(in.Passphrase))
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	if in.KeyPassphrase != "" {
		if ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, in.KeyPassphrase); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
	}
	s.Store.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: "client",
		CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter})
	s.Store.Audit(u.Username, "issue", "cn="+in.CN+" serial="+ic.SerialHex)
	jsonOK(w, map[string]string{"serial": ic.SerialHex,
		"cert": string(ic.CertPEM), "key": string(ic.KeyPEM)})
}

// handleRenewServer reissues the openvpn server cert in place (same CN, new
// serial), writing to the exact paths `serve` reads. Admin-only: it changes
// the server's own identity and needs a `vpn restart` to take effect.
func (s *Server) handleRenewServer(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		Passphrase string
		Days       int
	}
	if !decode(r, &in) || in.Passphrase == "" {
		jsonErr(w, 400, "passphrase required")
		return
	}
	if in.Days <= 0 {
		in.Days = 825
	}
	if s.DefaultRemote == "" {
		jsonErr(w, 400, "no server CN configured")
		return
	}
	ic, err := s.PKI.Issue(pki.KindServer, s.DefaultRemote, in.Days, []byte(in.Passphrase))
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	if err := os.WriteFile(s.ServerCert, ic.CertPEM, 0o644); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(s.ServerKey, ic.KeyPEM, 0o600); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: "server",
		CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter})
	s.Store.Audit(u.Username, "renew_server", "cn="+s.DefaultRemote+" serial="+ic.SerialHex)
	jsonOK(w, map[string]string{"serial": ic.SerialHex, "notAfter": ic.NotAfter.Format(time.RFC3339)})
}

// handleBackup streams an encrypted backup download; admin-only. No restore endpoint here — `ovcp backup restore` is CLI-only, offline.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Passphrase string }
	if !decode(r, &in) || in.Passphrase == "" {
		jsonErr(w, 400, "passphrase required")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	name := "ovcp-backup-" + time.Now().Format("20060102-150405") + ".ovcpbak"
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	if err := backup.Create(s.DataDir, s.Store, w, []byte(in.Passphrase)); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "backup_create", "")
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Serial, Passphrase string }
	if !decode(r, &in) || in.Serial == "" || in.Passphrase == "" {
		jsonErr(w, 400, "serial and passphrase required")
		return
	}
	if err := s.PKI.CheckPassphrase([]byte(in.Passphrase)); err != nil {
		s.pkiErr(w, err)
		return
	}
	if err := s.Store.Revoke(in.Serial, time.Now()); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	rev, err := s.Store.RevokedCerts()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	entries := make([]pki.RevokedEntry, len(rev))
	for i, c := range rev {
		entries[i] = pki.RevokedEntry{SerialHex: c.Serial, RevokedAt: *c.RevokedAt}
	}
	if err := s.PKI.RegenCRL(entries, []byte(in.Passphrase)); err != nil {
		s.pkiErr(w, err)
		return
	}
	s.Store.Audit(u.Username, "revoke", "serial="+in.Serial)
	jsonOK(w, map[string]bool{"ok": true})
}

// handleExport issues a fresh client cert and streams an inline .ovpn.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		CN, Passphrase, Remote, KeyPassphrase string
		Days                                  int
	}
	if !decode(r, &in) || in.CN == "" || in.Passphrase == "" {
		jsonErr(w, 400, "cn and passphrase required")
		return
	}
	if in.Remote == "" {
		in.Remote = s.DefaultRemote
	}
	if in.Remote == "" {
		jsonErr(w, 400, "remote required (no server CN configured)")
		return
	}
	if in.Days <= 0 {
		in.Days = 365
	}
	ic, err := s.PKI.Issue(pki.KindClient, in.CN, in.Days, []byte(in.Passphrase))
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	if in.KeyPassphrase != "" {
		if ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, in.KeyPassphrase); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
	}
	s.Store.AddCert(store.Cert{Serial: ic.SerialHex, CN: ic.CN, Kind: "client",
		CertPEM: ic.CertPEM, IssuedAt: time.Now(), NotAfter: ic.NotAfter})
	s.Store.Audit(u.Username, "issue", "cn="+in.CN+" (export)")
	caPEM, err := s.PKI.CACertPEM()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	tc, err := os.ReadFile(s.TLSCrypt)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	cfg := s.LoadConfig()
	bundle, err := pki.RenderOVPN(pki.BundleParams{
		Remote: in.Remote, Port: cfg.Port, Proto: cfg.Proto, ServerCN: s.DefaultRemote,
		CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
		TLSCrypt: tc, Cipher: cfg.Cipher,
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.ovpn"`, in.CN))
	w.Write(bundle)
}

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, s.LoadConfig())
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request, u *store.User) {
	cur := s.LoadConfig()
	in := cur
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	// path fields are server-owned; ignore client attempts to change them
	in.CACert, in.ServerCert, in.ServerKey = cur.CACert, cur.ServerCert, cur.ServerKey
	in.CRL, in.TLSCrypt, in.MgmtSocket, in.StatusLog = cur.CRL, cur.TLSCrypt, cur.MgmtSocket, cur.StatusLog
	if err := in.Validate(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := s.saveConfig(in); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := in.WriteAtomic(s.ConfigPath); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "config_change", "")
	jsonOK(w, in)
}

// handleVPN drives the openvpn worker: start|stop|restart|reconnect.
func (s *Server) handleVPN(w http.ResponseWriter, r *http.Request, u *store.User) {
	op := r.PathValue("op")
	var err error
	switch op {
	case "start":
		err = s.VPN.Start()
	case "stop":
		err = s.VPN.Stop()
	case "restart":
		err = s.VPN.Restart()
	case "reconnect":
		err = s.VPN.Reconnect()
	default:
		jsonErr(w, 404, "unknown vpn operation")
		return
	}
	if err != nil {
		jsonErr(w, 502, err.Error())
		return
	}
	s.Store.Audit(u.Username, "vpn_"+op, "")
	jsonOK(w, map[string]any{"op": op, "pid": s.VPN.Pid()})
}

// handleCertDownload returns the (public) certificate PEM for any issued cert.
func (s *Server) handleCertDownload(w http.ResponseWriter, r *http.Request, u *store.User) {
	serial := r.URL.Query().Get("serial")
	c, err := s.Store.GetCert(serial)
	if err != nil {
		jsonErr(w, 404, "certificate not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.crt"`, c.CN))
	w.Write(c.CertPEM)
}

// userSummary strips the auth-relevant-but-not-secret fields off store.User
// (never the password/TOTP secret itself) — shared by the /users list and
// the status export in logs.go, same shape either way.
type userSummary struct {
	Username  string
	Role      string
	Disabled  bool
	TOTP      bool
	CreatedAt time.Time
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request, u *store.User) {
	users, err := s.Store.ListUsers()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	out := []userSummary{}
	for _, x := range users {
		out = append(out, userSummary{x.Username, x.Role, x.Disabled, x.TOTPSecret != "", x.CreatedAt})
	}
	jsonOK(w, out)
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Username, Password, Role string }
	if !decode(r, &in) || in.Username == "" || !auth.ValidRole(in.Role) {
		jsonErr(w, 400, "username and valid role required")
		return
	}
	if len(in.Password) < 8 {
		jsonErr(w, 400, "password too short (min 8)")
		return
	}
	h, err := auth.HashPassword(in.Password)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if _, err := s.Store.AddUser(in.Username, h, in.Role); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.Store.Audit(u.Username, "user_add", "name="+in.Username+" role="+in.Role)
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	name := r.PathValue("name")
	if name == u.Username {
		jsonErr(w, 400, "cannot delete your own account")
		return
	}
	if err := s.Store.DeleteUser(name); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.Store.Audit(u.Username, "user_del", "name="+name)
	jsonOK(w, map[string]bool{"ok": true})
}

// handleUserDisabled toggles enable/disable (`ovcp user disable|enable` as one endpoint).
func (s *Server) handleUserDisabled(w http.ResponseWriter, r *http.Request, u *store.User) {
	name := r.PathValue("name")
	var in struct{ Disabled bool }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	if in.Disabled && name == u.Username {
		jsonErr(w, 400, "cannot disable your own account")
		return
	}
	if err := s.Store.SetUserDisabled(name, in.Disabled); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	action := "user_enable"
	if in.Disabled {
		action = "user_disable"
	}
	s.Store.Audit(u.Username, action, "name="+name)
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request, u *store.User) {
	name := r.PathValue("name")
	var in struct{ Password string }
	if !decode(r, &in) || len(in.Password) < 8 {
		jsonErr(w, 400, "password too short (min 8)")
		return
	}
	h, err := auth.HashPassword(in.Password)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := s.Store.SetUserPassword(name, h); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.Store.Audit(u.Username, "user_passwd", "name="+name)
	jsonOK(w, map[string]bool{"ok": true})
}

// handleUserTOTPEnroll mirrors `ovcp user totp`: generates+stores a fresh
// secret immediately (no separate confirm step) and returns it plus a QR
// code for display.
func (s *Server) handleUserTOTPEnroll(w http.ResponseWriter, r *http.Request, u *store.User) {
	name := r.PathValue("name")
	sec, err := auth.TOTPGenerateSecret()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := s.Store.SetUserTOTP(name, sec); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	url := auth.TOTPProvisioningURL(sec, name, s.DefaultRemote)
	qr, err := qrDataURI(url)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "user_totp_enroll", "name="+name)
	jsonOK(w, map[string]string{"secret": sec, "url": url, "qr": qr})
}

func (s *Server) handleUserTOTPOff(w http.ResponseWriter, r *http.Request, u *store.User) {
	name := r.PathValue("name")
	if err := s.Store.SetUserTOTP(name, ""); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.Store.Audit(u.Username, "user_totp_off", "name="+name)
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleDebugGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, map[string]bool{"debug": s.DebugLevel.Level() <= slog.LevelDebug})
}

// handleDebugSet mirrors `ovcp debug on|off`, flipping the same shared
// *slog.LevelVar the control-socket handler uses — one source of truth.
func (s *Server) handleDebugSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Debug bool }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	action := "off"
	if in.Debug {
		s.DebugLevel.Set(slog.LevelDebug)
		action = "on"
	} else {
		s.DebugLevel.Set(slog.LevelInfo)
	}
	s.Store.Audit(u.Username, "debug_"+action, "")
	jsonOK(w, map[string]bool{"debug": in.Debug})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, u *store.User) {
	tail, err := s.Store.AuditTail(200)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, tail)
}

func (s *Server) pkiErr(w http.ResponseWriter, err error) {
	if err == pki.ErrBadPassphrase {
		jsonErr(w, 403, "wrong CA passphrase")
		return
	}
	jsonErr(w, 500, err.Error())
}
