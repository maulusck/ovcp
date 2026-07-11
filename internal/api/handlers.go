package api

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

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
		jsonErr(w, 429, "too many attempts, try again later")
		return
	default:
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
	tc, _ := os.ReadFile(s.TLSCrypt)
	cfg := s.LoadConfig()
	bundle := pki.RenderOVPN(pki.BundleParams{
		Remote: in.Remote, Port: cfg.Port, Proto: cfg.Proto, ServerCN: s.DefaultRemote,
		CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
		TLSCrypt: tc, Cipher: cfg.Cipher,
	})
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
