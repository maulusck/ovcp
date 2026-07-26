package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/backup"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/telegram"
)

// handleHealthz is unauthenticated (probes have no session); a DB ping is
// the cheapest real signal serve is actually working, not just listening.
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
	out := map[string]any{
		"username": u.Username, "role": u.Role, "serverCN": s.DefaultRemote,
		"version": s.Version, "buildTarget": s.BuildTarget, "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"openvpnVersion": s.OpenVPNVersion, "openvpnPath": s.OpenVPNPath,
		"dnsmasqVersion": s.DnsmasqVersion, "dnsmasqPath": s.DnsmasqPath,
		"minSecretLen": auth.MinSecretLen, "minSecretClasses": auth.MinSecretClasses,
		// how often openvpn itself rewrites its status file (OVCP_STATUS_INTERVAL)
		// — the UI polls /api/status at the same cadence so it's never asking
		// faster than the data can actually change.
		"statusPollSeconds": s.LoadConfig().EffectiveStatusInterval(),
	}
	// CA info for Settings' renew-CA card; store.Cert{}.Status() is the same
	// classification every other cert-status display uses.
	if ca, err := s.PKI.CACert(); err == nil {
		out["caCN"] = ca.Subject.CommonName
		out["caNotAfter"] = ca.NotAfter
		out["caStatus"] = store.Cert{NotAfter: ca.NotAfter}.Status()
	}
	jsonOK(w, out)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, u *store.User) {
	// ovcp's own uptime is always known here — this handler only runs
	// inside a live serve process.
	out := map[string]any{"ovcp_uptime_seconds": int64(time.Since(controller.ProcessStartedAt).Seconds())}

	clients, err := s.Mgmt.Status()
	// Both signals required: Pid()!=0 catches a stale status file surviving a
	// crash (it wouldn't error — it just wouldn't be rewritten again),
	// err==nil catches a not-yet-running or torn-read status file.
	if up := s.VPN.Pid() != 0 && err == nil; !up {
		// VPN down/restarting is a normal state for the panel, not a 500.
		out["vpn_up"], out["clients"] = false, []any{}
	} else {
		if clients == nil {
			clients = []controller.VPNClient{}
		}
		out["vpn_up"], out["clients"] = true, clients
		out["vpn_uptime_seconds"] = int64(time.Since(s.VPN.StartedAt()).Seconds())
	}

	// s.DNS is nil in a bare/test Server; dnsmasq itself being merely
	// unconfigured still leaves a real Supervisor with Pid()==0 (not running).
	if s.DNS != nil {
		if pid := s.DNS.Pid(); pid != 0 {
			out["dns_up"] = true
			out["dns_uptime_seconds"] = int64(time.Since(s.DNS.StartedAt()).Seconds())
		} else {
			out["dns_up"] = false
		}
	}

	jsonOK(w, out)
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
		Serial, CN, Kind, Status string
		IssuedAt                 time.Time
		NotAfter                 time.Time
		Revoked                  bool
		IncludeDNS               bool
	}
	out := []row{}
	for _, c := range certs {
		out = append(out, row{c.Serial, c.CN, c.Kind, c.Status(), c.IssuedAt, c.NotAfter, c.RevokedAt != nil, c.IncludeDNS})
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
	ic, err := s.issueClientCert(in.CN, in.Passphrase, in.KeyPassphrase, in.Days, false)
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	s.Store.Audit(u.Username, "issue", "cn="+in.CN+" serial="+ic.SerialHex)
	jsonOK(w, map[string]string{"serial": ic.SerialHex,
		"cert": string(ic.CertPEM), "key": string(ic.KeyPEM)})
}

// issueClientCert issues a client cert, optionally password-protecting the
// key, and records it in the store — plain issue (AddCert, errors on an
// existing active cert) or renew (ReplaceCert + CRL regen) depending on
// renew. Shared by handleIssue and handleExport, so a renewal issued
// through export is exactly as atomic as a plain issue: the outgoing cert
// is only ever revoked once the new one already exists, never before.
func (s *Server) issueClientCert(cn, passphrase, keyPassphrase string, days int, renew bool) (*pki.IssuedCert, error) {
	if days <= 0 {
		days = 365
	}
	if renew {
		if err := s.Store.RequireActiveCert(cn, "client"); err != nil {
			return nil, err
		}
	}
	ic, err := s.PKI.Issue(pki.KindClient, cn, days, []byte(passphrase))
	if err != nil {
		return nil, err
	}
	if keyPassphrase != "" {
		if ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, keyPassphrase); err != nil {
			return nil, err
		}
	}
	if !renew {
		if err := s.Store.AddCert(store.CertFrom(ic, "client")); err != nil {
			return nil, err
		}
		return ic, nil
	}
	if err := s.Store.ReplaceCert(store.CertFrom(ic, "client")); err != nil {
		return nil, err
	}
	return ic, s.regenCRL([]byte(passphrase))
}

// regenCRL rebuilds the CRL from the store's full revoked set — the shared
// tail end of anything that revokes a cert, whether directly (handleRevoke)
// or as the side effect of a client renewal (issueClientCert).
func (s *Server) regenCRL(passphrase []byte) error {
	rev, err := s.Store.RevokedCerts()
	if err != nil {
		return err
	}
	entries := make([]pki.RevokedEntry, len(rev))
	for i, c := range rev {
		entries[i] = pki.RevokedEntry{SerialHex: c.Serial, RevokedAt: *c.RevokedAt}
	}
	return s.PKI.RegenCRL(entries, passphrase)
}

// WriteServerCert persists a freshly issued server cert+key to the paths
// `serve` reads and records it in the store — shared by handleRenew below
// and the CLI (init, certificate renew) via cmd/ovcp's writeServerCert.
func (s *Server) WriteServerCert(ic *pki.IssuedCert) error {
	if err := pki.WriteFileAtomic(s.ServerCert, ic.CertPEM, 0o644); err != nil {
		return err
	}
	if err := pki.WriteFileAtomic(s.ServerKey, ic.KeyPEM, 0o600); err != nil {
		return err
	}
	return s.Store.ReplaceCert(store.CertFrom(ic, "server"))
}

// handleRenew reissues the server cert in place (same CN, new serial) at the
// paths `serve` reads. Admin-only; needs a `vpn restart` to take effect.
// Client renewal is a separate path — handleExport's Renew flag.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request, u *store.User) {
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
	// fail fast if there's nothing active to replace; pkiErr maps
	// ErrNoActiveCert to 400, same as export's Renew path.
	if err := s.Store.RequireActiveCert("", "server"); err != nil {
		s.pkiErr(w, err)
		return
	}
	ic, err := s.PKI.Issue(pki.KindServer, s.DefaultRemote, in.Days, []byte(in.Passphrase))
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	if err := s.WriteServerCert(ic); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "renew", "kind=server cn="+s.DefaultRemote+" serial="+ic.SerialHex)
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
	if err := s.regenCRL([]byte(in.Passphrase)); err != nil {
		s.pkiErr(w, err)
		return
	}
	s.Store.Audit(u.Username, "revoke", "serial="+in.Serial)
	jsonOK(w, map[string]bool{"ok": true})
}

// handleExport issues a fresh client cert and streams an inline .ovpn.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		CN, Passphrase, Remote, KeyPassphrase, Extra string
		Days                                         int
		SplitTunnel, Renew                           bool
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
	cfg := s.LoadConfig()
	if in.SplitTunnel && !cfg.CanSplitTunnel() {
		jsonErr(w, 400, ovpnconf.ErrNoRedirect.Error())
		return
	}
	ic, err := s.issueClientCert(in.CN, in.Passphrase, in.KeyPassphrase, in.Days, in.Renew)
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	action := "issue"
	if in.Renew {
		action = "renew"
	}
	s.Store.Audit(u.Username, action, "cn="+in.CN+" (export)")
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
	bundle, err := pki.RenderOVPN(pki.BundleParams{
		Remote: in.Remote, Port: cfg.Port, Proto: cfg.Proto, ServerCN: s.DefaultRemote,
		CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
		TLSCrypt: tc, Cipher: cfg.Cipher, SplitTunnel: in.SplitTunnel, Extra: in.Extra,
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

func (s *Server) handleVPNConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, s.LoadConfig())
}

// mergedConfig decodes r's body onto cur, keeping server-owned path fields
// untouched — shared by PUT and preview so they can't drift on what's editable.
func mergedConfig(cur ovpnconf.Config, r *http.Request) (ovpnconf.Config, bool) {
	in := cur
	if !decode(r, &in) {
		return in, false
	}
	in.CACert, in.ServerCert, in.ServerKey = cur.CACert, cur.ServerCert, cur.ServerKey
	in.CRL, in.TLSCrypt, in.MgmtSocket, in.StatusLog = cur.CRL, cur.TLSCrypt, cur.MgmtSocket, cur.StatusLog
	in.StatusInterval = cur.StatusInterval
	in.ServerCN = cur.ServerCN
	return in, true
}

func (s *Server) handleVPNConfigPut(w http.ResponseWriter, r *http.Request, u *store.User) {
	cur := s.LoadConfig()
	in, ok := mergedConfig(cur, r)
	if !ok {
		jsonErr(w, 400, "bad json")
		return
	}
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

// handleVPNConfigPreview is handleVPNConfigPut's dry run: same merge+validation,
// but diffs against the persisted config instead of writing.
func (s *Server) handleVPNConfigPreview(w http.ResponseWriter, r *http.Request, u *store.User) {
	cur := s.LoadConfig()
	in, ok := mergedConfig(cur, r)
	if !ok {
		jsonErr(w, 400, "bad json")
		return
	}
	if err := in.Validate(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	diff := ovpnconf.Diff(cur.Render(), in.Render())
	warning := DNSLeakWarning(in, LoadDNSConfig(s.Store))
	jsonOK(w, map[string]any{"diff": diff, "changed": len(diff) > 0, "warning": warning})
}

// handleProc drives a supervised worker's lifecycle (start|stop|restart,
// optionally reconnect) — shared by /api/vpn/{op} and /api/dns/{op}, name
// prefixes the audit action and unknown-op message per worker.
func (s *Server) handleProc(name string, target controller.Lifecycle, allowReconnect bool) handler {
	return func(w http.ResponseWriter, r *http.Request, u *store.User) {
		op := r.PathValue("op")
		var err error
		switch op {
		case "start":
			err = target.Start()
		case "stop":
			err = target.Stop()
		case "restart":
			err = target.Restart()
		case "reconnect":
			if !allowReconnect {
				jsonErr(w, 404, "unknown "+name+" operation")
				return
			}
			err = target.Reconnect()
		default:
			jsonErr(w, 404, "unknown "+name+" operation")
			return
		}
		if err != nil {
			jsonErr(w, opStatus(err), err.Error())
			return
		}
		s.Store.Audit(u.Username, name+"_"+op, "")
		jsonOK(w, map[string]any{"op": op, "pid": target.Pid()})
	}
}

func (s *Server) handleTelegramConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, s.Telegram.Status())
}

// handleTelegramConfigSet sets token and/or admin independently — empty means
// unchanged for that field; SetToken validates against getMe when given.
// Admin is applied before token: SetAdmin's goodbye message to the outgoing
// admin needs the chat id SetToken would otherwise have already wiped, had a
// caller changed both in one request (SetToken clears it on any real token
// change, same unlink-on-identity-change rule SetAdmin follows for its own field).
func (s *Server) handleTelegramConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Token, Admin string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	if in.Admin != "" {
		if err := telegram.SetAdmin(s.Store, in.Admin); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		s.Store.Audit(u.Username, "telegram_admin_change", "admin="+in.Admin)
	}
	if in.Token != "" {
		if err := telegram.SetToken(s.Store, in.Token); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		s.Store.Audit(u.Username, "telegram_token_change", "")
	}
	jsonOK(w, s.Telegram.Status())
}

func (s *Server) handleTelegramOp(w http.ResponseWriter, r *http.Request, u *store.User) {
	op := r.PathValue("op")
	var err error
	switch op {
	case "start":
		err = s.Telegram.Start()
	case "stop":
		err = s.Telegram.Stop()
	case "restart":
		err = s.Telegram.Restart()
	default:
		jsonErr(w, 404, "unknown telegram operation")
		return
	}
	if err != nil {
		jsonErr(w, opStatus(err), err.Error())
		return
	}
	s.Store.Audit(u.Username, "telegram_"+op, "")
	jsonOK(w, s.Telegram.Status())
}

// opStatus: an op already in flight is a client retry situation, not a
// server failure — 409 instead of the generic 502.
func opStatus(err error) int {
	if errors.Is(err, controller.ErrBusy) {
		return 409
	}
	return 502
}

// handleCertDNS toggles whether a cert's CN gets a certs.hosts line while
// connected, mirroring handleUserDisabled's shape.
func (s *Server) handleCertDNS(w http.ResponseWriter, r *http.Request, u *store.User) {
	serial := r.PathValue("serial")
	var in struct{ IncludeDNS bool }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	c, err := s.Store.GetCert(serial)
	if err != nil {
		jsonErr(w, 404, "certificate not found")
		return
	}
	if c.IncludeDNS == in.IncludeDNS {
		jsonOK(w, map[string]bool{"ok": true, "changed": false})
		return
	}
	if err := s.Store.SetCertDNS(serial, in.IncludeDNS); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	action := "cert_dns_exclude"
	if in.IncludeDNS {
		action = "cert_dns_include"
	}
	s.Store.Audit(u.Username, action, "serial="+serial)
	jsonOK(w, map[string]bool{"ok": true, "changed": true})
}

// handleCustomHostsGet/Put/Preview manage custom.hosts — the free-form,
// user-authored hosts file, edited as one blob (same "whole-file, no
// per-line CRUD" shape custom-opts already uses for server.conf's Extra).
func (s *Server) handleCustomHostsGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	data, err := os.ReadFile(s.CustomHostsPath)
	if err != nil && !os.IsNotExist(err) {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]string{"content": string(data)})
}

func (s *Server) handleCustomHostsPut(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Content string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	if err := WriteAtomicHosts(s.CustomHostsPath, []byte(in.Content), s.DNSGroupGID); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "dns_custom_change", "")
	jsonOK(w, map[string]bool{"ok": true})
}

// handleCustomHostsPreview is handleCustomHostsPut's dry run, same shape as
// handleVPNConfigPreview: diff against what's on disk, don't write it.
func (s *Server) handleCustomHostsPreview(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Content string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	cur, err := os.ReadFile(s.CustomHostsPath)
	if err != nil && !os.IsNotExist(err) {
		jsonErr(w, 500, err.Error())
		return
	}
	diff := ovpnconf.Diff(cur, []byte(in.Content))
	jsonOK(w, map[string]any{"diff": diff, "changed": len(diff) > 0})
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

// UserSummary strips store.User to its non-secret fields — shared by /users,
// the status export, and `user list -json` so one place decides what's safe to leak.
type UserSummary struct {
	Username  string
	Role      string
	Disabled  bool
	TOTP      bool
	CreatedAt time.Time
}

func NewUserSummary(u store.User) UserSummary {
	return UserSummary{u.Username, u.Role, u.Disabled, u.TOTPSecret != "", u.CreatedAt}
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request, u *store.User) {
	users, err := s.Store.ListUsers()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	out := []UserSummary{}
	for _, x := range users {
		out = append(out, NewUserSummary(x))
	}
	jsonOK(w, out)
}

// checkPassword enforces auth.SecretOK, unless auth.SecretYOLO() is set — in
// which case it's let through, audited so the paper trail says so.
func (s *Server) checkPassword(w http.ResponseWriter, actor, target, password string) bool {
	if auth.SecretOK(password) {
		return true
	}
	if !auth.SecretYOLO() {
		jsonErr(w, 400, auth.SecretErr("password"))
		return false
	}
	s.Store.Audit(actor, "weak_password_accepted", "target="+target+" reason="+auth.SecretYOLOEnv+" is set")
	return true
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Username, Password, Role string }
	if !decode(r, &in) || in.Username == "" || !auth.ValidRole(in.Role) {
		jsonErr(w, 400, "username and valid role required")
		return
	}
	if !s.checkPassword(w, u.Username, in.Username, in.Password) {
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
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	if !s.checkPassword(w, u.Username, name, in.Password) {
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
// secret immediately (no confirm step) and returns it with a QR code.
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

// DNSConfig is the admin-tunable dnsmasq policy, persisted under dnsConfigKey.
type DNSConfig struct {
	BlockInternet bool // dnsmasq --no-resolv/--server=/#/ on next start/restart
}

// DefaultDNSConfig seeds from OVCP_DNS_BLOCK_INTERNET (container/unattended init).
func DefaultDNSConfig() DNSConfig {
	return DNSConfig{BlockInternet: os.Getenv("OVCP_DNS_BLOCK_INTERNET") == "true"}
}

const dnsConfigKey = "dns_config"

// LoadDNSConfig/SaveDNSConfig: the one read/write path, shared by the CLI
// (`ovcp dns config`), these handlers, and PreStart's dnsmasq arg build.
func LoadDNSConfig(s *store.Store) DNSConfig {
	return store.LoadJSON(s, dnsConfigKey, DefaultDNSConfig())
}
func SaveDNSConfig(s *store.Store, cfg DNSConfig) error { return store.SaveJSON(s, dnsConfigKey, cfg) }

// DNSLeakWarning flags a vpn/dns config combo that can leak queries around
// Block internet DNS — advisory only, never blocks a save. Shared by the CLI
// and the web UI's own inline check.
func DNSLeakWarning(vpn ovpnconf.Config, dns DNSConfig) string {
	switch {
	case dns.BlockInternet && len(vpn.DNS) > 0:
		return "manual DNS entries can leak queries around Block internet DNS"
	case dns.BlockInternet && !vpn.PushInternalDNS:
		return "Block internet DNS has no effect unless Push internal DNS is also on"
	}
	return ""
}

func (s *Server) handleDNSConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	dns := LoadDNSConfig(s.Store)
	jsonOK(w, map[string]any{"blockInternet": dns.BlockInternet, "warning": DNSLeakWarning(s.LoadConfig(), dns)})
}

// handleDNSConfigSet toggles whether dnsmasq forwards to upstream resolvers;
// PreStart picks it up on the next dnsmasq start/restart.
func (s *Server) handleDNSConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ BlockInternet bool }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	dns := DNSConfig{BlockInternet: in.BlockInternet}
	if err := SaveDNSConfig(s.Store, dns); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	action := "off"
	if in.BlockInternet {
		action = "on"
	}
	s.Store.Audit(u.Username, "dns_block_internet_"+action, "")
	jsonOK(w, map[string]any{"blockInternet": in.BlockInternet, "warning": DNSLeakWarning(s.LoadConfig(), dns)})
}

func (s *Server) handleLogsConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, store.LoadJSON(s.Store, "log_config", controller.DefaultLogConfig()))
}

// handleLogsConfigSet merges the JSON body onto the current config — an
// omitted field stays unchanged, same as PUT /api/vpn/config.
func (s *Server) handleLogsConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	cfg := store.LoadJSON(s.Store, "log_config", controller.DefaultLogConfig())
	if !decode(r, &cfg) {
		jsonErr(w, 400, "bad json")
		return
	}
	if err := store.SaveJSON(s.Store, "log_config", cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "log_config_change", "")
	jsonOK(w, cfg)
}

// handleLogsRotate is `ovcp logs rotate`'s API twin — same RotateLogs call.
func (s *Server) handleLogsRotate(w http.ResponseWriter, r *http.Request, u *store.User) {
	dir := filepath.Join(s.DataDir, "logs")
	paths := make([]string, len(controller.LogNames))
	for i, name := range controller.LogNames {
		paths[i] = filepath.Join(dir, name+".log")
	}
	cfg := store.LoadJSON(s.Store, "log_config", controller.DefaultLogConfig())
	if err := controller.RotateLogs(paths, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "log_rotate", "")
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleStatsConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, s.StatsConfig())
}

// handleStatsConfigSet merges the JSON body onto the current config, same
// idiom as handleLogsConfigSet.
func (s *Server) handleStatsConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	cfg := s.StatsConfig()
	if !decode(r, &cfg) {
		jsonErr(w, 400, "bad json")
		return
	}
	if cfg.SampleIntervalSec <= 0 || cfg.RetentionHours <= 0 {
		jsonErr(w, 400, "sampleIntervalSec and retentionHours must be positive")
		return
	}
	if err := SaveStatsConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.Store.Audit(u.Username, "stats_config_change", "")
	jsonOK(w, cfg)
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
	if errors.Is(err, store.ErrDuplicateCN) || errors.Is(err, store.ErrNoActiveCert) {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonErr(w, 500, err.Error())
}
