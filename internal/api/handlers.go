package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
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
		"username": u.Username, "role": u.Role, "serverCN": s.DefaultRemote(),
		"version": s.Version, "buildTarget": s.BuildTarget, "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"openvpnVersion": s.OpenVPNVersion, "openvpnPath": s.OpenVPNPath,
		"dnsmasqVersion": s.DnsmasqVersion, "dnsmasqPath": s.DnsmasqPath,
		"nftVersion": s.NftVersion, "nftPath": s.NftPath, "upstreamsEnabled": s.UpstreamsEnabled,
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

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ CN string }
	if !decode(r, &in) || in.CN == "" {
		jsonErr(w, 400, "cn required")
		return
	}
	act(w)(Kill(s.Store, u.Username, in.CN, s.Mgmt.Kill))
}

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request, u *store.User) {
	certs, err := s.Store.ListCerts()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	out := []CertRow{}
	for _, c := range certs {
		out = append(out, NewCertRow(c))
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
	req := ClientRequest{CN: in.CN, Days: defaultDays(in.Days, 365), Passphrase: []byte(in.Passphrase), KeyPass: in.KeyPassphrase}
	ic, err := IssueClient(s.Store, s.PKI, req)
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	AuditClient(s.Store, u.Username, req, ic)
	jsonOK(w, IssueResult{ic.SerialHex, string(ic.CertPEM), string(ic.KeyPEM)})
}

// IssueResult is a client issue's result: the key appears here once, never stored.
type IssueResult struct {
	Serial string `json:"serial"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
}

// ExportResult is a client export's result: the .ovpn, key inline.
type ExportResult struct {
	Serial string `json:"serial"`
	Bundle string `json:"bundle"`
}

// CertRow is one certificate as certificate list, record list (with IP) and
// GET /api/certs show it.
type CertRow struct {
	Status     string    `json:"status"`
	Kind       string    `json:"kind"`
	CN         string    `json:"cn"`
	Serial     string    `json:"serial"`
	Issued     time.Time `json:"issued"`
	Expires    time.Time `json:"expires"`
	IncludeDNS bool      `json:"includeDNS"`
	IP         string    `json:"ip,omitempty"` // record list: where it resolves right now
}

// NewCertRow is c's CertRow, IP unset.
func NewCertRow(c store.Cert) CertRow {
	return CertRow{c.Status(), c.Kind, c.CN, c.Serial, c.IssuedAt, c.NotAfter, c.IncludeDNS, ""}
}

// ClientRequest is one client issue or renewal, CLI or API alike.
type ClientRequest struct {
	CN         string
	Days       int
	Passphrase []byte // CA passphrase
	KeyPass    string // encrypts the returned key; "" leaves it plain
	Renew      bool   // replace cn's active cert instead of adding one
}

// IssueClient is every client issue: a renewal retires the outgoing cert only
// once the new one exists, then regenerates the CRL. Restarting the outgoing
// cert's sessions is the caller's, over its own transport.
func IssueClient(st *store.Store, p *pki.PKI, r ClientRequest) (*pki.IssuedCert, error) {
	if r.Renew {
		if err := st.RequireActiveCert(r.CN, "client"); err != nil {
			return nil, err
		}
	}
	ic, err := p.Issue(pki.KindClient, r.CN, r.Days, r.Passphrase)
	if err != nil {
		return nil, err
	}
	if r.KeyPass != "" {
		if ic.KeyPEM, err = pki.EncryptKeyPEM(ic.KeyPEM, r.KeyPass); err != nil {
			return nil, err
		}
	}
	c := store.CertFrom(ic, "client")
	if !r.Renew {
		return ic, st.AddCert(c)
	}
	if err := st.ReplaceCert(c); err != nil {
		return nil, err
	}
	return ic, RegenCRL(st, p, r.Passphrase)
}

// ErrNoRemote: an export with no host to connect to and no server CN to default it to.
var ErrNoRemote = errors.New("remote required (no server CN found)")

// ExportOpts shape a .ovpn. Remote and ServerCN are required (callers default
// both to the server's CN); zero Port and Proto take the server's own.
type ExportOpts struct {
	Remote, ServerCN, Proto, Extra string
	Port                           int
	SplitTunnel                    bool
}

// ExportClient is every export: IssueClient, then the .ovpn. The options are
// checked before anything is issued, so a refused export leaves no cert behind.
func ExportClient(st *store.Store, p *pki.PKI, tlsCryptPath string, r ClientRequest, o ExportOpts) (*pki.IssuedCert, []byte, error) {
	if o.Remote == "" || o.ServerCN == "" {
		return nil, nil, ErrNoRemote
	}
	cfg := LoadConfig(st)
	if o.Port != 0 {
		cfg.Port = o.Port
	}
	if o.Proto != "" {
		cfg.Proto = o.Proto
	}
	if o.SplitTunnel && !cfg.CanSplitTunnel() {
		return nil, nil, ovpnconf.ErrNoRedirect
	}
	caPEM, err := p.CACertPEM()
	if err != nil {
		return nil, nil, err
	}
	tc, err := os.ReadFile(tlsCryptPath)
	if err != nil {
		return nil, nil, err
	}
	ic, err := IssueClient(st, p, r)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := pki.RenderOVPN(pki.BundleParams{
		Remote: o.Remote, Port: cfg.Port, Proto: cfg.Proto, ServerCN: o.ServerCN,
		CACertPEM: caPEM, ClientCert: ic.CertPEM, ClientKey: ic.KeyPEM,
		TLSCrypt: tc, Cipher: cfg.Cipher, SplitTunnel: o.SplitTunnel, Extra: o.Extra,
	})
	return ic, bundle, err
}

// defaultDays is the API's reading of an omitted Days: the CLI flag's default.
func defaultDays(d, def int) int {
	if d == 0 {
		return def
	}
	return d
}

// AuditClient records a client issue or renewal, the same line from every path.
func AuditClient(st *store.Store, actor string, r ClientRequest, ic *pki.IssuedCert) {
	action := "issue"
	if r.Renew {
		action = "renew"
	}
	st.Audit(actor, action, "cn="+r.CN+" serial="+ic.SerialHex)
}

// RegenCRL rebuilds the CRL from the store's full revoked set: the one
// implementation behind every revoke, CLI (cmd/ovcp) or API.
func RegenCRL(st *store.Store, p *pki.PKI, passphrase []byte) error {
	rev, err := st.RevokedCerts()
	if err != nil {
		return err
	}
	entries := make([]pki.RevokedEntry, len(rev))
	for i, c := range rev {
		entries[i] = pki.RevokedEntry{SerialHex: c.Serial, RevokedAt: *c.RevokedAt}
	}
	return p.RegenCRL(entries, passphrase)
}

// restartSessions restarts cn's live sessions so openvpn checks the new CRL
// on reconnect, not at the next renegotiation.
func (s *Server) restartSessions(cn string) {
	if _, err := s.Mgmt.Kill(cn, "RESTART"); err != nil {
		slog.Warn("revoke: live sessions not restarted", "cn", cn, "err", err)
	}
}

// RevokeResult is a revocation's result.
type RevokeResult struct {
	Serial  string `json:"serial"`
	CN      string `json:"cn"`
	CRLPath string `json:"crlPath"`
}

// RevokeCert is every revoke, CLI or API: the passphrase is checked before
// the store changes, so a revoked row always reaches the CRL. Restarting the
// CN's sessions is the caller's, over its own transport.
func RevokeCert(st *store.Store, p *pki.PKI, actor, serial string, passphrase []byte) (RevokeResult, error) {
	if err := p.CheckPassphrase(passphrase); err != nil {
		return RevokeResult{}, err
	}
	cn, err := st.Revoke(serial, time.Now())
	if err != nil {
		return RevokeResult{}, err
	}
	if err := RegenCRL(st, p, passphrase); err != nil {
		return RevokeResult{}, err
	}
	st.Audit(actor, "revoke", "serial="+serial)
	return RevokeResult{serial, cn, p.CRLPath()}, nil
}

// WriteServerCert persists a freshly issued server cert+key to the paths
// `serve` reads and records it in the store: init and RenewServer.
func WriteServerCert(st *store.Store, certPath, keyPath string, ic *pki.IssuedCert) error {
	if err := pki.WriteFileAtomic(certPath, ic.CertPEM, 0o644); err != nil {
		return err
	}
	if err := pki.WriteFileAtomic(keyPath, ic.KeyPEM, 0o600); err != nil {
		return err
	}
	return st.ReplaceCert(store.CertFrom(ic, "server"))
}

// RenewResult is a server-cert renewal's result.
type RenewResult struct {
	CN       string    `json:"cn"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"notAfter"`
}

// ErrNoServerCN: nothing names the server (e.g. right after a backup restore).
var ErrNoServerCN = errors.New("no server CN known (e.g. right after a backup restore): name one")

// RenewServer reissues the active server cert as cn (the current CN, or a
// rename) at the paths serve reads; it applies on the next vpn restart.
func RenewServer(st *store.Store, p *pki.PKI, certPath, keyPath, actor, cn string, days int, passphrase []byte) (RenewResult, error) {
	if err := st.RequireActiveCert("", "server"); err != nil {
		return RenewResult{}, err
	}
	if cn == "" {
		return RenewResult{}, ErrNoServerCN
	}
	ic, err := p.Issue(pki.KindServer, cn, days, passphrase)
	if err != nil {
		return RenewResult{}, err
	}
	if err := WriteServerCert(st, certPath, keyPath, ic); err != nil {
		return RenewResult{}, err
	}
	st.Audit(actor, "renew", "kind=server cn="+cn+" serial="+ic.SerialHex)
	return RenewResult{cn, ic.SerialHex, ic.NotAfter}, nil
}

// handleRenew reissues the server cert in place, same CN (a rename is CLI-only).
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		Passphrase string
		Days       int
	}
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	res, err := RenewServer(s.Store, s.PKI, s.ServerCert, s.ServerKey, u.Username, s.DefaultRemote(), defaultDays(in.Days, 825), []byte(in.Passphrase))
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	jsonOK(w, res)
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
	res, err := RevokeCert(s.Store, s.PKI, u.Username, in.Serial, []byte(in.Passphrase))
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	s.restartSessions(res.CN)
	jsonOK(w, res)
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
		in.Remote = s.DefaultRemote()
	}
	req := ClientRequest{CN: in.CN, Days: defaultDays(in.Days, 365), Passphrase: []byte(in.Passphrase),
		KeyPass: in.KeyPassphrase, Renew: in.Renew}
	ic, bundle, err := ExportClient(s.Store, s.PKI, s.TLSCrypt, req,
		ExportOpts{Remote: in.Remote, ServerCN: s.DefaultRemote(), Extra: in.Extra, SplitTunnel: in.SplitTunnel})
	if err != nil {
		s.pkiErr(w, err)
		return
	}
	if in.Renew {
		s.restartSessions(in.CN)
	}
	AuditClient(s.Store, u.Username, req, ic)
	jsonOK(w, ExportResult{ic.SerialHex, string(bundle)})
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
	in, ok := mergedConfig(s.LoadConfig(), r)
	if !ok {
		jsonErr(w, 400, "bad json")
		return
	}
	if _, err := SetVPNConfig(s.Store, u.Username, s.ConfigPath, in); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonOK(w, in)
}

// handleVPNConfigPreview is handleVPNConfigPut's dry run: same merge+validation,
// but diffs against the persisted config instead of writing.
func (s *Server) handleVPNConfigPreview(w http.ResponseWriter, r *http.Request, u *store.User) {
	in, ok := mergedConfig(s.LoadConfig(), r)
	if !ok {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(PreviewVPNConfig(s.Store, in))
}

// handleProc drives a supervised worker's lifecycle (start|stop|restart,
// optionally reconnect) — shared by /api/vpn/{op} and /api/dns/{op}, name
// prefixes the audit action and unknown-op message per worker.
func (s *Server) handleProc(name string, target controller.Lifecycle, isVPN bool) handler {
	return func(w http.ResponseWriter, r *http.Request, u *store.User) {
		var after func() error
		if isVPN {
			after = s.AfterVPNStart
		}
		res, err := controller.RunOp(target, r.PathValue("op"), isVPN, after)
		if err != nil {
			jsonErr(w, opStatus(err), err.Error())
			return
		}
		if op := r.PathValue("op"); op != "status" { // a read, never audited
			s.Store.Audit(u.Username, name+"_"+op, fmt.Sprintf("pid=%d", res.Pid))
		}
		jsonOK(w, res)
	}
}

func (s *Server) handleTelegramConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, s.Telegram.Status())
}

// SetTelegram sets the bot's admin and/or token, "" leaving either unchanged.
// Admin applies first: SetToken wipes the chat id on a real token change, so
// SetAdmin's goodbye to the replaced chat must go out before it.
func SetTelegram(st *store.Store, actor, admin, token string) error {
	if admin == "" && token == "" {
		return errors.New("nothing to set: an admin and/or a token")
	}
	if admin != "" {
		if err := telegram.SetAdmin(st, admin); err != nil {
			return err
		}
		st.Audit(actor, "telegram_admin_change", "admin="+admin)
	}
	if token != "" {
		if err := telegram.SetToken(st, token); err != nil {
			return err
		}
		st.Audit(actor, "telegram_token_change", "")
	}
	return nil
}
func (s *Server) handleTelegramConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Token, Admin string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	if err := SetTelegram(s.Store, u.Username, in.Admin, in.Token); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonOK(w, s.Telegram.Status())
}

func (s *Server) handleTelegramOp(w http.ResponseWriter, r *http.Request, u *store.User) {
	st, err := controller.RunTelegramOp(s.Telegram, r.PathValue("op"))
	if err != nil {
		jsonErr(w, opStatus(err), err.Error())
		return
	}
	s.Store.Audit(u.Username, "telegram_"+r.PathValue("op"), "")
	jsonOK(w, st)
}

// opStatus: an op already in flight is a client retry situation, not a
// server failure — 409 instead of the generic 502.
func opStatus(err error) int {
	switch {
	case errors.Is(err, controller.ErrBusy):
		return 409
	case errors.Is(err, controller.ErrUnknownOp):
		return 404
	}
	return 502
}

// handleCertDNS toggles whether a cert's CN gets a certs.hosts line while
// connected, mirroring handleUserDisabled's shape.
func (s *Server) handleCertDNS(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ IncludeDNS bool }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(SetCertDNS(s.Store, u.Username, r.PathValue("serial"), in.IncludeDNS))
}

func (s *Server) handleCustomHostsPut(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Content string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(SetCustomHosts(s.Store, u.Username, s.CustomHostsPath, in.Content))
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

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Username, Password, Role string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(AddUser(s.Store, u.Username, in.Username, in.Password, in.Role))
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	name := r.PathValue("name")
	if name == u.Username {
		jsonErr(w, 400, "cannot delete your own account")
		return
	}
	act(w)(DeleteUser(s.Store, u.Username, name))
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
	act(w)(SetUserDisabled(s.Store, u.Username, name, in.Disabled))
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ Password string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(SetUserPassword(s.Store, u.Username, r.PathValue("name"), in.Password))
}

// handleUserTOTPEnroll mirrors `ovcp user totp`: generates+stores a fresh
// secret immediately (no confirm step) and returns it with a QR code.
func (s *Server) handleUserTOTPEnroll(w http.ResponseWriter, r *http.Request, u *store.User) {
	act(w)(EnrollTOTP(s.Store, u.Username, r.PathValue("name"), s.DefaultRemote()))
}

func (s *Server) handleUserTOTPOff(w http.ResponseWriter, r *http.Request, u *store.User) {
	act(w)(DisableTOTP(s.Store, u.Username, r.PathValue("name")))
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

// DNSView is the dns config as dns config get|set and the web API show it,
// with the leak warning (the CLI also prints it to stderr).
type DNSView struct {
	DNSConfig
	Warning string `json:"warning,omitempty"`
}

// ViewDNS is the persisted dns config's view.
func ViewDNS(st *store.Store) DNSView {
	dns := LoadDNSConfig(st)
	return DNSView{dns, DNSLeakWarning(LoadConfig(st), dns)}
}

// SetDNSConfig persists cfg.
func SetDNSConfig(st *store.Store, actor string, cfg DNSConfig) (DNSView, error) {
	if err := SaveDNSConfig(st, cfg); err != nil {
		return DNSView{}, err
	}
	action := "off"
	if cfg.BlockInternet {
		action = "on"
	}
	st.Audit(actor, "dns_block_internet_"+action, "")
	return ViewDNS(st), nil
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
	jsonOK(w, ViewDNS(s.Store))
}

// handleDNSConfigSet toggles whether dnsmasq forwards to upstream resolvers;
// PreStart picks it up on the next dnsmasq start/restart.
func (s *Server) handleDNSConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ BlockInternet bool }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(SetDNSConfig(s.Store, u.Username, DNSConfig{BlockInternet: in.BlockInternet}))
}

func (s *Server) handleLogsConfigGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, LoadLogConfig(s.Store))
}

// handleLogsConfigSet merges the JSON body onto the current config — an
// omitted field stays unchanged, same as PUT /api/vpn/config.
func (s *Server) handleLogsConfigSet(w http.ResponseWriter, r *http.Request, u *store.User) {
	cfg := LoadLogConfig(s.Store)
	if !decode(r, &cfg) {
		jsonErr(w, 400, "bad json")
		return
	}
	act(w)(SaveLogConfig(s.Store, u.Username, cfg))
}

// handleLogsRotate is `ovcp logs rotate`'s API twin — same RotateLogs call.
func (s *Server) handleLogsRotate(w http.ResponseWriter, r *http.Request, u *store.User) {
	act(w)(RotateLogs(s.Store, u.Username, s.DataDir))
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
	act(w)(SaveStatsConfig(s.Store, u.Username, cfg))
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
	if errors.Is(err, store.ErrDuplicateCN) || errors.Is(err, store.ErrNoActiveCert) ||
		errors.Is(err, ovpnconf.ErrNoRedirect) || errors.Is(err, ErrNoRemote) || errors.Is(err, ErrNoServerCN) {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonErr(w, 500, err.Error())
}
