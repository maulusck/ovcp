package api

import (
	"errors"
	"fmt"
	"io"
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
func (s *Server) handleHealthz(c call, _ none) (Health, error) {
	if err := s.Store.Ping(); err != nil {
		return Health{}, fail(503, "db unreachable")
	}
	return Health{"ok"}, nil
}

// Health is GET /healthz.
type Health struct {
	Status string `json:"status"`
}

func (s *Server) handleLogin(c call, in struct{ Username, Password, TOTP string }) (Me, error) {
	token, u, err := s.Auth.Login(in.Username, in.Password, in.TOTP, clientIP(c.r))
	switch err {
	case nil:
	case auth.ErrTOTPRequired:
		return Me{}, fail(401, "totp required")
	case auth.ErrRateLimited:
		slog.Warn("login rate limited", "user", in.Username, "remote", clientIP(c.r))
		return Me{}, fail(429, "too many attempts, try again later")
	default:
		slog.Warn("login failed", "user", in.Username, "remote", clientIP(c.r))
		return Me{}, fail(401, "invalid credentials")
	}
	http.SetCookie(c.w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(auth.SessionTTL.Seconds())})
	http.SetCookie(c.w, &http.Cookie{Name: csrfCookie, Value: randToken(), Path: "/",
		Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(auth.SessionTTL.Seconds())})
	return s.me(u), nil
}

func (s *Server) handleLogout(c call, _ none) (Msg, error) {
	if ck, err := c.r.Cookie(sessionCookie); err == nil {
		s.Auth.Logout(ck.Value)
	}
	http.SetCookie(c.w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	return Msg{"logged out", true}, nil
}

// Me is the signed-in user and the server facts the UI shows: versions, the
// password policy, the status poll cadence and the CA (unset if unreadable).
type Me struct {
	Username         string    `json:"username"`
	Role             string    `json:"role"`
	ServerCN         string    `json:"serverCN"`
	Version          string    `json:"version"`
	BuildTarget      string    `json:"buildTarget"`
	Platform         string    `json:"platform"`
	OpenVPNVersion   string    `json:"openvpnVersion"`
	OpenVPNPath      string    `json:"openvpnPath"`
	DnsmasqVersion   string    `json:"dnsmasqVersion"`
	DnsmasqPath      string    `json:"dnsmasqPath"`
	NftVersion       string    `json:"nftVersion"`
	NftPath          string    `json:"nftPath"`
	UpstreamsEnabled bool      `json:"upstreamsEnabled"`
	MinSecretLen     int       `json:"minSecretLen"`
	MinSecretClasses int       `json:"minSecretClasses"`
	StatusPollSecs   int       `json:"statusPollSeconds"` // openvpn's status file cadence (OVCP_STATUS_INTERVAL)
	CACN             string    `json:"caCN,omitempty"`
	CANotAfter       time.Time `json:"caNotAfter,omitzero"`
	CAStatus         string    `json:"caStatus,omitempty"`
}

func (s *Server) me(u *store.User) Me {
	m := Me{u.Username, u.Role, s.DefaultRemote(), s.Version, s.BuildTarget, runtime.GOOS + "/" + runtime.GOARCH,
		s.OpenVPNVersion, s.OpenVPNPath, s.DnsmasqVersion, s.DnsmasqPath, s.NftVersion, s.NftPath, s.UpstreamsEnabled,
		auth.MinSecretLen, auth.MinSecretClasses, s.LoadConfig().EffectiveStatusInterval(), "", time.Time{}, ""}
	if ca, err := s.PKI.CACert(); err == nil {
		m.CACN, m.CANotAfter, m.CAStatus = ca.Subject.CommonName, ca.NotAfter, store.Cert{NotAfter: ca.NotAfter}.Status()
	}
	return m
}

func (s *Server) handleMe(c call, _ none) (Me, error) { return s.me(c.u), nil }

func (s *Server) handleKill(c call, in struct{ CN string }) (Msg, error) {
	if in.CN == "" {
		return Msg{}, fail(400, "cn required")
	}
	return Kill(s.Store, c.u.Username, in.CN, s.Mgmt.Kill)
}

func (s *Server) handleCertList(c call, _ none) ([]CertRow, error) {
	certs, err := s.Store.ListCerts()
	if err != nil {
		return nil, httpError{500, err}
	}
	out := []CertRow{}
	for _, c := range certs {
		out = append(out, NewCertRow(c))
	}
	return out, nil
}

func (s *Server) handleIssue(c call, in struct {
	CN, Passphrase, KeyPassphrase string
	Days                          int
}) (IssueResult, error) {
	if in.CN == "" || in.Passphrase == "" {
		return IssueResult{}, fail(400, "cn and passphrase required")
	}
	req := ClientRequest{CN: in.CN, Days: defaultDays(in.Days, 365), Passphrase: []byte(in.Passphrase), KeyPass: in.KeyPassphrase}
	ic, err := IssueClient(s.Store, s.PKI, req)
	if err != nil {
		return IssueResult{}, pkiErr(err)
	}
	AuditClient(s.Store, c.u.Username, req, ic)
	return IssueResult{ic.SerialHex, string(ic.CertPEM), string(ic.KeyPEM)}, nil
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
func (s *Server) handleRenew(c call, in struct {
	Passphrase string
	Days       int
}) (RenewResult, error) {
	res, err := RenewServer(s.Store, s.PKI, s.ServerCert, s.ServerKey, c.u.Username, s.DefaultRemote(), defaultDays(in.Days, 825), []byte(in.Passphrase))
	if err != nil {
		return res, pkiErr(err)
	}
	return res, nil
}

// handleBackup streams an encrypted backup download; admin-only. No restore endpoint here — `ovcp backup restore` is CLI-only, offline.
func (s *Server) handleBackup(c call, in struct{ Passphrase string }) (Download, error) {
	if in.Passphrase == "" {
		return Download{}, fail(400, "passphrase required")
	}
	name := "ovcp-backup-" + time.Now().Format("20060102-150405") + ".ovcpbak"
	return Download{name, "application/octet-stream", func(w io.Writer) error {
		if err := backup.Create(s.DataDir, s.Store, w, []byte(in.Passphrase)); err != nil {
			return err
		}
		s.Store.Audit(c.u.Username, "backup_create", "")
		return nil
	}}, nil
}

func (s *Server) handleRevoke(c call, in struct{ Serial, Passphrase string }) (RevokeResult, error) {
	if in.Serial == "" || in.Passphrase == "" {
		return RevokeResult{}, fail(400, "serial and passphrase required")
	}
	res, err := RevokeCert(s.Store, s.PKI, c.u.Username, in.Serial, []byte(in.Passphrase))
	if err != nil {
		return res, pkiErr(err)
	}
	s.restartSessions(res.CN)
	return res, nil
}

// handleExport issues a fresh client cert and returns an inline .ovpn.
func (s *Server) handleExport(c call, in struct {
	CN, Passphrase, Remote, KeyPassphrase, Extra string
	Days                                         int
	SplitTunnel, Renew                           bool
}) (ExportResult, error) {
	if in.CN == "" || in.Passphrase == "" {
		return ExportResult{}, fail(400, "cn and passphrase required")
	}
	if in.Remote == "" {
		in.Remote = s.DefaultRemote()
	}
	req := ClientRequest{CN: in.CN, Days: defaultDays(in.Days, 365), Passphrase: []byte(in.Passphrase),
		KeyPass: in.KeyPassphrase, Renew: in.Renew}
	ic, bundle, err := ExportClient(s.Store, s.PKI, s.TLSCrypt, req,
		ExportOpts{Remote: in.Remote, ServerCN: s.DefaultRemote(), Extra: in.Extra, SplitTunnel: in.SplitTunnel})
	if err != nil {
		return ExportResult{}, pkiErr(err)
	}
	if in.Renew {
		s.restartSessions(in.CN)
	}
	AuditClient(s.Store, c.u.Username, req, ic)
	return ExportResult{ic.SerialHex, string(bundle)}, nil
}

func (s *Server) handleVPNConfigGet(c call, _ none) (ovpnconf.Config, error) {
	return s.LoadConfig(), nil
}

// mergedConfig is p onto the current config, server-owned path fields kept:
// shared by PUT and preview so they can't drift on what's editable.
func (s *Server) mergedConfig(p Patch[ovpnconf.Config]) (ovpnconf.Config, error) {
	cur := s.LoadConfig()
	in, err := p.Onto(cur)
	in.CACert, in.ServerCert, in.ServerKey = cur.CACert, cur.ServerCert, cur.ServerKey
	in.CRL, in.TLSCrypt, in.MgmtSocket, in.StatusLog = cur.CRL, cur.TLSCrypt, cur.MgmtSocket, cur.StatusLog
	in.StatusInterval = cur.StatusInterval
	in.ServerCN = cur.ServerCN
	return in, err
}

func (s *Server) handleVPNConfigPut(c call, p Patch[ovpnconf.Config]) (ovpnconf.Config, error) {
	in, err := s.mergedConfig(p)
	if err != nil {
		return in, err
	}
	_, err = SetVPNConfig(s.Store, c.u.Username, s.ConfigPath, in)
	return in, err
}

// handleVPNConfigPreview is handleVPNConfigPut's dry run: same merge+validation,
// but diffs against the persisted config instead of writing.
func (s *Server) handleVPNConfigPreview(c call, p Patch[ovpnconf.Config]) (Preview, error) {
	in, err := s.mergedConfig(p)
	if err != nil {
		return Preview{}, err
	}
	return PreviewVPNConfig(s.Store, in)
}

// opIn is a lifecycle route's input: the {op} it names.
type opIn struct {
	Op string `json:"op"`
}

// handleProc drives a supervised worker's lifecycle (start|stop|restart,
// optionally reconnect) — shared by /api/vpn/{op} and /api/dns/{op}, name
// prefixes the audit action and unknown-op message per worker.
func (s *Server) handleProc(name string, target controller.Lifecycle, isVPN bool) func(call, opIn) (controller.ControlResult, error) {
	return func(c call, in opIn) (controller.ControlResult, error) {
		var after func() error
		if isVPN {
			after = s.AfterVPNStart
		}
		res, err := controller.RunOp(target, in.Op, isVPN, after)
		if err != nil {
			return res, httpError{opStatus(err), err}
		}
		if in.Op != "status" { // a read, never audited
			s.Store.Audit(c.u.Username, name+"_"+in.Op, fmt.Sprintf("pid=%d", res.Pid))
		}
		return res, nil
	}
}

func (s *Server) handleTelegramConfigGet(c call, _ none) (controller.TelegramStatus, error) {
	return s.Telegram.Status(), nil
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
func (s *Server) handleTelegramConfigSet(c call, in struct{ Token, Admin string }) (controller.TelegramStatus, error) {
	if err := SetTelegram(s.Store, c.u.Username, in.Admin, in.Token); err != nil {
		return controller.TelegramStatus{}, err
	}
	return s.Telegram.Status(), nil
}

func (s *Server) handleTelegramOp(c call, in opIn) (controller.TelegramStatus, error) {
	st, err := controller.RunTelegramOp(s.Telegram, in.Op)
	if err != nil {
		return st, httpError{opStatus(err), err}
	}
	if in.Op != "status" { // a read, never audited
		s.Store.Audit(c.u.Username, "telegram_"+in.Op, fmt.Sprintf("running=%t", st.Running))
	}
	return st, nil
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
func (s *Server) handleCertDNS(c call, in struct {
	Serial     string `json:"serial"`
	IncludeDNS bool
}) (Msg, error) {
	return SetCertDNS(s.Store, c.u.Username, in.Serial, in.IncludeDNS)
}

func (s *Server) handleCustomHostsPut(c call, in struct{ Content string }) (Msg, error) {
	return SetCustomHosts(s.Store, c.u.Username, s.CustomHostsPath, in.Content)
}

// handleCustomHostsPreview is handleCustomHostsPut's dry run, same shape as
// handleVPNConfigPreview: diff against what's on disk, don't write it.
func (s *Server) handleCustomHostsPreview(c call, in struct{ Content string }) (Preview, error) {
	cur, err := os.ReadFile(s.CustomHostsPath)
	if err != nil && !os.IsNotExist(err) {
		return Preview{}, httpError{500, err}
	}
	diff := ovpnconf.Diff(cur, []byte(in.Content))
	return Preview{Diff: diff, Changed: len(diff) > 0}, nil
}

// handleCertDownload returns the (public) certificate PEM for any issued cert.
func (s *Server) handleCertDownload(c call, in struct {
	Serial string `json:"serial"`
}) (Download, error) {
	cert, err := s.Store.GetCert(in.Serial)
	if err != nil {
		return Download{}, fail(404, "certificate not found")
	}
	return Download{cert.CN + ".crt", "application/x-pem-file", func(w io.Writer) error {
		_, err := w.Write(cert.CertPEM)
		return err
	}}, nil
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

func (s *Server) handleUsersList(c call, _ none) ([]UserSummary, error) {
	users, err := s.Store.ListUsers()
	if err != nil {
		return nil, httpError{500, err}
	}
	out := []UserSummary{}
	for _, x := range users {
		out = append(out, NewUserSummary(x))
	}
	return out, nil
}

func (s *Server) handleUserAdd(c call, in struct{ Username, Password, Role string }) (Msg, error) {
	return AddUser(s.Store, c.u.Username, in.Username, in.Password, in.Role)
}

// user is a per-user route's input: the {name} it names.
type user struct {
	Name string `json:"name"`
}

func (s *Server) handleUserDelete(c call, in user) (Msg, error) {
	if in.Name == c.u.Username {
		return Msg{}, fail(400, "cannot delete your own account")
	}
	return DeleteUser(s.Store, c.u.Username, in.Name)
}

// handleUserDisabled toggles enable/disable (`ovcp user disable|enable` as one endpoint).
func (s *Server) handleUserDisabled(c call, in struct {
	Name     string `json:"name"`
	Disabled bool
}) (Msg, error) {
	if in.Disabled && in.Name == c.u.Username {
		return Msg{}, fail(400, "cannot disable your own account")
	}
	return SetUserDisabled(s.Store, c.u.Username, in.Name, in.Disabled)
}

func (s *Server) handleUserPassword(c call, in struct {
	Name     string `json:"name"`
	Password string
}) (Msg, error) {
	return SetUserPassword(s.Store, c.u.Username, in.Name, in.Password)
}

// handleUserTOTPEnroll mirrors `ovcp user totp`: generates+stores a fresh
// secret immediately (no confirm step) and returns it with a QR code.
func (s *Server) handleUserTOTPEnroll(c call, in user) (TOTPEnrollment, error) {
	return EnrollTOTP(s.Store, c.u.Username, in.Name, s.DefaultRemote())
}

func (s *Server) handleUserTOTPOff(c call, in user) (Msg, error) {
	return DisableTOTP(s.Store, c.u.Username, in.Name)
}

// Debug is the server's log level, as GET and POST /api/debug read and set it.
type Debug struct {
	Debug bool `json:"debug"`
}

func (s *Server) handleDebugGet(c call, _ none) (Debug, error) {
	return Debug{s.DebugLevel.Level() <= slog.LevelDebug}, nil
}

// handleDebugSet mirrors `ovcp debug on|off`, flipping the same shared
// *slog.LevelVar the control-socket handler uses — one source of truth.
func (s *Server) handleDebugSet(c call, in Debug) (Debug, error) {
	action := "off"
	if in.Debug {
		s.DebugLevel.Set(slog.LevelDebug)
		action = "on"
	} else {
		s.DebugLevel.Set(slog.LevelInfo)
	}
	s.Store.Audit(c.u.Username, "debug_"+action, "")
	return in, nil
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

func (s *Server) handleDNSConfigGet(c call, _ none) (DNSView, error) { return ViewDNS(s.Store), nil }

// handleDNSConfigSet toggles whether dnsmasq forwards to upstream resolvers;
// PreStart picks it up on the next dnsmasq start/restart.
func (s *Server) handleDNSConfigSet(c call, in DNSConfig) (DNSView, error) {
	return SetDNSConfig(s.Store, c.u.Username, in)
}

func (s *Server) handleLogsConfigGet(c call, _ none) (controller.LogConfig, error) {
	return LoadLogConfig(s.Store), nil
}

// handleLogsConfigSet applies the body onto the current config — an omitted
// field stays unchanged, same as PUT /api/vpn/config.
func (s *Server) handleLogsConfigSet(c call, p Patch[controller.LogConfig]) (controller.LogConfig, error) {
	cfg, err := p.Onto(LoadLogConfig(s.Store))
	if err != nil {
		return cfg, err
	}
	return SaveLogConfig(s.Store, c.u.Username, cfg)
}

// handleLogsRotate is `ovcp logs rotate`'s API twin — same RotateLogs call.
func (s *Server) handleLogsRotate(c call, _ none) (Msg, error) {
	return RotateLogs(s.Store, c.u.Username, s.DataDir)
}

func (s *Server) handleStatsConfigGet(c call, _ none) (StatsConfig, error) {
	return s.StatsConfig(), nil
}

// handleStatsConfigSet applies the body onto the current config, same idiom
// as handleLogsConfigSet.
func (s *Server) handleStatsConfigSet(c call, p Patch[StatsConfig]) (StatsConfig, error) {
	cfg, err := p.Onto(s.StatsConfig())
	if err != nil {
		return cfg, err
	}
	return SaveStatsConfig(s.Store, c.u.Username, cfg)
}

func (s *Server) handleAudit(c call, _ none) ([]store.AuditEntry, error) {
	tail, err := s.Store.AuditTail(200)
	if err != nil {
		return nil, httpError{500, err}
	}
	return tail, nil
}

// pkiErr is a PKI action's error: a wrong passphrase 403, a refusal the
// caller can fix 400, anything else the server's 500.
func pkiErr(err error) error {
	switch {
	case err == pki.ErrBadPassphrase:
		return fail(403, "wrong CA passphrase")
	case errors.Is(err, store.ErrDuplicateCN), errors.Is(err, store.ErrNoActiveCert),
		errors.Is(err, ovpnconf.ErrNoRedirect), errors.Is(err, ErrNoRemote), errors.Is(err, ErrNoServerCN):
		return httpError{400, err}
	}
	return httpError{500, err}
}
