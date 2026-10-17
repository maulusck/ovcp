package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

// The actions below are each the one implementation behind a CLI command and
// its web API route: both adapters print or encode the value returned here.

// Msg is the result of an action with nothing structured to return.
type Msg struct {
	Message string `json:"message"`
	Changed bool   `json:"changed"`
}

// ErrNotConnected: kill named a CN with no live session.
var ErrNotConnected = errors.New("not connected")

// Kill ends cn's sessions (HALT: the client exits) through kill, the caller's
// transport to openvpn.
func Kill(st *store.Store, actor, cn string, kill func(cn, verb string) (int, error)) (Msg, error) {
	n, err := kill(cn, "HALT")
	if err != nil {
		return Msg{}, err
	}
	if n == 0 {
		return Msg{}, fmt.Errorf("%s: %w", cn, ErrNotConnected)
	}
	st.Audit(actor, "kill", "cn="+cn)
	return Msg{"killed " + cn, true}, nil
}

// SetCertDNS includes or excludes an active client cert's DNS line.
func SetCertDNS(st *store.Store, actor, serial string, include bool) (Msg, error) {
	op := "exclude"
	if include {
		op = "include"
	}
	cn, changed, err := st.SetCertDNS(serial, include)
	if err != nil {
		return Msg{}, err
	}
	if !changed {
		return Msg{cn + " is already " + op + "d", false}, nil
	}
	st.Audit(actor, "cert_dns_"+op, "cn="+cn+" serial="+serial)
	return Msg{op + "d: " + cn, true}, nil
}

// SetCustomHosts replaces custom.hosts at path, a no-op when content is unchanged.
func SetCustomHosts(st *store.Store, actor, path, content string) (Msg, error) {
	if cur, _ := os.ReadFile(path); string(cur) == content {
		return Msg{"no change", false}, nil
	}
	if err := WriteAtomicHosts(path, []byte(content)); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "dns_custom_change", "")
	return Msg{"saved", true}, nil
}

// RotateLogs runs one rotation pass over the logs under dataDir.
func RotateLogs(st *store.Store, actor, dataDir string) (Msg, error) {
	if err := controller.RotateLogs(controller.LogPaths(filepath.Join(dataDir, "logs")), LoadLogConfig(st)); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "log_rotate", "")
	return Msg{"rotated", true}, nil
}

// checkPassword enforces auth.SecretOK, auditing a weak one accepted under
// auth.SecretYOLOEnv.
func checkPassword(st *store.Store, actor, target, password string) error {
	if auth.SecretOK(password) {
		return nil
	}
	if !auth.SecretYOLO() {
		return errors.New(auth.SecretErr("password"))
	}
	st.Audit(actor, "weak_password_accepted", "target="+target+" reason="+auth.SecretYOLOEnv+" is set")
	return nil
}

// AddUser creates an account.
func AddUser(st *store.Store, actor, name, password, role string) (Msg, error) {
	if !auth.ValidRole(role) {
		return Msg{}, fmt.Errorf("role must be admin, operator or readonly")
	}
	if err := checkPassword(st, actor, name, password); err != nil {
		return Msg{}, err
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		return Msg{}, err
	}
	if _, err := st.AddUser(name, h, role); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "user_add", "name="+name+" role="+role)
	return Msg{"user added: " + name + " (" + role + ")", true}, nil
}

// SetUserPassword replaces name's password, ending its sessions (schema trigger).
func SetUserPassword(st *store.Store, actor, name, password string) (Msg, error) {
	if err := checkPassword(st, actor, name, password); err != nil {
		return Msg{}, err
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		return Msg{}, err
	}
	if err := st.SetUserPassword(name, h); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "user_passwd", "name="+name)
	return Msg{"password updated: " + name, true}, nil
}

// DeleteUser removes an account and its sessions.
func DeleteUser(st *store.Store, actor, name string) (Msg, error) {
	if err := st.DeleteUser(name); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "user_del", "name="+name)
	return Msg{"deleted: " + name, true}, nil
}

// SetUserDisabled locks name out, or lets it back in.
func SetUserDisabled(st *store.Store, actor, name string, disabled bool) (Msg, error) {
	op := "enable"
	if disabled {
		op = "disable"
	}
	if err := st.SetUserDisabled(name, disabled); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "user_"+op, "name="+name)
	return Msg{op + "d: " + name, true}, nil
}

// TOTPEnrollment is a fresh 2FA secret: its otpauth URL and that URL as a QR PNG data URI.
type TOTPEnrollment struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
	QR     string `json:"qr"`
}

// EnrollTOTP gives name a new 2FA secret; issuer is the server CN.
func EnrollTOTP(st *store.Store, actor, name, issuer string) (TOTPEnrollment, error) {
	sec, err := auth.TOTPGenerateSecret()
	if err != nil {
		return TOTPEnrollment{}, err
	}
	url := auth.TOTPProvisioningURL(sec, name, issuer)
	qr, err := qrDataURI(url)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	if err := st.SetUserTOTP(name, sec); err != nil {
		return TOTPEnrollment{}, err
	}
	st.Audit(actor, "user_totp_enroll", "name="+name)
	return TOTPEnrollment{sec, url, qr}, nil
}

// DisableTOTP turns name's 2FA off.
func DisableTOTP(st *store.Store, actor, name string) (Msg, error) {
	if err := st.SetUserTOTP(name, ""); err != nil {
		return Msg{}, err
	}
	st.Audit(actor, "user_totp_off", "name="+name)
	return Msg{"2FA disabled: " + name, true}, nil
}

// Status is status and GET /api/status: the workers, their clients, cert
// counts, the bot and the host routing ovcp doesn't own.
type Status struct {
	Running          bool                       `json:"running"`
	Pid              int                        `json:"pid"`
	StartedAt        time.Time                  `json:"startedAt"`
	ServeStartedAt   time.Time                  `json:"serveStartedAt"` // zero: serve unreachable
	Error            string                     `json:"error,omitempty"`
	Clients          []controller.VPNClient     `json:"clients"`
	DNSRunning       bool                       `json:"dnsRunning"`
	DNSPid           int                        `json:"dnsPid"`
	DNSStartedAt     time.Time                  `json:"dnsStartedAt"`
	CertsTotal       int                        `json:"certsTotal"`
	CertsExpiring    int                        `json:"certsExpiring"`
	Telegram         *controller.TelegramStatus `json:"telegram,omitempty"` // nil: serve unreachable
	RoutingWarning   string                     `json:"routingWarning,omitempty"`
	UpstreamsEnabled bool                       `json:"upstreamsEnabled"`
	UpstreamDefault  string                     `json:"upstreamDefault,omitempty"`
	UpstreamWarning  string                     `json:"upstreamWarning,omitempty"`
}

// StatusSource is where Status reads live state: serve's own workers, or a
// running serve over the control socket.
type StatusSource interface {
	VPN() (controller.ControlResult, error)
	DNS() (controller.ControlResult, error)
	Clients() ([]controller.VPNClient, error)
	Telegram() (controller.TelegramStatus, error)
}

// BuildStatus reads src once. An unreachable serve leaves the dns and bot
// fields unasked: they travel the same socket and would fail the same way.
func BuildStatus(st *store.Store, p *pki.PKI, src StatusSource, upstreams bool) Status {
	out := Status{Clients: []controller.VPNClient{}}
	r, err := src.VPN()
	if err != nil {
		out.Error = err.Error()
	} else {
		out.ServeStartedAt = r.ServeStartedAt
		if r.Pid != 0 {
			out.Running, out.Pid, out.StartedAt = true, r.Pid, r.StartedAt
			if cl, err := src.Clients(); err != nil {
				out.Error = err.Error()
			} else if cl != nil {
				out.Clients = cl
			}
		}
		if d, err := src.DNS(); err == nil && d.Pid != 0 {
			out.DNSRunning, out.DNSPid, out.DNSStartedAt = true, d.Pid, d.StartedAt
		}
		if tg, err := src.Telegram(); err == nil {
			out.Telegram = &tg
		}
	}
	if certs, err := st.AllCerts(p); err == nil {
		out.CertsTotal, out.CertsExpiring = store.CertCounts(certs)
	}
	out.RoutingWarning = controller.RoutingPrereqsWarning(upstreams)
	out.UpstreamsEnabled = upstreams
	if upstreams {
		cfg := LoadUpstreamConfig(st)
		out.UpstreamDefault, out.UpstreamWarning = cfg.Default, upstream.Warning(cfg.Upstreams)
	}
	return out
}

// liveSource is StatusSource inside serve.
type liveSource struct{ s *Server }

func (l liveSource) VPN() (controller.ControlResult, error) {
	return controller.RunOp(l.s.VPN, "status", true, nil)
}
func (l liveSource) DNS() (controller.ControlResult, error) {
	if l.s.DNS == nil {
		return controller.ControlResult{}, nil
	}
	return controller.RunOp(l.s.DNS, "status", false, nil)
}
func (l liveSource) Clients() ([]controller.VPNClient, error) { return l.s.Mgmt.Status() }
func (l liveSource) Telegram() (controller.TelegramStatus, error) {
	return l.s.Telegram.Status(), nil
}

func (s *Server) handleStatus(c call, _ none) (Status, error) {
	return BuildStatus(s.Store, s.PKI, liveSource{s}, s.UpstreamsEnabled), nil
}
