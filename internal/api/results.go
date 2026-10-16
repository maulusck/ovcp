package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
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

// act encodes an action's result, or maps its error to a status: unknown
// target 404, anything else a 400 the caller can fix.
func act(w http.ResponseWriter) func(any, error) {
	return func(v any, err error) {
		switch {
		case err == nil:
			jsonOK(w, v)
		case errors.Is(err, ErrNotConnected), errors.Is(err, store.ErrNoActiveCert):
			jsonErr(w, 404, err.Error())
		default:
			jsonErr(w, 400, err.Error())
		}
	}
}
