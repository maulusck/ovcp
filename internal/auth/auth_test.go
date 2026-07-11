package auth

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovcp/ovcp/internal/store"
)

func svc(t *testing.T) *Service {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return NewService(s)
}

func addUser(t *testing.T, a *Service, name, pass, role string) {
	h, err := HashPassword(pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Store.AddUser(name, h, role); err != nil {
		t.Fatal(err)
	}
}

func TestHashVerify(t *testing.T) {
	h, _ := HashPassword("hunter22")
	if !VerifyPassword("hunter22", h) || VerifyPassword("wrong", h) || VerifyPassword("x", "garbage") {
		t.Fatal("hash/verify broken")
	}
}

func TestLoginSession(t *testing.T) {
	a := svc(t)
	addUser(t, a, "admin", "hunter22", "admin")
	tok, u, err := a.Login("admin", "hunter22", "", "1.2.3.4")
	if err != nil || u.Role != "admin" || tok == "" {
		t.Fatalf("%v %v", u, err)
	}
	su, err := a.Validate(tok)
	if err != nil || su == nil || su.Username != "admin" {
		t.Fatalf("%v %v", su, err)
	}
	if !Role(su.Role).Can(RoleOperator) || Role("readonly").Can(RoleAdmin) {
		t.Fatal("rbac")
	}
	a.Logout(tok)
	if su, _ := a.Validate(tok); su != nil {
		t.Fatal("session survives logout")
	}
	if _, _, err := a.Login("admin", "nope", "", "1.2.3.4"); err != ErrBadCredentials {
		t.Fatal(err)
	}
	if _, _, err := a.Login("ghost", "x", "", "1.2.3.4"); err != ErrBadCredentials {
		t.Fatal(err)
	}
}

func TestDisabledUser(t *testing.T) {
	a := svc(t)
	addUser(t, a, "bob", "password1", "operator")
	tok, _, _ := a.Login("bob", "password1", "", "ip")
	a.Store.SetUserDisabled("bob", true)
	if su, _ := a.Validate(tok); su != nil {
		t.Fatal("disabled user session must die")
	}
	if _, _, err := a.Login("bob", "password1", "", "ip"); err != ErrBadCredentials {
		t.Fatal(err)
	}
}

func TestTOTPFlow(t *testing.T) {
	a := svc(t)
	addUser(t, a, "eve", "password1", "admin")
	sec, err := TOTPGenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	a.Store.SetUserTOTP("eve", sec)
	if _, _, err := a.Login("eve", "password1", "", "ip"); err != ErrTOTPRequired {
		t.Fatal(err)
	}
	now := time.Now()
	code, _ := totpCode(sec, now)
	a.now = func() time.Time { return now }
	if _, _, err := a.Login("eve", "password1", code, "ip"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Login("eve", "password1", "000000", "ip"); err != ErrBadCredentials {
		t.Fatal(err)
	}
}

func TestTOTPProvisioningURL(t *testing.T) {
	if u := TOTPProvisioningURL("SECRET", "eve", "vpn.example.com"); u !=
		"otpauth://totp/vpn.example.com:eve?secret=SECRET&issuer=vpn.example.com" {
		t.Fatalf("got %q", u)
	}
	if u := TOTPProvisioningURL("SECRET", "eve", ""); u !=
		"otpauth://totp/OVCP:eve?secret=SECRET&issuer=OVCP" {
		t.Fatalf("empty issuer should fall back to OVCP, got %q", u)
	}
}

func TestTOTPVector(t *testing.T) {
	// RFC 6238 test vector (SHA1): secret "12345678901234567890", T=59 → 94287082 → 6-digit 287082
	sec := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := totpCode(sec, time.Unix(59, 0))
	if err != nil || code != "287082" {
		t.Fatalf("code=%s err=%v", code, err)
	}
	if !TOTPVerify(sec, "287082", time.Unix(59, 0)) {
		t.Fatal("verify")
	}
}

func TestRateLimit(t *testing.T) {
	a := svc(t)
	addUser(t, a, "carl", "password1", "readonly")
	for i := 0; i < 5; i++ {
		a.Login("carl", "wrong", "", "9.9.9.9")
	}
	if _, _, err := a.Login("carl", "password1", "", "9.9.9.9"); err != ErrRateLimited {
		t.Fatal(err)
	}
	// different IP unaffected
	if _, _, err := a.Login("carl", "password1", "", "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	// window expiry unlocks
	a.Limiter.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if _, _, err := a.Login("carl", "password1", "", "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
}

// TestRateLimitAcrossIPs: Limiter alone buckets on username+ip, so a brute
// force spread across many source IPs never trips it. UserLimiter buckets on
// username alone and catches this.
func TestRateLimitAcrossIPs(t *testing.T) {
	a := svc(t)
	addUser(t, a, "dana", "password1", "readonly")
	for i := 0; i < 20; i++ {
		a.Login("dana", "wrong", "", fmt.Sprintf("10.0.0.%d", i))
	}
	if _, _, err := a.Login("dana", "password1", "", "10.0.0.99"); err != ErrRateLimited {
		t.Fatal(err)
	}
}

// TestLimiterSweepBoundsMap: a key that fails once and is never rechecked
// must not linger in the map forever — Fail sweeps expired entries so the
// map stays bounded to the current window instead of growing for the life
// of the process.
func TestLimiterSweepBoundsMap(t *testing.T) {
	l := NewLimiter(5, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 1000; i++ {
		l.Fail(fmt.Sprintf("stale-key-%d", i))
	}
	if len(l.failures) != 1000 {
		t.Fatalf("expected 1000 fresh entries, got %d", len(l.failures))
	}

	now = now.Add(2 * time.Minute) // past the window
	l.Fail("fresh-key")
	if len(l.failures) != 1 {
		t.Fatalf("expected the sweep to drop all stale entries, got %d left", len(l.failures))
	}
}
