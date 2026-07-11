// Package auth: local users, argon2id, sessions, TOTP, rate-limit.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ovcp/ovcp/internal/store"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleReadonly Role = "readonly"
)

// Can implements the RBAC matrix: readonly ⊂ operator ⊂ admin.
func (r Role) Can(required Role) bool {
	rank := map[Role]int{RoleReadonly: 0, RoleOperator: 1, RoleAdmin: 2}
	return rank[r] >= rank[required]
}

func ValidRole(s string) bool {
	switch Role(s) {
	case RoleAdmin, RoleOperator, RoleReadonly:
		return true
	}
	return false
}

var (
	ErrBadCredentials = errors.New("auth: invalid credentials")
	ErrTOTPRequired   = errors.New("auth: totp code required")
	ErrRateLimited    = errors.New("auth: too many failed attempts, try later")
)

const (
	hTime    = 2
	hMemKiB  = 64 * 1024
	hThreads = 4
	hKeyLen  = 32

	SessionTTL = 12 * time.Hour
)

// HashPassword → PHC string: $argon2id$v=19$m=..,t=..,p=..$salt$hash
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(password), salt, hTime, hMemKiB, hThreads, hKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		hMemKiB, hTime, hThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h)), nil
}

func VerifyPassword(password, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var par uint8
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &m, &t, &par); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(p[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, par, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Service wires store + limiter. One instance per process.
type Service struct {
	Store *store.Store
	// Limiter buckets on username+ip (tight): stops one source hammering one account.
	Limiter *Limiter
	// UserLimiter buckets on username alone (looser): stops the same account
	// being hammered from many source IPs, which Limiter can't see.
	UserLimiter *Limiter
	now         func() time.Time // test seam
}

func NewService(s *store.Store) *Service {
	return &Service{
		Store:       s,
		Limiter:     NewLimiter(5, 15*time.Minute),
		UserLimiter: NewLimiter(20, 15*time.Minute),
		now:         time.Now,
	}
}

// Login validates credentials (+TOTP when enrolled) and mints a session token.
// key is the rate-limit bucket (username+ip).
func (a *Service) Login(username, password, totpCode, ip string) (token string, u *store.User, err error) {
	key := username + "|" + ip
	if !a.Limiter.Allow(key) || !a.UserLimiter.Allow(username) {
		return "", nil, ErrRateLimited
	}
	fail := func() (string, *store.User, error) {
		a.Limiter.Fail(key)
		a.UserLimiter.Fail(username)
		a.Store.Audit(username, "login_fail", "ip="+ip)
		return "", nil, ErrBadCredentials
	}
	u, gerr := a.Store.GetUser(username)
	if gerr != nil || u.Disabled {
		// burn time to reduce user-enumeration signal
		VerifyPassword(password, "$argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		return fail()
	}
	if !VerifyPassword(password, u.PassHash) {
		return fail()
	}
	if u.TOTPSecret != "" {
		if totpCode == "" {
			return "", nil, ErrTOTPRequired
		}
		if !TOTPVerify(u.TOTPSecret, totpCode, a.now()) {
			return fail()
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	if err := a.Store.AddSession(hashToken(token), u.ID, SessionTTL); err != nil {
		return "", nil, err
	}
	a.Limiter.Reset(key)
	a.UserLimiter.Reset(username)
	a.Store.Audit(username, "login", "ip="+ip)
	return token, u, nil
}

// Validate resolves a session token; nil user = unauthenticated.
func (a *Service) Validate(token string) (*store.User, error) {
	if token == "" {
		return nil, nil
	}
	return a.Store.SessionUser(hashToken(token))
}

func (a *Service) Logout(token string) error {
	return a.Store.DeleteSession(hashToken(token))
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}
