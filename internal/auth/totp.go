package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"sync"
	"time"
)

// --- TOTP: RFC 6238, SHA1, 6 digits, 30s step, ±1 step skew ---

func TOTPGenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPProvisioningURL → otpauth:// URI for authenticator apps. issuer keeps
// "OVCP" so enrollments stay searchable, with the FQDN appended so multiple
// deployments stay distinguishable: "OVCP (vpn.example.com)".
func TOTPProvisioningURL(secret, account, fqdn string) string {
	issuer := "OVCP"
	if fqdn != "" {
		issuer = "OVCP (" + fqdn + ")"
	}
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer))
}

func totpCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix())/30)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000), nil
}

func TOTPVerify(secret, code string, now time.Time) bool {
	for _, skew := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		want, err := totpCode(secret, now.Add(skew))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// --- Limiter: lock a key after N failures within the window ---

type Limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string]entry
	now      func() time.Time
}

type entry struct {
	count int
	first time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, failures: map[string]entry{}, now: time.Now}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[key]
	if !ok {
		return true
	}
	if l.now().Sub(e.first) > l.window {
		delete(l.failures, key)
		return true
	}
	return e.count < l.max
}

// Fail also sweeps expired entries: it's the only method that grows the
// map, so this is what keeps a key that fails once and is never rechecked
// from lingering forever (unbounded growth otherwise).
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, e := range l.failures {
		if now.Sub(e.first) > l.window {
			delete(l.failures, k)
		}
	}
	e, ok := l.failures[key]
	if !ok || now.Sub(e.first) > l.window {
		l.failures[key] = entry{count: 1, first: now}
		return
	}
	e.count++
	l.failures[key] = e
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
