// Package api: HTTPS-only REST/JSON admin API + embedded UI.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ovcp/ovcp/internal/auth"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/ovpnconf"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/telegram"
)

type Server struct {
	Store            *store.Store
	Auth             *auth.Service
	PKI              *pki.PKI
	Mgmt             *controller.Client
	VPN              controller.Lifecycle
	Telegram         *telegram.Poller
	DataDir          string               // data directory root (backup source)
	ConfigPath       string               // rendered server.conf
	TLSCrypt         string               // tls-crypt key path
	ServerCert       string               // openvpn server cert path (certificate renew target)
	ServerKey        string               // openvpn server key path (certificate renew target)
	DefaultRemote    func() string        // OVCP_SERVER_CN / server cert CN; live, not cached — a `certificate renew -cn` rename takes effect on the next call, no restart
	Version          string               // build version, for the status export
	BuildTarget      string               // Makefile TARGET/Containerfile arch this binary was built for, e.g. "host", "arm64-musl"
	OpenVPNVersion   string               // "" if openvpn isn't on PATH
	OpenVPNPath      string               // "" if openvpn isn't on PATH
	DNS              controller.Lifecycle // nil until dnsmasq is found on PATH (Records tab gate)
	DnsmasqVersion   string               // "" if dnsmasq isn't on PATH
	DnsmasqPath      string               // "" if dnsmasq isn't on PATH
	UpstreamsEnabled bool                 // nft found and not OVCP_UPSTREAMS_ENABLED=false (Upstreams tab gate)
	NftVersion       string               // "" if nft isn't on PATH
	NftPath          string               // "" if nft isn't on PATH
	CertsHostsPath   string               // Records tab: machine-owned certs.hosts, regenerated wholesale
	CustomHostsPath  string               // Records tab: user-authored custom.hosts, edited as one blob
	UI               fs.FS                // built frontend; nil = API only
	DebugLevel       *slog.LevelVar       // shared with `ovcp debug on|off`'s control-socket handler
	PollInterval     time.Duration        // RunSampler's ticker; set from OVCP_STATUS_INTERVAL, same cadence OpenVPN writes its status file at
}

const (
	sessionCookie = "ovcp_session"
	csrfCookie    = "ovcp_csrf"
	csrfHeader    = "X-OVCP-CSRF"
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// public
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	// authenticated
	mux.Handle("POST /api/logout", s.wrap(auth.RoleReadonly, s.handleLogout))
	mux.Handle("GET /api/me", s.wrap(auth.RoleReadonly, s.handleMe))
	mux.Handle("GET /api/status", s.wrap(auth.RoleReadonly, s.handleStatus))
	mux.Handle("GET /api/stats", s.wrap(auth.RoleReadonly, s.handleStats))
	mux.Handle("GET /api/certs", s.wrap(auth.RoleReadonly, s.handleCertList))
	mux.Handle("GET /api/vpn/config", s.wrap(auth.RoleReadonly, s.handleVPNConfigGet))
	mux.Handle("GET /api/audit", s.wrap(auth.RoleReadonly, s.handleAudit))
	for _, name := range controller.LogNames {
		mux.Handle("GET /api/logs/"+name, s.wrap(auth.RoleReadonly, s.logHandler(name+".log")))
	}
	mux.Handle("GET /api/logs/download", s.wrap(auth.RoleOperator, s.handleLogsDownload))
	mux.Handle("GET /api/logs/config", s.wrap(auth.RoleReadonly, s.handleLogsConfigGet))
	mux.Handle("PUT /api/logs/config", s.wrap(auth.RoleAdmin, s.handleLogsConfigSet))
	mux.Handle("POST /api/logs/rotate", s.wrap(auth.RoleAdmin, s.handleLogsRotate))
	mux.Handle("GET /api/stats/config", s.wrap(auth.RoleReadonly, s.handleStatsConfigGet))
	mux.Handle("PUT /api/stats/config", s.wrap(auth.RoleAdmin, s.handleStatsConfigSet))
	mux.Handle("GET /api/debug", s.wrap(auth.RoleReadonly, s.handleDebugGet))
	mux.Handle("POST /api/debug", s.wrap(auth.RoleAdmin, s.handleDebugSet))
	mux.Handle("POST /api/clients/kill", s.wrap(auth.RoleOperator, s.handleKill))
	mux.Handle("POST /api/certs", s.wrap(auth.RoleOperator, s.handleIssue))
	mux.Handle("POST /api/certs/revoke", s.wrap(auth.RoleOperator, s.handleRevoke))
	mux.Handle("POST /api/certs/renew", s.wrap(auth.RoleAdmin, s.handleRenew))
	mux.Handle("POST /api/backup", s.wrap(auth.RoleAdmin, s.handleBackup))
	mux.Handle("POST /api/certs/export", s.wrap(auth.RoleOperator, s.handleExport))
	mux.Handle("PUT /api/vpn/config", s.wrap(auth.RoleAdmin, s.handleVPNConfigPut))
	mux.Handle("POST /api/vpn/config/preview", s.wrap(auth.RoleAdmin, s.handleVPNConfigPreview))
	mux.Handle("POST /api/vpn/{op}", s.wrap(auth.RoleAdmin, s.handleProc("vpn", s.VPN, true)))
	mux.Handle("POST /api/dns/{op}", s.wrap(auth.RoleAdmin, s.handleProc("dns", s.DNS, false)))
	mux.Handle("PATCH /api/certs/{serial}/dns", s.wrap(auth.RoleOperator, s.handleCertDNS))
	mux.Handle("GET /api/dns/custom", s.wrap(auth.RoleReadonly, s.handleCustomHostsGet))
	mux.Handle("PUT /api/dns/custom", s.wrap(auth.RoleAdmin, s.handleCustomHostsPut))
	mux.Handle("POST /api/dns/custom/preview", s.wrap(auth.RoleAdmin, s.handleCustomHostsPreview))
	mux.Handle("GET /api/dns/config", s.wrap(auth.RoleReadonly, s.handleDNSConfigGet))
	mux.Handle("PUT /api/dns/config", s.wrap(auth.RoleAdmin, s.handleDNSConfigSet))
	mux.Handle("GET /api/upstreams", s.wrap(auth.RoleReadonly, s.handleUpstreamsGet))
	mux.Handle("POST /api/upstreams", s.wrap(auth.RoleAdmin, s.handleUpstreamAdd))
	mux.Handle("DELETE /api/upstreams/{id}", s.wrap(auth.RoleAdmin, s.handleUpstreamDelete))
	mux.Handle("PUT /api/upstreams/default", s.wrap(auth.RoleAdmin, s.handleUpstreamSetDefault))
	mux.Handle("PUT /api/upstreams/assign", s.wrap(auth.RoleAdmin, s.handleUpstreamAssign))
	mux.Handle("POST /api/upstreams/reconcile", s.wrap(auth.RoleAdmin, s.handleUpstreamReconcile))
	mux.Handle("GET /api/telegram/config", s.wrap(auth.RoleReadonly, s.handleTelegramConfigGet))
	mux.Handle("PUT /api/telegram/config", s.wrap(auth.RoleAdmin, s.handleTelegramConfigSet))
	mux.Handle("POST /api/telegram/{op}", s.wrap(auth.RoleAdmin, s.handleTelegramOp))
	mux.Handle("GET /api/certs/download", s.wrap(auth.RoleReadonly, s.handleCertDownload))
	mux.Handle("GET /api/users", s.wrap(auth.RoleAdmin, s.handleUsersList))
	mux.Handle("POST /api/users", s.wrap(auth.RoleAdmin, s.handleUserAdd))
	mux.Handle("DELETE /api/users/{name}", s.wrap(auth.RoleAdmin, s.handleUserDelete))
	mux.Handle("PATCH /api/users/{name}", s.wrap(auth.RoleAdmin, s.handleUserDisabled))
	mux.Handle("POST /api/users/{name}/password", s.wrap(auth.RoleAdmin, s.handleUserPassword))
	mux.Handle("POST /api/users/{name}/totp", s.wrap(auth.RoleAdmin, s.handleUserTOTPEnroll))
	mux.Handle("DELETE /api/users/{name}/totp", s.wrap(auth.RoleAdmin, s.handleUserTOTPOff))
	if s.UI != nil {
		mux.Handle("/", spa(s.UI))
	}
	return requestLog(secureHeaders(mux))
}

// requestLog: Debug for 2xx/4xx noise, Warn for 5xx so server faults are
// visible without debug logging on (state changes are audited separately).
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		level := slog.LevelDebug
		if sw.status >= 500 {
			level = slog.LevelWarn
		}
		slog.Log(r.Context(), level, "http", "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "remote", clientIP(r), "dur", time.Since(start))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type handler func(w http.ResponseWriter, r *http.Request, u *store.User)

// wrap = session auth + CSRF (mutating verbs) + RBAC.
func (s *Server) wrap(required auth.Role, h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			jsonErr(w, 401, "not authenticated")
			return
		}
		u, err := s.Auth.Validate(c.Value)
		if err != nil || u == nil {
			jsonErr(w, 401, "not authenticated")
			return
		}
		if r.Method != http.MethodGet {
			cc, err := r.Cookie(csrfCookie)
			if err != nil || cc.Value == "" || r.Header.Get(csrfHeader) != cc.Value {
				jsonErr(w, 403, "csrf check failed")
				return
			}
		}
		if !auth.Role(u.Role).Can(required) {
			jsonErr(w, 403, "insufficient role")
			return
		}
		h(w, r, u)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

// spa serves the embedded UI, falling back to index.html for client routes.
func spa(ui fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(ui, p); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// --- helpers ---

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	if code >= 500 {
		slog.Warn("api error", "status", code, "msg", msg)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(r *http.Request, v any) bool {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v) == nil
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// LoadConfig reads persisted server config (settings key) or defaults.
func (s *Server) LoadConfig() ovpnconf.Config {
	raw, _ := s.Store.GetSetting("vpn_config")
	return ovpnconf.Load(raw)
}

// SaveConfig persists cfg to the settings store (not server.conf itself —
// pair with cfg.WriteAtomic for that). Exported so callers outside this
// package (e.g. cmd/ovcp's boot sequence) reuse it instead of re-marshaling.
func (s *Server) SaveConfig(cfg ovpnconf.Config) error {
	raw, _ := json.Marshal(cfg)
	return s.Store.SetSetting("vpn_config", string(raw))
}

// SetManagementClientAuth rewrites vpn_config's ManagementClientAuth flag
// and server.conf to match. vpn-config's own mutation — called by
// whichever feature needs the toggle (today: upstream's per-CN
// activation) instead of each caller reimplementing load/save/WriteAtomic.
func SetManagementClientAuth(s *store.Store, confPath string, active bool) error {
	raw, _ := s.GetSetting("vpn_config")
	cfg := ovpnconf.Load(raw)
	cfg.ManagementClientAuth = active
	enc, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := s.SetSetting("vpn_config", string(enc)); err != nil {
		return err
	}
	return cfg.WriteAtomic(confPath)
}
