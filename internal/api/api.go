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
)

type Server struct {
	Store         *store.Store
	Auth          *auth.Service
	PKI           *pki.PKI
	Mgmt          *controller.Client
	VPN           controller.Lifecycle
	DataDir       string         // data directory root (backup source)
	ConfigPath    string         // rendered server.conf
	TLSCrypt      string         // tls-crypt key path
	ServerCert    string         // openvpn server cert path (renew-server target)
	ServerKey     string         // openvpn server key path (renew-server target)
	DefaultRemote string         // OVCP_SERVER_CN / server cert CN; default client remote
	Version       string         // build version, for the status export
	UI            fs.FS          // built frontend; nil = API only
	DebugLevel    *slog.LevelVar // shared with `ovcp debug on|off`'s control-socket handler
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
	mux.Handle("GET /api/certs", s.wrap(auth.RoleReadonly, s.handleCertList))
	mux.Handle("GET /api/config", s.wrap(auth.RoleReadonly, s.handleConfigGet))
	mux.Handle("GET /api/audit", s.wrap(auth.RoleReadonly, s.handleAudit))
	mux.Handle("GET /api/logs/openvpn", s.wrap(auth.RoleReadonly, s.logHandler("openvpn.log")))
	mux.Handle("GET /api/logs/ovcp", s.wrap(auth.RoleReadonly, s.logHandler("ovcp.log")))
	mux.Handle("GET /api/logs/download", s.wrap(auth.RoleReadonly, s.handleLogsDownload))
	mux.Handle("GET /api/debug", s.wrap(auth.RoleReadonly, s.handleDebugGet))
	mux.Handle("POST /api/debug", s.wrap(auth.RoleAdmin, s.handleDebugSet))
	mux.Handle("POST /api/clients/kill", s.wrap(auth.RoleOperator, s.handleKill))
	mux.Handle("POST /api/certs", s.wrap(auth.RoleOperator, s.handleIssue))
	mux.Handle("POST /api/certs/revoke", s.wrap(auth.RoleOperator, s.handleRevoke))
	mux.Handle("POST /api/certs/renew-server", s.wrap(auth.RoleAdmin, s.handleRenewServer))
	mux.Handle("POST /api/backup", s.wrap(auth.RoleAdmin, s.handleBackup))
	mux.Handle("POST /api/certs/export", s.wrap(auth.RoleOperator, s.handleExport))
	mux.Handle("PUT /api/config", s.wrap(auth.RoleAdmin, s.handleConfigPut))
	mux.Handle("POST /api/vpn/{op}", s.wrap(auth.RoleAdmin, s.handleVPN))
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

// requestLog is debug-only noise: every request, its status and latency.
// State-changing actions already land in the persistent audit log (see
// Store.Audit calls in handlers.go); this is for live troubleshooting.
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Debug("http", "method", r.Method, "path", r.URL.Path,
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
	raw, _ := s.Store.GetSetting("server_config")
	return ovpnconf.Load(raw)
}

func (s *Server) saveConfig(cfg ovpnconf.Config) error {
	raw, _ := json.Marshal(cfg)
	return s.Store.SetSetting("server_config", string(raw))
}
