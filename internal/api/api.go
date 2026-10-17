// Package api: HTTPS-only REST/JSON admin API + embedded UI.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"reflect"
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
	AfterVPNStart    func() error         // after a vpn start/restart, both transports: upstream re-apply, mgmt reattach
	PollInterval     time.Duration        // RunSampler's ticker; set from OVCP_STATUS_INTERVAL, same cadence OpenVPN writes its status file at
}

const (
	sessionCookie = "ovcp_session"
	csrfCookie    = "ovcp_csrf"
	csrfHeader    = "X-OVCP-CSRF"
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		if rt.role == "" {
			mux.HandleFunc(rt.pattern, func(w http.ResponseWriter, r *http.Request) { rt.serve(call{w, r, nil}) })
		} else {
			mux.Handle(rt.pattern, s.wrap(rt.role, rt.serve))
		}
	}
	if s.UI != nil {
		mux.Handle("/", spa(s.UI))
	}
	return requestLog(secureHeaders(mux))
}

// routes is the web API: every route, the role it needs ("" is public) and
// its handler. Handler serves it; TypeScript describes it to the web UI.
func (s *Server) routes() []route {
	rs := []route{
		handle("GET /healthz", "", s.handleHealthz),
		handle("POST /api/login", "", s.handleLogin),
		handle("POST /api/logout", auth.RoleReadonly, s.handleLogout),
		handle("GET /api/me", auth.RoleReadonly, s.handleMe),
		handle("GET /api/status", auth.RoleReadonly, s.handleStatus),
		handle("GET /api/stats", auth.RoleReadonly, s.handleStats),
		handle("GET /api/certs", auth.RoleReadonly, s.handleCertList),
		handle("GET /api/vpn/config", auth.RoleReadonly, s.handleVPNConfigGet),
		handle("GET /api/audit", auth.RoleReadonly, s.handleAudit),
		handle("GET /api/logs/download", auth.RoleOperator, s.handleLogsDownload),
		handle("GET /api/logs/config", auth.RoleReadonly, s.handleLogsConfigGet),
		handle("PUT /api/logs/config", auth.RoleAdmin, s.handleLogsConfigSet),
		handle("POST /api/logs/rotate", auth.RoleAdmin, s.handleLogsRotate),
		handle("GET /api/stats/config", auth.RoleReadonly, s.handleStatsConfigGet),
		handle("PUT /api/stats/config", auth.RoleAdmin, s.handleStatsConfigSet),
		handle("GET /api/debug", auth.RoleReadonly, s.handleDebugGet),
		handle("POST /api/debug", auth.RoleAdmin, s.handleDebugSet),
		handle("POST /api/clients/kill", auth.RoleOperator, s.handleKill),
		handle("POST /api/certs", auth.RoleOperator, s.handleIssue),
		handle("POST /api/certs/revoke", auth.RoleOperator, s.handleRevoke),
		handle("POST /api/certs/renew", auth.RoleAdmin, s.handleRenew),
		handle("POST /api/backup", auth.RoleAdmin, s.handleBackup),
		handle("POST /api/certs/export", auth.RoleOperator, s.handleExport),
		handle("PUT /api/vpn/config", auth.RoleAdmin, s.handleVPNConfigPut),
		handle("POST /api/vpn/config/preview", auth.RoleAdmin, s.handleVPNConfigPreview),
		handle("POST /api/vpn/{op}", auth.RoleAdmin, s.handleProc("vpn", s.VPN, true)),
		handle("POST /api/dns/{op}", auth.RoleAdmin, s.handleProc("dns", s.DNS, false)),
		handle("PATCH /api/certs/{serial}/dns", auth.RoleOperator, s.handleCertDNS),
		handle("GET /api/records", auth.RoleReadonly, s.handleRecords),
		handle("PUT /api/records/custom", auth.RoleAdmin, s.handleCustomHostsPut),
		handle("POST /api/records/custom/preview", auth.RoleAdmin, s.handleCustomHostsPreview),
		handle("GET /api/dns/config", auth.RoleReadonly, s.handleDNSConfigGet),
		handle("PUT /api/dns/config", auth.RoleAdmin, s.handleDNSConfigSet),
		handle("GET /api/upstreams", auth.RoleReadonly, s.handleUpstreamsGet),
		handle("POST /api/upstreams", auth.RoleAdmin, s.handleUpstreamAdd),
		handle("DELETE /api/upstreams/{id}", auth.RoleAdmin, s.handleUpstreamDelete),
		handle("PUT /api/upstreams/default", auth.RoleAdmin, s.handleUpstreamSetDefault),
		handle("PUT /api/upstreams/assign", auth.RoleAdmin, s.handleUpstreamAssign),
		handle("POST /api/upstreams/reconcile", auth.RoleAdmin, s.handleUpstreamReconcile),
		handle("GET /api/telegram/config", auth.RoleReadonly, s.handleTelegramConfigGet),
		handle("PUT /api/telegram/config", auth.RoleAdmin, s.handleTelegramConfigSet),
		handle("POST /api/telegram/{op}", auth.RoleAdmin, s.handleTelegramOp),
		handle("GET /api/certs/download", auth.RoleReadonly, s.handleCertDownload),
		handle("GET /api/users", auth.RoleAdmin, s.handleUsersList),
		handle("POST /api/users", auth.RoleAdmin, s.handleUserAdd),
		handle("DELETE /api/users/{name}", auth.RoleAdmin, s.handleUserDelete),
		handle("PATCH /api/users/{name}", auth.RoleAdmin, s.handleUserDisabled),
		handle("POST /api/users/{name}/password", auth.RoleAdmin, s.handleUserPassword),
		handle("POST /api/users/{name}/totp", auth.RoleAdmin, s.handleUserTOTPEnroll),
		handle("DELETE /api/users/{name}/totp", auth.RoleAdmin, s.handleUserTOTPOff),
	}
	for _, name := range controller.LogNames {
		rs = append(rs, handle("GET /api/logs/"+name, auth.RoleReadonly, s.logHandler(name+".log")))
	}
	return rs
}

// call is one request as a route's handler sees it; u is nil on a public route.
type call struct {
	w http.ResponseWriter
	r *http.Request
	u *store.User
}

// none is the input of a route that reads nothing.
type none struct{}

// route is one web API route: in is what its handler reads, out what it returns.
type route struct {
	pattern string
	role    auth.Role
	in, out reflect.Type
	serve   func(call)
}

// handle is a route whose handler reads In (a JSON body, or on GET the query,
// then the pattern's {wildcards}) and returns Out as JSON, a Download as its file.
func handle[In, Out any](pattern string, role auth.Role, h func(call, In) (Out, error)) route {
	in := reflect.TypeFor[In]()
	wild := wildcards(pattern, in)
	return route{pattern, role, in, reflect.TypeFor[Out](), func(c call) {
		var v In
		if err := readIn(c.r, wild, &v); err != nil {
			jsonErr(c.w, 400, "bad json")
			return
		}
		out, err := h(c, v)
		respond(c.w, out, err)
	}}
}

// wildcards are pattern's {names}; each must be a string field of in, by JSON name.
func wildcards(pattern string, in reflect.Type) []string {
	var names []string
	for seg := range strings.SplitSeq(pattern, "/") {
		name, ok := strings.CutPrefix(seg, "{")
		if !ok {
			continue
		}
		name = strings.TrimSuffix(name, "}")
		if f, ok := jsonField(in, name); !ok || f.Type.Kind() != reflect.String {
			panic(pattern + ": {" + name + "} is not a string field of " + in.String())
		}
		names = append(names, name)
	}
	return names
}

// readIn fills v from r. Query and path values go on top of the body, so a
// body can't override the path.
func readIn(r *http.Request, wild []string, v any) error {
	params := map[string]string{}
	if r.Method == http.MethodGet {
		for k, vs := range r.URL.Query() {
			params[k] = vs[0]
		}
	} else if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v); err != nil && err != io.EOF {
		return err // no body sets nothing
	}
	for _, k := range wild {
		params[k] = r.PathValue(k)
	}
	if len(params) == 0 {
		return nil
	}
	b, _ := json.Marshal(params)
	return json.Unmarshal(b, v)
}

// Download is a file response.
type Download struct {
	Name, Type string
	Write      func(io.Writer) error
}

// Patch is a request body applied onto the current T: omitted fields keep their value.
type Patch[T any] struct{ raw json.RawMessage }

func (p *Patch[T]) UnmarshalJSON(b []byte) error { p.raw = append(p.raw[:0], b...); return nil }

// Onto is cur with p's fields set.
func (p Patch[T]) Onto(cur T) (T, error) {
	if p.raw == nil {
		return cur, nil
	}
	return cur, json.Unmarshal(p.raw, &cur)
}

func (Patch[T]) patched() reflect.Type { return reflect.TypeFor[T]() }

// httpError is an error with its own status.
type httpError struct {
	code int
	error
}

func fail(code int, msg string) error { return httpError{code, errors.New(msg)} }

// respond writes a handler's result, or its error: an httpError's status, an
// unknown target 404, anything else a 400 the caller can fix.
func respond(w http.ResponseWriter, out any, err error) {
	var he httpError
	switch {
	case errors.As(err, &he):
		jsonErr(w, he.code, err.Error())
	case errors.Is(err, ErrNotConnected), errors.Is(err, store.ErrNoActiveCert), errors.Is(err, ErrNoUpstream):
		jsonErr(w, 404, err.Error())
	case err != nil:
		jsonErr(w, 400, err.Error())
	default:
		d, ok := out.(Download)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
			return
		}
		w.Header().Set("Content-Type", d.Type)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, d.Name))
		if err := d.Write(w); err != nil {
			jsonErr(w, 500, err.Error())
		}
	}
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

// wrap = session auth + CSRF (mutating verbs) + RBAC.
func (s *Server) wrap(required auth.Role, serve func(call)) http.Handler {
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
		serve(call{w, r, u})
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

func jsonErr(w http.ResponseWriter, code int, msg string) {
	if code >= 500 {
		slog.Warn("api error", "status", code, "msg", msg)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
func (s *Server) LoadConfig() ovpnconf.Config { return LoadConfig(s.Store) }

// LoadConfig is the persisted server config, defaults filled in.
func LoadConfig(st *store.Store) ovpnconf.Config {
	raw, _ := st.GetSetting("vpn_config")
	return ovpnconf.Load(raw)
}

// SaveConfig persists cfg to the settings store, not server.conf itself:
// pair it with cfg.WriteAtomic, or use SetVPNConfig.
func SaveConfig(st *store.Store, cfg ovpnconf.Config) error {
	raw, _ := json.Marshal(cfg)
	return st.SetSetting("vpn_config", string(raw))
}

// Preview is a would-be change: server.conf's diff lines, and the DNS leak
// warning the change would leave (the CLI also prints it to stderr).
type Preview struct {
	Diff    []string `json:"diff"`
	Changed bool     `json:"changed"`
	Warning string   `json:"warning,omitempty"`
}

// PreviewVPNConfig validates cfg and returns the change it makes.
func PreviewVPNConfig(st *store.Store, cfg ovpnconf.Config) (Preview, error) {
	if err := cfg.Validate(); err != nil {
		return Preview{}, err
	}
	cur := LoadConfig(st)
	diff := ovpnconf.Diff(cur.Render(), cfg.Render())
	return Preview{diff, len(diff) > 0, DNSLeakWarning(cfg, LoadDNSConfig(st))}, nil
}

// SetVPNConfig is every server-config change, CLI or API: PreviewVPNConfig,
// then persisted with server.conf, only when that diff isn't empty.
func SetVPNConfig(st *store.Store, actor, confPath string, cfg ovpnconf.Config) ([]string, error) {
	pv, err := PreviewVPNConfig(st, cfg)
	if err != nil || !pv.Changed {
		return nil, err
	}
	diff := pv.Diff
	if err := SaveConfig(st, cfg); err != nil {
		return nil, err
	}
	if err := cfg.WriteAtomic(confPath); err != nil {
		return nil, err
	}
	st.Audit(actor, "config_change", "")
	return diff, nil
}

// SetManagementClientAuth rewrites vpn_config's ManagementClientAuth flag
// and server.conf to match. vpn-config's own mutation — called by
// whichever feature needs the toggle (today: upstream's per-CN
// activation) instead of each caller reimplementing load/save/WriteAtomic.
func SetManagementClientAuth(s *store.Store, confPath string, active bool) error {
	cfg := LoadConfig(s)
	cfg.ManagementClientAuth = active
	if err := SaveConfig(s, cfg); err != nil {
		return err
	}
	return cfg.WriteAtomic(confPath)
}
