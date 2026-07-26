package telegram

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
)

const (
	keyToken = "telegram_bot_token"
	keyAdmin = "telegram_admin"
	keyChat  = "telegram_chat_id" // learned from the first authorized message
)

// sensitive audit actions worth a push notification.
var notifyActions = map[string]bool{
	"revoke": true, "user_add": true, "user_del": true, "ca_rotate": true, "renew_ca": true,
}

// unauthorizedBlockThreshold: an unrecognized sender gets this many 403s,
// then goes silent for the process's life, capping the sendMessage burst a spam wave would trigger.
// ponytail: unbounded in-memory map, no eviction/TTL; add one if abused.
const unauthorizedBlockThreshold = 3

type Poller struct {
	s    *store.Store
	p    *pki.PKI
	vpn  controller.Lifecycle
	dns  controller.Lifecycle
	mgmt *controller.Client

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool

	abuseMu  sync.Mutex
	attempts map[int64]int
	blocked  map[int64]bool
}

func New(s *store.Store, p *pki.PKI, vpn, dns controller.Lifecycle, mgmt *controller.Client) *Poller {
	return &Poller{s: s, p: p, vpn: vpn, dns: dns, mgmt: mgmt}
}

// isNumericID reports whether s is a Telegram numeric id rather than a
// @username — shared by matches, chatID and ConfigStatus.
func isNumericID(s string) bool {
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

// SetToken validates token against getMe, then saves it — independently of
// SetAdmin, so changing one never requires re-supplying the other. Forgets
// any previously-learned chat only if the token actually changed — a bare
// re-save (e.g. the web UI's own form) must not silently re-link the chat.
func SetToken(s *store.Store, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := newBot(token).getMe(ctx); err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	old, _ := s.GetSetting(keyToken)
	if err := s.SetSetting(keyToken, token); err != nil {
		return err
	}
	slog.Info("telegram: token updated")
	if token == old {
		return nil
	}
	return s.SetSetting(keyChat, "")
}

// SetAdmin saves the admin identity — forgets any previously-learned chat
// only if the admin actually changed, same reasoning as SetToken.
func SetAdmin(s *store.Store, admin string) error {
	old, _ := s.GetSetting(keyAdmin)
	if err := s.SetSetting(keyAdmin, admin); err != nil {
		return err
	}
	slog.Info("telegram: admin updated", "admin", admin)
	if admin == old {
		return nil
	}
	warnOldAdmin(s, old, admin)
	return s.SetSetting(keyChat, "")
}

// warnOldAdmin best-effort notifies the chat being replaced, before it's
// unlinked — the one line of defense against a hijacked admin reassignment.
// Names newAdmin (whatever form it was set in, numeric id or @username) so
// the outgoing admin knows who to investigate if this wasn't them.
func warnOldAdmin(s *store.Store, old, newAdmin string) {
	token, _ := s.GetSetting(keyToken)
	chatID, err := chatIDFor(s, old)
	if old == "" || token == "" || err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	text := fmt.Sprintf("🚨 admin identity changed to %s — if this wasn't you, investigate now.", newAdmin)
	newBot(token).sendMessage(ctx, chatID, text, nil)
}

// ConfigStatus reads token/admin presence directly from the store — no
// running Poller needed, the same shape (*Poller).Status serves over the
// control socket. Shared by that and `ovcp telegram config get`.
func ConfigStatus(s *store.Store) controller.TelegramStatus {
	token, _ := s.GetSetting(keyToken)
	admin, _ := s.GetSetting(keyAdmin)
	chat, _ := s.GetSetting(keyChat)
	return controller.TelegramStatus{
		TokenSet: token != "", Admin: admin,
		ChatLinked: isNumericID(admin) || chat != "",
	}
}

func (p *Poller) Status() controller.TelegramStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := ConfigStatus(p.s)
	st.Running = p.running
	return st
}

// acquireOp claims mu for one Start/Stop/Restart — held for the op's real
// duration, so a concurrent call only ever gets in once this one has
// genuinely finished, not after a guessed delay.
func (p *Poller) acquireOp() error {
	if !p.mu.TryLock() {
		return fmt.Errorf("telegram: %w", controller.ErrBusy)
	}
	return nil
}

func (p *Poller) Start() error {
	if err := p.acquireOp(); err != nil {
		return err
	}
	defer p.mu.Unlock()
	return p.start()
}

func (p *Poller) Stop() error {
	if err := p.acquireOp(); err != nil {
		return err
	}
	defer p.mu.Unlock()
	return p.stop()
}

func (p *Poller) Restart() error {
	if err := p.acquireOp(); err != nil {
		return err
	}
	defer p.mu.Unlock()
	p.stop()
	return p.start()
}

// start/stop assume p.mu is already held (mirrors Supervisor's opMu/start/stop split).
func (p *Poller) start() error {
	if p.running {
		return nil
	}
	token, _ := p.s.GetSetting(keyToken)
	admin, _ := p.s.GetSetting(keyAdmin)
	if token == "" || admin == "" {
		return fmt.Errorf("telegram: token/admin not configured")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running = true
	go p.loop(ctx, newBot(token), admin)
	slog.Info("telegram: poller started")
	return nil
}

func (p *Poller) stop() error {
	if !p.running {
		return nil
	}
	p.cancel()
	p.running = false
	slog.Info("telegram: poller stopped")
	return nil
}

// getUpdatesWarnThreshold: consecutive failures before escalating Debug to
// Warn. Never gives up retrying — a failed poll only costs the next 5s wait.
const getUpdatesWarnThreshold = 3

func (p *Poller) loop(ctx context.Context, b *bot, admin string) {
	b.setMyCommands(ctx, botCommands) // best-effort: a stale/missing menu never blocks polling
	var offset int64
	var failStreak int
	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := b.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failStreak++
			if failStreak >= getUpdatesWarnThreshold {
				slog.Warn("telegram: getUpdates failing repeatedly", "streak", failStreak, "err", err)
			} else {
				slog.Debug("telegram: getUpdates failed", "err", err)
			}
			time.Sleep(5 * time.Second) // ponytail: fixed backoff, fine for a single-admin poller
			continue
		}
		failStreak = 0
		for _, u := range updates {
			offset = u.UpdateID + 1
			p.handle(ctx, b, admin, u)
		}
	}
}

// shouldReplyUnauthorized tracks id's attempts and reports whether this one
// still gets a 403 reply; past unauthorizedBlockThreshold it's blocked for good.
func (p *Poller) shouldReplyUnauthorized(id int64, username string) bool {
	p.abuseMu.Lock()
	defer p.abuseMu.Unlock()
	if p.blocked == nil {
		p.blocked = map[int64]bool{}
		p.attempts = map[int64]int{}
	}
	if p.blocked[id] {
		return false
	}
	p.attempts[id]++
	if p.attempts[id] >= unauthorizedBlockThreshold {
		p.blocked[id] = true
		delete(p.attempts, id)
		slog.Warn("telegram: blocking unauthorized sender after repeated attempts",
			"id", id, "username", username, "threshold", unauthorizedBlockThreshold)
		return true // this message still gets one final reply, explaining why
	}
	slog.Debug("telegram: unauthorized sender rejected", "id", id, "username", username)
	return true
}

func matches(admin string, u user) bool {
	if id, err := strconv.ParseInt(admin, 10, 64); err == nil {
		return u.ID == id
	}
	return u.Username != "" && strings.EqualFold(strings.TrimPrefix(admin, "@"), u.Username)
}

func senderOf(u update) (user, int64) {
	if u.Callback != nil {
		return u.Callback.From, u.Callback.Message.Chat.ID
	}
	if u.Message != nil {
		return u.Message.From, u.Message.Chat.ID
	}
	return user{}, 0
}

func (p *Poller) handle(ctx context.Context, b *bot, admin string, u update) {
	from, chatID := senderOf(u)
	if from.ID == 0 {
		return
	}
	if !matches(admin, from) {
		if p.shouldReplyUnauthorized(from.ID, from.Username) && u.Message != nil {
			b.sendMessage(ctx, chatID, "🚫 403: not my admin.", nil)
		}
		return
	}
	if err := p.s.SetSetting(keyChat, strconv.FormatInt(chatID, 10)); err != nil {
		slog.Warn("telegram: failed to persist linked chat id", "err", err)
	}

	if u.Callback != nil {
		b.answerCallback(ctx, u.Callback.ID)
		slog.Debug("telegram: authorized request", "id", from.ID, "chat", chatID, "data", u.Callback.Data)
		p.handleCommand(ctx, b, chatID, u.Callback.Data)
		return
	}
	if u.Message != nil {
		cmd := strings.TrimSpace(u.Message.Text)
		slog.Debug("telegram: authorized request", "id", from.ID, "chat", chatID, "text", cmd)
		p.handleCommand(ctx, b, chatID, cmd)
	}
}

const (
	cmdStatus     = "status"
	cmdMenu       = "menu"
	cmdStart      = "start"
	cmdStop       = "stop"
	cmdRestart    = "restart"
	cmdReconnect  = "reconnect"
	cmdDNS        = "dns"
	cmdDNSStart   = "dns_start"
	cmdDNSStop    = "dns_stop"
	cmdDNSRestart = "dns_restart"
	cmdCerts      = "certs"
)

// Reply-keyboard labels double as the tap-back text (no callback_data on a
// reply keyboard), so handleCommand's switch matches them directly, like the slash form.
const (
	lblStart     = "▶ start"
	lblStop      = "⏹ stop"
	lblRestart   = "🔄 restart"
	lblReconnect = "🔌 reconnect"
	lblStatus    = "📊 status"
	lblDNS       = "🌐 dns"
	lblCerts     = "📜 certs"
)

// opsKeyboard is the persistent reply keyboard /menu (and /start) hands out.
// Status/dns/certs get their own wide rows: they're what you check, not act on directly.
var opsKeyboard = rkb(
	[]string{lblStart, lblStop},
	[]string{lblRestart, lblReconnect},
	[]string{lblStatus},
	[]string{lblDNS},
	[]string{lblCerts},
)

// dnsKeyboard: dns's own start/stop/restart, handed out under /dns — no
// config surface from the bot, same boundary as vpn.
var dnsKeyboard = kb([]inlineButton{btn("start", cmdDNSStart), btn("stop", cmdDNSStop), btn("restart", cmdDNSRestart)})

// botCommands drives Telegram's "/" autocomplete menu (registered via
// setMyCommands on every start), using the same consts handleCommand
// dispatches on, so the menu can't list something unhandled.
var botCommands = []botCommand{
	{cmdStatus, "full status: vpn, dns, certs"},
	{cmdMenu, "hand out the control-panel keyboard"},
	{cmdStart, "bring the tunnel up"},
	{cmdStop, "bring it down (asks first)"},
	{cmdRestart, "full bounce (asks first)"},
	{cmdReconnect, "SIGUSR1: renegotiate, no restart"},
	{cmdDNS, "dnsmasq status + start|stop|restart"},
	{cmdCerts, "list certs: expiring, expired, revoked, valid"},
}

type botCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

func (p *Poller) handleCommand(ctx context.Context, b *bot, chatID int64, cmd string) {
	// "/dns start|stop|restart" folds onto the same tokens the inline
	// keyboard's callback_data already uses — one entry point, not two.
	if arg, ok := strings.CutPrefix(cmd, "/"+cmdDNS+" "); ok {
		cmd = "dns_" + strings.TrimSpace(arg)
	}
	switch cmd {
	case "/" + cmdStatus, cmdStatus, lblStatus:
		b.sendMessage(ctx, chatID, p.statusText(), nil)
	case "/" + cmdMenu, cmdMenu:
		b.sendMessage(ctx, chatID, menuText, opsKeyboard)
	case "/" + cmdStart, cmdStart, lblStart: // also Telegram's own greeting trigger — matches unix `start` semantics, no confirmation needed
		b.sendMessage(ctx, chatID, resultText("🟢 up.", p.vpn.Start()), nil)
	case "/" + cmdStop, cmdStop, lblStop:
		b.sendMessage(ctx, chatID, "stop the tunnel? every client drops.", kb(
			[]inlineButton{btn("yes, stop", "vpn_stop_confirm"), btn("cancel", "cancel")}))
	case "/" + cmdRestart, cmdRestart, lblRestart:
		b.sendMessage(ctx, chatID, "restart? full bounce, clients briefly drop.", kb(
			[]inlineButton{btn("yes, restart", "vpn_restart_confirm"), btn("cancel", "cancel")}))
	case "/" + cmdReconnect, cmdReconnect, lblReconnect:
		b.sendMessage(ctx, chatID, resultText("🔌 reconnect signal sent (SIGUSR1).", p.vpn.Reconnect()), nil)
	case "vpn_stop_confirm":
		b.sendMessage(ctx, chatID, resultText("🔴 down.", p.vpn.Stop()), nil)
	case "vpn_restart_confirm":
		b.sendMessage(ctx, chatID, resultText("🔄 restarted.", p.vpn.Restart()), nil)
	case "/" + cmdDNS, cmdDNS, lblDNS:
		b.sendMessage(ctx, chatID, p.dnsLine(), dnsKeyboard)
	case "/" + cmdCerts, cmdCerts, lblCerts:
		b.sendMessage(ctx, chatID, p.certsText(), nil)
	case cmdDNSStart:
		b.sendMessage(ctx, chatID, resultText("🟢 dns up.", p.dns.Start()), nil)
	case cmdDNSStop:
		b.sendMessage(ctx, chatID, "stop dns? clients stop resolving internal names.", kb(
			[]inlineButton{btn("yes, stop", "dns_stop_confirm"), btn("cancel", "cancel")}))
	case cmdDNSRestart:
		b.sendMessage(ctx, chatID, "restart dns? full bounce, clients briefly can't resolve.", kb(
			[]inlineButton{btn("yes, restart", "dns_restart_confirm"), btn("cancel", "cancel")}))
	case "dns_stop_confirm":
		b.sendMessage(ctx, chatID, resultText("🔴 dns down.", p.dns.Stop()), nil)
	case "dns_restart_confirm":
		b.sendMessage(ctx, chatID, resultText("🔄 dns restarted.", p.dns.Restart()), nil)
	case "cancel":
		b.sendMessage(ctx, chatID, "cancelled.", nil)
	}
}

// menuText: old-school sysadmin tone for the /menu control panel.
const menuText = "ovcp control panel:"

func resultText(ok string, err error) string {
	if err != nil {
		return "⚠️ " + err.Error()
	}
	return ok
}

// vpnLine/dnsLine: one worker's status, shared by statusText and /dns.
func (p *Poller) vpnLine() string {
	pid := p.vpn.Pid()
	if pid == 0 {
		return "🔴 vpn down"
	}
	n := 0
	if cl, err := p.mgmt.Status(); err == nil {
		n = len(cl)
	}
	return fmt.Sprintf("🟢 vpn up (pid %d, up %s) · %d client(s) connected", pid, time.Since(p.vpn.StartedAt()).Round(time.Second), n)
}

func (p *Poller) dnsLine() string {
	if pid := p.dns.Pid(); pid != 0 {
		return fmt.Sprintf("🟢 dns up (pid %d, up %s)", pid, time.Since(p.dns.StartedAt()).Round(time.Second))
	}
	return "🔴 dns down"
}

// certLine: live cert count + how many are expiring, CA included.
func (p *Poller) certLine() string {
	certs, _ := p.s.AllCerts(p.p)
	live, soon := store.CertCounts(certs)
	if soon == 0 {
		return fmt.Sprintf("📜 %d cert(s)", live)
	}
	return fmt.Sprintf("📜 %d cert(s) · %d expiring ≤%dd", live, soon, store.ExpiryWarnDays)
}

// certStatusSections is certsText's status-to-heading order, most urgent
// first — one place both the grouping loop and the ordering read from.
var certStatusSections = []struct{ status, label string }{
	{"expiring", "⏳ Expiring"},
	{"expired", "❌ Expired"},
	{"revoked", "🚫 Revoked"},
	{"valid", "✅ Valid"},
}

// certDetail is certsText's one-line "what's the number that matters" per
// status: days left, days overdue, or the expiry date for a merely valid cert.
func certDetail(c store.Cert) string {
	switch c.Status() {
	case "expiring":
		return fmt.Sprintf("%dd left", int(time.Until(c.NotAfter).Hours()/24))
	case "expired":
		return fmt.Sprintf("expired %dd ago", int(time.Since(c.NotAfter).Hours()/24))
	case "revoked":
		return "revoked"
	default:
		return "until " + c.NotAfter.Format("2006-01-02")
	}
}

// certsText: every cert (client, server, and the CA), grouped by status —
// report-only, same as the rest of this bot; renewing/revoking stays
// CLI/web-UI-only.
// ponytail: no length cap on the message (Telegram's own 4096-char limit is
// the only ceiling) — fine at this tool's per-admin cert-count scale, add
// pagination if a deployment ever grows past it.
func (p *Poller) certsText() string {
	certs, err := p.s.AllCerts(p.p)
	if err != nil {
		return "⚠️ " + err.Error()
	}
	groups := map[string][]store.Cert{}
	for _, c := range certs {
		st := c.Status()
		groups[st] = append(groups[st], c)
	}
	for _, g := range groups {
		slices.SortFunc(g, func(a, b store.Cert) int { return a.NotAfter.Compare(b.NotAfter) })
	}
	var b strings.Builder
	fmt.Fprintf(&b, "📜 Certificates (%d total)", len(certs))
	for _, sec := range certStatusSections {
		g := groups[sec.status]
		if len(g) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d)", sec.label, len(g))
		for _, c := range g {
			fmt.Fprintf(&b, "\n  · %s (%s) — %s", c.CN, c.Kind, certDetail(c))
		}
	}
	return b.String()
}

// statusText: the full report — every worker plus certs, not just the vpn.
func (p *Poller) statusText() string {
	ovcpUptime := time.Since(controller.ProcessStartedAt).Round(time.Second)
	return fmt.Sprintf("%s\n%s\n%s\novcp up %s", p.vpnLine(), p.dnsLine(), p.certLine(), ovcpUptime)
}

// Notify best-effort pushes text to the linked admin chat. No-op if not
// configured or not yet linked (chat id is only known after first contact).
func (p *Poller) Notify(text string) {
	admin, _ := p.s.GetSetting(keyAdmin)
	token, _ := p.s.GetSetting(keyToken)
	if admin == "" || token == "" {
		slog.Debug("telegram: notify skipped, not configured")
		return
	}
	chatID, err := chatIDFor(p.s, admin)
	if err != nil {
		// admin is a @username and hasn't messaged the bot yet — visible at
		// Warn, not Debug, since this silently swallows every push otherwise.
		slog.Warn("telegram: notify skipped, chat not linked yet", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newBot(token).sendMessage(ctx, chatID, text, nil)
}

// chatIDFor is a free function, not a Poller method — SetAdmin needs it too,
// with no Poller instance necessarily around at that call site.
func chatIDFor(s *store.Store, admin string) (int64, error) {
	if id, err := strconv.ParseInt(admin, 10, 64); err == nil {
		return id, nil
	}
	cached, _ := s.GetSetting(keyChat)
	if cached == "" {
		return 0, fmt.Errorf("telegram: no chat linked yet")
	}
	return strconv.ParseInt(cached, 10, 64)
}

// OnAudit is store.AuditHook, wired in runServe: notifies on sensitive actions.
func (p *Poller) OnAudit(actor, action, detail string) {
	if !notifyActions[action] {
		return
	}
	p.Notify(fmt.Sprintf("🔔 %s: %s %s", actor, action, detail))
}
