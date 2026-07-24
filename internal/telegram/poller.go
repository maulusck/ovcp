package telegram

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
)

const (
	keyToken  = "telegram_bot_token"
	keyAdmin  = "telegram_admin"
	keyChat   = "telegram_chat_id" // learned from the first authorized message
	keyWarned = "telegram_warned_serials"
)

// sensitive audit actions worth a push notification.
var notifyActions = map[string]bool{"revoke": true, "user_add": true, "user_del": true, "ca_rotate": true}

// unauthorizedBlockThreshold: an unrecognized sender gets this many 403s,
// then goes silent for the process's life, capping the sendMessage burst a spam wave would trigger.
// ponytail: unbounded in-memory map, no eviction/TTL; add one if abused.
const unauthorizedBlockThreshold = 3

type Poller struct {
	s    *store.Store
	vpn  controller.Lifecycle
	mgmt *controller.Client

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool

	abuseMu  sync.Mutex
	attempts map[int64]int
	blocked  map[int64]bool
}

func New(s *store.Store, vpn controller.Lifecycle, mgmt *controller.Client) *Poller {
	return &Poller{s: s, vpn: vpn, mgmt: mgmt}
}

// SetCredentials validates token against getMe, then saves token+admin
// together and forgets any previously-learned chat (new admin, new chat).
func SetCredentials(s *store.Store, token, admin string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := newBot(token).getMe(ctx); err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	if err := s.SetSetting(keyToken, token); err != nil {
		return err
	}
	if err := s.SetSetting(keyAdmin, admin); err != nil {
		return err
	}
	if err := s.SetSetting(keyChat, ""); err != nil {
		return err
	}
	slog.Info("telegram: credentials updated", "admin", admin)
	return nil
}

func (p *Poller) Status() controller.TelegramStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	token, _ := p.s.GetSetting(keyToken)
	admin, _ := p.s.GetSetting(keyAdmin)
	return controller.TelegramStatus{Running: p.running, TokenSet: token != "", Admin: admin}
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
			b.sendMessage(ctx, chatID, "🚫 403: you're not my admin.", nil)
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
	cmdStatus    = "status"
	cmdMenu      = "menu"
	cmdStart     = "start"
	cmdStop      = "stop"
	cmdRestart   = "restart"
	cmdReconnect = "reconnect"
)

// Reply-keyboard labels double as the tap-back text (no callback_data on a
// reply keyboard), so handleCommand's switch matches them directly, like the slash form.
const (
	lblStart     = "▶ start"
	lblStop      = "⏹ stop"
	lblRestart   = "🔄 restart"
	lblReconnect = "🔌 reconnect"
	lblStatus    = "📊 status"
)

// opsKeyboard is the persistent reply keyboard /menu (and /start) hands out.
// Status gets its own wide row: it's the one you check without acting.
var opsKeyboard = rkb(
	[]string{lblStart, lblStop},
	[]string{lblRestart, lblReconnect},
	[]string{lblStatus},
)

// botCommands drives Telegram's "/" autocomplete menu (registered via
// setMyCommands on every start), using the same consts handleCommand
// dispatches on, so the menu can't list something unhandled.
var botCommands = []botCommand{
	{cmdStatus, "pid, uptime, client count"},
	{cmdMenu, "hand out the control-panel keyboard"},
	{cmdStart, "bring the tunnel up"},
	{cmdStop, "bring it down (asks first)"},
	{cmdRestart, "full bounce (asks first)"},
	{cmdReconnect, "SIGUSR1: renegotiate, no restart"},
}

type botCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

func (p *Poller) handleCommand(ctx context.Context, b *bot, chatID int64, cmd string) {
	switch cmd {
	case "/" + cmdStatus, cmdStatus, lblStatus:
		b.sendMessage(ctx, chatID, p.statusText(), nil)
	case "/" + cmdMenu, cmdMenu:
		b.sendMessage(ctx, chatID, menuText, opsKeyboard)
	case "/" + cmdStart, cmdStart, lblStart: // also Telegram's own greeting trigger — matches unix `start` semantics, no confirmation needed
		b.sendMessage(ctx, chatID, resultText("▶ up.", p.vpn.Start()), nil)
	case "/" + cmdStop, cmdStop, lblStop:
		b.sendMessage(ctx, chatID, "stop the tunnel? every client drops.", kb(
			[]inlineButton{btn("yes, stop", "stop_confirm"), btn("cancel", "cancel")}))
	case "/" + cmdRestart, cmdRestart, lblRestart:
		b.sendMessage(ctx, chatID, "restart? full bounce, clients briefly drop.", kb(
			[]inlineButton{btn("yes, restart", "restart_confirm"), btn("cancel", "cancel")}))
	case "/" + cmdReconnect, cmdReconnect, lblReconnect:
		b.sendMessage(ctx, chatID, resultText("🔌 kicked (SIGUSR1).", p.vpn.Reconnect()), nil)
	case "stop_confirm":
		b.sendMessage(ctx, chatID, resultText("⏹ down.", p.vpn.Stop()), nil)
	case "restart_confirm":
		b.sendMessage(ctx, chatID, resultText("🔄 bounced.", p.vpn.Restart()), nil)
	case "cancel":
		b.sendMessage(ctx, chatID, "cancelled.", nil)
	}
}

// menuText: old-school sysadmin tone for the /menu control panel — a status
// line, not a greeting.
const menuText = "ovcp control panel. pick your poison:"

func resultText(ok string, err error) string {
	if err != nil {
		return "⚠️ " + err.Error()
	}
	return ok
}

func (p *Poller) statusText() string {
	ovcpUptime := time.Since(controller.ProcessStartedAt).Round(time.Second)
	pid := p.vpn.Pid()
	if pid == 0 {
		return fmt.Sprintf("🔴 VPN down.\novcp up %s", ovcpUptime)
	}
	n := 0
	if cl, err := p.mgmt.Status(); err == nil {
		n = len(cl)
	}
	vpnUptime := time.Since(p.vpn.StartedAt()).Round(time.Second)
	return fmt.Sprintf("🟢 VPN up (pid %d, up %s) · %d client(s) connected\novcp up %s", pid, vpnUptime, n, ovcpUptime)
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
	chatID, err := p.chatID(admin)
	if err != nil {
		slog.Debug("telegram: notify skipped", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newBot(token).sendMessage(ctx, chatID, text, nil)
}

func (p *Poller) chatID(admin string) (int64, error) {
	if id, err := strconv.ParseInt(admin, 10, 64); err == nil {
		return id, nil
	}
	cached, _ := p.s.GetSetting(keyChat)
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
