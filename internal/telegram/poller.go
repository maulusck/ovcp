package telegram

import (
	"context"
	"fmt"
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

type Poller struct {
	s    *store.Store
	vpn  controller.Lifecycle
	mgmt *controller.Client

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
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
	return s.SetSetting(keyChat, "")
}

func (p *Poller) Status() controller.TelegramStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	token, _ := p.s.GetSetting(keyToken)
	admin, _ := p.s.GetSetting(keyAdmin)
	return controller.TelegramStatus{Running: p.running, TokenSet: token != "", Admin: admin}
}

func (p *Poller) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	return nil
}

func (p *Poller) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return nil
	}
	p.cancel()
	p.running = false
	return nil
}

func (p *Poller) Restart() error {
	p.Stop()
	return p.Start()
}

func (p *Poller) loop(ctx context.Context, b *bot, admin string) {
	var offset int64
	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := b.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(5 * time.Second) // ponytail: fixed backoff, fine for a single-admin poller
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			p.handle(ctx, b, admin, u)
		}
	}
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
		if u.Message != nil {
			b.sendMessage(ctx, chatID, "🚫 403: you're not my admin.", nil)
		}
		return
	}
	p.s.SetSetting(keyChat, strconv.FormatInt(chatID, 10))

	if u.Callback != nil {
		b.answerCallback(ctx, u.Callback.ID)
		p.handleCommand(ctx, b, chatID, u.Callback.Data)
		return
	}
	if u.Message != nil {
		p.handleCommand(ctx, b, chatID, strings.TrimSpace(u.Message.Text))
	}
}

func (p *Poller) handleCommand(ctx context.Context, b *bot, chatID int64, cmd string) {
	switch cmd {
	case "/status", "status":
		b.sendMessage(ctx, chatID, p.statusText(), nil)
	case "/menu", "menu", "/start":
		b.sendMessage(ctx, chatID, "VPN control:", kb(
			[]inlineButton{btn("▶ Start", "start"), btn("⏹ Stop", "stop")},
			[]inlineButton{btn("🔄 Restart", "restart"), btn("📊 Status", "status")}))
	case "start":
		b.sendMessage(ctx, chatID, resultText("▶ Started.", p.vpn.Start()), nil)
	case "stop":
		b.sendMessage(ctx, chatID, "Stop the VPN? This disconnects all clients.", kb(
			[]inlineButton{btn("Yes, stop", "stop_confirm"), btn("Cancel", "cancel")}))
	case "restart":
		b.sendMessage(ctx, chatID, "Restart the VPN? Connected clients will briefly drop.", kb(
			[]inlineButton{btn("Yes, restart", "restart_confirm"), btn("Cancel", "cancel")}))
	case "stop_confirm":
		b.sendMessage(ctx, chatID, resultText("⏹ Stopped.", p.vpn.Stop()), nil)
	case "restart_confirm":
		b.sendMessage(ctx, chatID, resultText("🔄 Restarted.", p.vpn.Restart()), nil)
	case "cancel":
		b.sendMessage(ctx, chatID, "Cancelled.", nil)
	}
}

func resultText(ok string, err error) string {
	if err != nil {
		return "⚠️ " + err.Error()
	}
	return ok
}

func (p *Poller) statusText() string {
	pid := p.vpn.Pid()
	if pid == 0 {
		return "🔴 VPN down."
	}
	n := 0
	if cl, err := p.mgmt.Status(); err == nil {
		n = len(cl)
	}
	return fmt.Sprintf("🟢 VPN up (pid %d) · %d client(s) connected", pid, n)
}

// Notify best-effort pushes text to the linked admin chat. No-op if not
// configured or not yet linked (chat id only known after first contact,
// unless the admin is configured as a numeric id, which doubles as the
// private-chat id directly).
func (p *Poller) Notify(text string) {
	admin, _ := p.s.GetSetting(keyAdmin)
	token, _ := p.s.GetSetting(keyToken)
	if admin == "" || token == "" {
		return
	}
	chatID, err := p.chatID(admin)
	if err != nil {
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
