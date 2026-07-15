// Package telegram: notify-only Telegram bot, plus a small VPN
// start/stop/restart/status command surface gated to one admin identity.
// Plain HTTP against the Bot API — no SDK dependency.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// apiBase is a var, not a const, so tests can point it at an httptest
// server instead of hitting the real Telegram API.
var apiBase = "https://api.telegram.org/bot"

// SetAPIBaseForTesting points the client at url instead of the real
// Telegram API; call the returned func to restore it. For other packages'
// tests (e.g. internal/api) that need SetCredentials to succeed without a
// network call — not meant for anything but tests.
func SetAPIBaseForTesting(url string) (restore func()) {
	old := apiBase
	apiBase = url
	return func() { apiBase = old }
}

type bot struct {
	token string
	hc    *http.Client
}

func newBot(token string) *bot {
	return &bot{token: token, hc: &http.Client{Timeout: 40 * time.Second}}
}

func (b *bot) call(ctx context.Context, method string, body, out any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+b.token+"/"+method, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if !env.OK {
		return fmt.Errorf("telegram: %s", env.Description)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (b *bot) getMe(ctx context.Context) error { return b.call(ctx, "getMe", nil, nil) }

func (b *bot) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	var out []update
	err := b.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 30}, &out)
	return out, err
}

// markup is either *inlineKeyboard (buttons on this one message, e.g. a
// confirm/cancel) or *replyKeyboard (persistent, replaces the device
// keyboard until reissued) — nil for neither.
func (b *bot) sendMessage(ctx context.Context, chatID int64, text string, markup any) {
	body := map[string]any{"chat_id": chatID, "text": text}
	if markup != nil {
		body["reply_markup"] = markup
	}
	if err := b.call(ctx, "sendMessage", body, nil); err != nil { // best-effort: nothing to retry on
		slog.Debug("telegram: sendMessage failed", "chat", chatID, "err", err)
	}
}

func (b *bot) answerCallback(ctx context.Context, id string) {
	if err := b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id}, nil); err != nil {
		slog.Debug("telegram: answerCallbackQuery failed", "err", err)
	}
}

func (b *bot) setMyCommands(ctx context.Context, cmds []botCommand) {
	if err := b.call(ctx, "setMyCommands", map[string]any{"commands": cmds}, nil); err != nil {
		slog.Debug("telegram: setMyCommands failed", "err", err)
	}
}

type update struct {
	UpdateID int64          `json:"update_id"`
	Message  *message       `json:"message"`
	Callback *callbackQuery `json:"callback_query"`
}

type message struct {
	Chat chat   `json:"chat"`
	From user   `json:"from"`
	Text string `json:"text"`
}

type chat struct {
	ID int64 `json:"id"`
}

type user struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type callbackQuery struct {
	ID      string   `json:"id"`
	From    user     `json:"from"`
	Data    string   `json:"data"`
	Message *message `json:"message"`
}

type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

func kb(rows ...[]inlineButton) *inlineKeyboard { return &inlineKeyboard{InlineKeyboard: rows} }
func btn(text, data string) inlineButton        { return inlineButton{Text: text, CallbackData: data} }

// replyKeyboard replaces the device keyboard with real buttons — unlike
// inlineKeyboard (attached to one message, dismissed with it), this persists
// across the whole chat until reissued or removed.
type replyKeyboard struct {
	Keyboard       [][]string `json:"keyboard"`
	ResizeKeyboard bool       `json:"resize_keyboard"` // shrink to fit the labels, not full device height
}

func rkb(rows ...[]string) *replyKeyboard {
	return &replyKeyboard{Keyboard: rows, ResizeKeyboard: true}
}
