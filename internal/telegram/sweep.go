package telegram

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/ovcp/ovcp/internal/store"
)

// RunExpirySweeper checks daily for certs newly inside store.ExpiryWarnDays
// and notifies once per serial. Same ticker shape as api.RunStatsSampler.
func (p *Poller) RunExpirySweeper(stop <-chan struct{}) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	p.sweepExpiring() // once at boot, not just after the first 24h
	for {
		select {
		case <-t.C:
			p.sweepExpiring()
		case <-stop:
			return
		}
	}
}

func (p *Poller) sweepExpiring() {
	certs, err := p.s.ListCerts()
	if err != nil {
		slog.Warn("telegram: expiry sweep failed to list certs", "err", err)
		return
	}
	warned := p.warnedSet()
	live := map[string]bool{}
	changed := false
	for _, c := range certs {
		live[c.Serial] = true
		if c.RevokedAt != nil {
			continue
		}
		days := time.Until(c.NotAfter).Hours() / 24
		if days < 0 || days > store.ExpiryWarnDays || warned[c.Serial] {
			continue
		}
		warned[c.Serial] = true
		changed = true
		p.Notify(fmt.Sprintf("⏳ %s (%s) expires in %.0fd", c.CN, c.Kind, days))
	}
	for serial := range warned {
		if !live[serial] {
			delete(warned, serial)
			changed = true
		}
	}
	if changed {
		p.saveWarnedSet(warned)
	}
}

func (p *Poller) warnedSet() map[string]bool {
	raw, _ := p.s.GetSetting(keyWarned)
	var list []string
	json.Unmarshal([]byte(raw), &list)
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[s] = true
	}
	return out
}

func (p *Poller) saveWarnedSet(set map[string]bool) {
	list := make([]string, 0, len(set))
	for s := range set {
		list = append(list, s)
	}
	data, _ := json.Marshal(list)
	p.s.SetSetting(keyWarned, string(data))
}
