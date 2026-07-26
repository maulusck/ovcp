package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/ovcp/ovcp/internal/pki"
	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/telegram"
)

const certExpiryWarnedKey = "cert_expiry_warned_serials"

// runExpirySweepTicker checks daily for certs newly inside store.ExpiryWarnDays
// and notifies once per serial. Same ticker shape as runLogRotateTicker;
// telegram.Poller is just the notification sink here, not the owner of what/when.
func runExpirySweepTicker(s *store.Store, p *pki.PKI, tg *telegram.Poller, stop <-chan struct{}) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	sweepExpiring(s, p, tg) // once at boot, not just after the first 24h
	for {
		select {
		case <-t.C:
			sweepExpiring(s, p, tg)
		case <-stop:
			return
		}
	}
}

func sweepExpiring(s *store.Store, p *pki.PKI, tg *telegram.Poller) {
	certs, err := s.AllCerts(p)
	if err != nil {
		slog.Warn("expiry sweep failed to list certs", "err", err)
		return
	}
	warned := store.LoadJSON(s, certExpiryWarnedKey, map[string]bool{})
	live := map[string]bool{}
	changed := false
	for _, c := range certs {
		live[c.Serial] = true
		if c.Status() != "expiring" || warned[c.Serial] {
			continue
		}
		days := time.Until(c.NotAfter).Hours() / 24
		warned[c.Serial] = true
		changed = true
		slog.Warn("cert expiring", "cn", c.CN, "kind", c.Kind, "serial", c.Serial, "days", int(days))
		tg.Notify(fmt.Sprintf("⏳ %s (%s) expires in %.0fd", c.CN, c.Kind, days))
	}
	for serial := range warned {
		if !live[serial] {
			delete(warned, serial)
			changed = true
		}
	}
	if changed {
		store.SaveJSON(s, certExpiryWarnedKey, warned)
	}
}
