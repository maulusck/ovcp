package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/ovcp/ovcp/internal/api"
	"github.com/ovcp/ovcp/internal/controller"
	"github.com/ovcp/ovcp/internal/store"
)

// statsSnapshot is `stats -json`'s shape: the same samples+sessions pair
// GET /api/stats returns, so scripts get the real history, not a summary.
type statsSnapshot struct {
	Samples  []store.Sample        `json:"samples"`
	Sessions []store.ClientSession `json:"sessions"`
}

func cmdStats(fs *flag.FlagSet) func(ctx *cliContext) {
	cn := fs.String("cn", "", "client CN (default: global aggregate)")
	follow := fs.Bool("follow", false, "live top-like view, via a running serve's control socket (ignores -json)")
	interval := fs.Int("interval", 2, "poll interval in seconds, -follow only")
	ctrl := fs.String("ctrl", ctrlSock(), "serve control socket, -follow only")
	return func(ctx *cliContext) {
		if *follow {
			if jsonOut {
				die(fmt.Errorf("-json is not supported with -follow"))
			}
			followStats(*ctrl, *cn, *interval)
			return
		}
		s := ctx.openStore()
		defer s.Close()
		since := time.Now().Add(-api.StatsRetention)
		var samples []store.Sample
		var err error
		if *cn != "" {
			samples, err = s.ClientSamples(*cn, since)
		} else {
			samples, err = s.Samples(since)
		}
		die(err)
		sessions, err := s.Sessions(200)
		die(err)
		if *cn != "" {
			sessions = filterSessionsByCN(sessions, *cn)
		}
		if samples == nil {
			samples = []store.Sample{}
		}
		if sessions == nil {
			sessions = []store.ClientSession{}
		}
		output(statsSnapshot{samples, sessions}, func(o statsSnapshot) { printStatsText(o, *cn) })
	}
}

func filterSessionsByCN(sessions []store.ClientSession, cn string) []store.ClientSession {
	var out []store.ClientSession
	for _, s := range sessions {
		if s.CN == cn {
			out = append(out, s)
		}
	}
	return out
}

// fmtBytes mirrors web/ui/src/api.js's fmtBytes: same units, same thresholds.
func fmtBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	i := 0
	for v /= 1024; v >= 1024 && i < len(units)-1; v /= 1024 {
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func fmtRate(bytesPerSec uint64) string { return fmtBytes(bytesPerSec) + "/s" }

// fmtDur mirrors web/ui/src/Stats.svelte's fmtDur: same thresholds.
func fmtDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

func printStatsText(o statsSnapshot, cn string) {
	if len(o.Samples) == 0 {
		fmt.Println("no samples yet — the sampler writes one per connected client per minute")
	} else {
		last := o.Samples[len(o.Samples)-1]
		if cn == "" {
			fmt.Printf("global · %d client(s)   recv %s   sent %s\n", last.Clients, fmtBytes(last.BytesRecv), fmtBytes(last.BytesSent))
		} else {
			fmt.Printf("%s   recv %s   sent %s\n", cn, fmtBytes(last.BytesRecv), fmtBytes(last.BytesSent))
		}
		if len(o.Samples) >= 2 { // the first sample always has rate 0 — no baseline yet
			fmt.Printf("rate: rx %s   tx %s\n", fmtRate(last.BytesRecvRate), fmtRate(last.BytesSentRate))
		}
		fmt.Printf("%d sample(s), oldest %s\n", len(o.Samples), o.Samples[0].TS.Format(time.RFC3339))
	}

	fmt.Println()
	if len(o.Sessions) == 0 {
		if cn != "" {
			fmt.Println("no finished sessions for", cn)
		} else {
			fmt.Println("no finished sessions")
		}
		return
	}
	n := min(len(o.Sessions), 20)
	fmt.Println("recent sessions:")
	for _, s := range o.Sessions[:n] {
		fmt.Printf("  %-20s %-16s %-6s disconnected %s  recv %s  sent %s\n",
			s.CN, s.RealAddress, fmtDur(s.DisconnectedAt.Sub(s.ConnectedAt)),
			s.DisconnectedAt.Format(time.RFC3339), fmtBytes(s.BytesRecv), fmtBytes(s.BytesSent))
	}
}

// followStats polls a running serve's control socket (bypassing the DB/
// sampler entirely, for sub-minute liveliness) at intervalSec and redraws a
// small in-place block, top-style.
//
// This goes through serve, not a direct dial to openvpn's own mgmt socket:
// OpenVPN's management interface serves exactly one connected client, ever,
// and serve already holds that slot for its whole life — a second direct
// dial doesn't get refused, it just hangs until openvpn's accept queue
// backs up and every mgmt-dependent command (this, `status`, `kill`) starts
// failing with "resource temporarily unavailable". See ServeControl.
func followStats(ctrl, cn string, intervalSec int) {
	if intervalSec <= 0 {
		intervalSec = 2
	}
	tty := term.IsTerminal(int(os.Stdout.Fd()))
	if tty {
		fmt.Print("\x1b[?25l") // hide cursor
	}
	restore := func() {
		if tty {
			fmt.Print("\x1b[?25h")
		}
	}
	defer restore()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; restore(); os.Exit(0) }()

	// ponytail: prevC never evicts CNs that leave for good — fine for an
	// interactive session (bounded by distinct clients seen this run); add
	// a sweep if -follow is ever left running unattended for days.
	prevC := map[string]store.Sample{}
	printed := 0
	for {
		clients, err := controller.Clients(ctrl)
		now := time.Now()
		lines := followLines(clients, err, cn, now, prevC)
		redraw(lines, &printed, tty)
		time.Sleep(time.Duration(intervalSec) * time.Second)
	}
}

// redraw overwrites the previous frame in place on a real terminal (cursor
// up, reprint, clear any now-shorter trailing lines); on a pipe/file it just
// prints each frame as a new block.
func redraw(lines []string, printed *int, tty bool) {
	if tty && *printed > 0 {
		fmt.Printf("\x1b[%dA", *printed)
	}
	for _, l := range lines {
		fmt.Print(l)
		if tty {
			fmt.Print("\x1b[K")
		}
		fmt.Println()
	}
	if tty && *printed > len(lines) {
		extra := *printed - len(lines)
		for i := 0; i < extra; i++ {
			fmt.Print("\x1b[K")
			fmt.Println()
		}
		fmt.Printf("\x1b[%dA", extra)
	}
	*printed = len(lines)
}

// followLines renders one frame: a header, then either a single client's
// detail (-cn set) or a per-client table sorted busiest-first (global), like
// top. prevC (one entry per CN, updated in place every frame) is the only
// state carried across calls — the global rate is derived from it exactly
// like store.Samples derives it from the DB: sum each still-connected
// client's own clamped delta, divide once, never diff the aggregate itself.
func followLines(clients []controller.VPNClient, err error, cn string, now time.Time, prevC map[string]store.Sample) []string {
	if err != nil {
		return []string{red("VPN unreachable — " + err.Error())}
	}
	byCN := make(map[string]controller.VPNClient, len(clients))
	for _, c := range clients {
		byCN[c.CN] = c
	}

	if cn == "" {
		type row struct {
			cn         string
			rx, tx     uint64
			recv, sent uint64
		}
		rows := make([]row, 0, len(clients))
		var recvDelta, sentDelta uint64
		var dt time.Duration
		for _, c := range clients {
			var rx, tx uint64
			if old, ok := prevC[c.CN]; ok {
				dt = now.Sub(old.TS) // same for every client seen last tick
				rx, tx = store.Rate(old.BytesRecv, c.BytesRecv, dt), store.Rate(old.BytesSent, c.BytesSent, dt)
				recvDelta += store.ClampedDelta(old.BytesRecv, c.BytesRecv)
				sentDelta += store.ClampedDelta(old.BytesSent, c.BytesSent)
			}
			prevC[c.CN] = store.Sample{TS: now, BytesRecv: c.BytesRecv, BytesSent: c.BytesSent}
			rows = append(rows, row{c.CN, rx, tx, c.BytesRecv, c.BytesSent})
		}
		grx, gtx := store.Rate(0, recvDelta, dt), store.Rate(0, sentDelta, dt)
		lines := []string{fmt.Sprintf("%s · %d client(s)   rx %s   tx %s",
			green("vpn up"), len(clients), fmtRate(grx), fmtRate(gtx))}
		if len(clients) == 0 {
			return lines
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].rx+rows[i].tx > rows[j].rx+rows[j].tx })
		lines = append(lines, fmt.Sprintf("%-20s %-11s %-11s %-12s %-12s", "CN", "RECV/s", "SENT/s", "TOTAL RECV", "TOTAL SENT"))
		shown, more := rows, 0
		if len(shown) > 20 {
			shown, more = rows[:20], len(rows)-20
		}
		for _, r := range shown {
			lines = append(lines, fmt.Sprintf("%-20s %-11s %-11s %-12s %-12s",
				r.cn, fmtRate(r.rx), fmtRate(r.tx), fmtBytes(r.recv), fmtBytes(r.sent)))
		}
		if more > 0 {
			lines = append(lines, fmt.Sprintf("… %d more", more))
		}
		return lines
	}

	c, ok := byCN[cn]
	if !ok {
		return []string{yellow(cn + ": not connected")}
	}
	var rx, tx uint64
	if old, ok := prevC[cn]; ok {
		dt := now.Sub(old.TS)
		rx, tx = store.Rate(old.BytesRecv, c.BytesRecv, dt), store.Rate(old.BytesSent, c.BytesSent, dt)
	}
	prevC[cn] = store.Sample{TS: now, BytesRecv: c.BytesRecv, BytesSent: c.BytesSent}
	return []string{
		fmt.Sprintf("%s · connected since %s", green(cn), c.ConnectedSince.Format("15:04:05")),
		fmt.Sprintf("rx %s   tx %s   total recv %s   total sent %s", fmtRate(rx), fmtRate(tx), fmtBytes(c.BytesRecv), fmtBytes(c.BytesSent)),
	}
}
