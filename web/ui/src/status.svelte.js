// Shared live VPN status. Polled app-wide; phase drives the header glow.
import { api } from './api.js'

export const vpn = $state({ up: false, phase: 'down', clients: 0, clientList: [], uptime: '', routingWarning: '', ovcpUptime: '', reloadLabel: '' }) // ok | down | reloading
export const dns = $state({ up: false, phase: 'down', uptime: '', reloadLabel: '' }) // ok | down | reloading; dnsmasq is optional — App.svelte overrides to "na" when never installed
export const telegram = $state({ running: false, tokenSet: false, admin: '', chatLinked: false })
export const upstreams = $state({ warning: '' }) // live iface-down check, read-only — riding this same poll instead of a second one
// whole ovcp process reachable at all — distinct from vpn/dns above, which can be
// legitimately down while ovcp itself answers fine. App.svelte locks the UI on this.
export const backend = $state({ up: true })

let deadline = 0
let dnsDeadline = 0
let misses = 0 // consecutive network-level failures; 2 before backend.up flips, so one dropped poll doesn't flash the lock

// fmtUptime: seconds → compact string, longest unit that keeps it readable.
// Shared with Stats.svelte's session-duration column.
export function fmtUptime(sec) {
  if (!sec) return ''
  if (sec < 60) return Math.round(sec) + 's'
  if (sec < 3600) return Math.round(sec / 60) + 'm'
  if (sec < 86400) return (sec / 3600).toFixed(1) + 'h'
  return (sec / 86400).toFixed(1) + 'd'
}

// since: an RFC 3339 start time → seconds up, 0 for Go's zero time (not running).
const since = (t) => (t && !t.startsWith('0001') ? (Date.now() - Date.parse(t)) / 1000 : 0)

export async function pollOnce() {
  try {
    const d = await api('GET', '/status')
    backend.up = true; misses = 0
    vpn.up = d.running && !d.error // a pid but no readable client list is not up
    vpn.clients = d.clients?.length ?? 0
    vpn.clientList = d.clients || []
    vpn.uptime = fmtUptime(since(d.startedAt))
    vpn.ovcpUptime = fmtUptime(since(d.serveStartedAt))
    if (vpn.up) {
      vpn.phase = 'ok'
      deadline = 0
    } else if (vpn.phase === 'reloading' && Date.now() < deadline) {
      // still within the grace window
    } else {
      vpn.phase = 'down'
    }
    dns.up = !!d.dnsRunning
    dns.uptime = fmtUptime(since(d.dnsStartedAt))
    if (dns.up) {
      dns.phase = 'ok'
      dnsDeadline = 0
    } else if (dns.phase === 'reloading' && Date.now() < dnsDeadline) {
      // still within the grace window
    } else {
      dns.phase = 'down'
    }
    if (d.telegram) Object.assign(telegram, d.telegram)
    upstreams.warning = d.upstreamWarning || ''
    vpn.routingWarning = d.routingWarning || ''
    return d
  } catch (err) {
    // api() throws {status, error} once the server has answered (even with an
    // error) — only a raw fetch failure (no .status) means ovcp itself is unreachable.
    if (err?.status === undefined) {
      if (++misses >= 2) backend.up = false
    } else {
      backend.up = true; misses = 0
    }
    if (!(vpn.phase === 'reloading' && Date.now() < deadline)) {
      vpn.phase = 'down'; vpn.up = false; vpn.clientList = []; vpn.uptime = ''; vpn.ovcpUptime = ''
    }
    if (!(dns.phase === 'reloading' && Date.now() < dnsDeadline)) {
      dns.phase = 'down'; dns.up = false; dns.uptime = ''
    }
    return { running: false, clients: [] }
  }
}

// Call when a reload/restart/reconnect was requested: yellow until back up
// (or timeout) — label is what the pill/tooltip call it meanwhile, since
// "restarting" during a Reconnect (SIGUSR1, process never stops) would lie.
export function expectRecovery(ms = 30000, label = 'restarting') {
  vpn.phase = 'reloading'
  vpn.reloadLabel = label
  deadline = Date.now() + ms
}
export function expectDnsRecovery(ms = 15000, label = 'restarting') {
  dns.phase = 'reloading'
  dns.reloadLabel = label
  dnsDeadline = Date.now() + ms
}
