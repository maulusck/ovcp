// Shared live VPN status. Polled app-wide; phase drives the header glow.
import { api } from './api.js'

export const vpn = $state({ up: false, phase: 'down', clients: 0, clientList: [], uptime: '', ovcpUptime: '', reloadLabel: '' }) // ok | down | reloading
export const dns = $state({ up: false, phase: 'down', uptime: '', reloadLabel: '' }) // ok | down | reloading; dnsmasq is optional — App.svelte overrides to "na" when never installed

let deadline = 0
let dnsDeadline = 0

// fmtUptime: seconds → compact string, longest unit that keeps it readable.
// Shared with Stats.svelte's session-duration column.
export function fmtUptime(sec) {
  if (!sec) return ''
  if (sec < 60) return Math.round(sec) + 's'
  if (sec < 3600) return Math.round(sec / 60) + 'm'
  if (sec < 86400) return (sec / 3600).toFixed(1) + 'h'
  return (sec / 86400).toFixed(1) + 'd'
}

export async function pollOnce() {
  try {
    const d = await api('GET', '/status')
    vpn.up = d.vpn_up
    vpn.clients = d.clients?.length ?? 0
    vpn.clientList = d.clients || []
    vpn.uptime = fmtUptime(d.vpn_uptime_seconds)
    vpn.ovcpUptime = fmtUptime(d.ovcp_uptime_seconds)
    if (d.vpn_up) {
      vpn.phase = 'ok'
      deadline = 0
    } else if (vpn.phase === 'reloading' && Date.now() < deadline) {
      // still within the grace window
    } else {
      vpn.phase = 'down'
    }
    dns.up = !!d.dns_up
    dns.uptime = fmtUptime(d.dns_uptime_seconds)
    if (d.dns_up) {
      dns.phase = 'ok'
      dnsDeadline = 0
    } else if (dns.phase === 'reloading' && Date.now() < dnsDeadline) {
      // still within the grace window
    } else {
      dns.phase = 'down'
    }
    return d
  } catch {
    if (!(vpn.phase === 'reloading' && Date.now() < deadline)) {
      vpn.phase = 'down'; vpn.up = false; vpn.clientList = []; vpn.uptime = ''; vpn.ovcpUptime = ''
    }
    if (!(dns.phase === 'reloading' && Date.now() < dnsDeadline)) {
      dns.phase = 'down'; dns.up = false; dns.uptime = ''
    }
    return { vpn_up: false, clients: [] }
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
