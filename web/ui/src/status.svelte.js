// Shared live VPN status. Polled app-wide; phase drives the header glow.
import { api } from './api.js'

export const vpn = $state({ up: false, phase: 'down', clients: 0, clientList: [], uptime: '', ovcpUptime: '' }) // ok | down | reloading

let deadline = 0

// fmtUptime: seconds → compact string, longest unit that keeps it readable.
// A process-uptime figure (hours to weeks), not a client-session one
// (seconds to hours) — same idea as Stats.svelte's fmtDur, one more tier.
function fmtUptime(sec) {
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
    return d
  } catch {
    if (!(vpn.phase === 'reloading' && Date.now() < deadline)) {
      vpn.phase = 'down'; vpn.up = false; vpn.clientList = []; vpn.uptime = ''; vpn.ovcpUptime = ''
    }
    return { vpn_up: false, clients: [] }
  }
}

// Call when a reload/restart was requested: yellow until back up, red after timeout.
export function expectRecovery(ms = 30000) {
  vpn.phase = 'reloading'
  deadline = Date.now() + ms
}
