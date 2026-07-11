// Shared live VPN status. Polled app-wide; phase drives the header glow.
import { api } from './api.js'

export const vpn = $state({ up: false, phase: 'down', clients: 0 }) // ok | down | reloading

let deadline = 0

export async function pollOnce() {
  try {
    const d = await api('GET', '/status')
    vpn.up = d.vpn_up
    vpn.clients = d.clients?.length ?? 0
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
    if (!(vpn.phase === 'reloading' && Date.now() < deadline)) vpn.phase = 'down'
    return { vpn_up: false, clients: [] }
  }
}

// Call when a reload/restart was requested: yellow until back up, red after timeout.
export function expectRecovery(ms = 30000) {
  vpn.phase = 'reloading'
  deadline = Date.now() + ms
}
