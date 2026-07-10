<script>
  import { api } from './api.js'
  import { expectRecovery } from './status.svelte.js'
  let { isAdmin } = $props()
  let cfg = $state(null)
  let dns = $state('')
  let err = $state('')
  let ok = $state('')

  async function load() {
    try {
      cfg = await api('GET', '/config')
      dns = (cfg.DNS || []).join(', ')
    } catch (x) { err = x.error }
  }
  load()

  async function save(e) {
    e.preventDefault()
    err = ''; ok = ''
    try {
      cfg.DNS = dns.split(',').map(s => s.trim()).filter(Boolean)
      cfg.Port = +cfg.Port
      cfg = await api('PUT', '/config', cfg)
      ok = 'Saved. Use Restart to apply configuration changes.'
    } catch (x) { err = x.error }
  }

  // Config and CRL changes require a full Restart (fresh root process re-reads
  // the keys); Reconnect only soft-resets live sessions for recovery.
  async function vpn(op, confirmMsg, recoverMs, done) {
    if (confirmMsg && !confirm(confirmMsg)) return
    err = ''; ok = ''
    try {
      await api('POST', '/vpn/' + op)
      if (recoverMs) expectRecovery(recoverMs)
      ok = done
    } catch (x) { err = x.error }
  }

  const start     = () => vpn('start', null, 30000, 'Start requested.')
  const stop      = () => vpn('stop', 'Stop OpenVPN? All tunnels disconnect.', 0, 'Stopped. All tunnels disconnected.')
  const restart   = () => vpn('restart', 'Restart OpenVPN? Connected clients will briefly drop.', 30000, 'Restarting. Applies all configuration changes.')
  const reconnect = () => vpn('reconnect', null, 15000, 'Reconnect signal sent. Live sessions reset.')
</script>

<div class="card">
  <h2>Server configuration</h2>
  {#if !cfg}
    <p class="muted">Loading…</p>
  {:else}
    <form onsubmit={save}>
      <div class="grid">
        <label>Protocol
          <select bind:value={cfg.Proto} disabled={!isAdmin}>
            <option value="udp">udp</option>
            <option value="tcp">tcp</option>
          </select>
        </label>
        <label>Port
          <input type="number" bind:value={cfg.Port} min="1" max="65535" disabled={!isAdmin} />
        </label>
        <label>VPN subnet (CIDR)
          <input bind:value={cfg.Subnet} disabled={!isAdmin} />
        </label>
        <label>Data cipher
          <select bind:value={cfg.Cipher} disabled={!isAdmin}>
            <option>AES-256-GCM</option>
            <option>AES-128-GCM</option>
            <option>CHACHA20-POLY1305</option>
          </select>
        </label>
        <label>Push DNS (comma-separated)
          <input bind:value={dns} placeholder="1.1.1.1, 9.9.9.9" disabled={!isAdmin} />
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={cfg.RedirectGW} disabled={!isAdmin} />
          Route all client traffic through the VPN
        </label>
      </div>
      {#if err}<p class="err">{err}</p>{/if}
      {#if ok}<p class="ok">{ok}</p>{/if}
      {#if isAdmin}
        <div class="row">
          <button type="submit">Save configuration</button>
          <button type="button" class="ghost" onclick={start}>Start</button>
          <button type="button" class="ghost" onclick={stop}>Stop</button>
          <button type="button" class="ghost" onclick={restart}>Restart</button>
          <button type="button" class="ghost" onclick={reconnect}>Reconnect</button>
        </div>
      {:else}
        <p class="muted">Read-only: your role can view but not change settings.</p>
      {/if}
    </form>
  {/if}
</div>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0 14px; }
  .check { display: flex; align-items: center; gap: 8px; }
  .check input { width: auto; }
  .row { display: flex; gap: 10px; margin-top: 6px; }
  .ok { color: var(--ok); font-size: 13px; }
</style>
