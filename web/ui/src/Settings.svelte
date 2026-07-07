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
      ok = 'Saved. Use Restart to apply port/protocol/subnet changes.'
    } catch (x) { err = x.error }
  }

  async function reload() {
    err = ''; ok = ''
    try {
      const d = await api('POST', '/reload')
      expectRecovery(15000)
      ok = `Reload signal sent (${d.via}). Picks up CRL and connection settings.`
    } catch (x) { err = x.error }
  }

  async function restart() {
    if (!confirm('Restart OpenVPN? Connected clients will briefly drop.')) return
    err = ''; ok = ''
    try {
      const d = await api('POST', '/restart')
      expectRecovery(30000)
      ok = `Restarting (${d.via}). Applies port, protocol, subnet and key changes.`
    } catch (x) { err = x.error }
  }
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
          <button type="button" class="ghost" onclick={reload}>Reload</button>
          <button type="button" class="ghost" onclick={restart}>Restart</button>
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
