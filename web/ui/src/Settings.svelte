<script>
  import { api, apiBlob, downloadBlob } from './api.js'
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

  async function renewServer() {
    const passphrase = prompt('CA passphrase to renew the server certificate:')
    if (!passphrase) return
    err = ''; ok = ''
    try {
      const r = await api('POST', '/certs/renew-server', { Passphrase: passphrase })
      ok = `Server cert renewed (serial ${r.serial.slice(0, 12)}…). Use Restart to apply.`
    } catch (x) { err = x.error }
  }

  let backupErr = $state('')
  let backupOk = $state('')
  async function downloadBackup() {
    const passphrase = prompt('Set a passphrase to encrypt this backup (needed to restore it — write it down, it cannot be recovered):')
    if (!passphrase) return
    backupErr = ''; backupOk = ''
    try {
      const { blob, filename } = await apiBlob('POST', '/backup', { Passphrase: passphrase })
      downloadBlob(blob, filename || 'ovcp-backup.ovcpbak')
      backupOk = 'Backup downloaded.'
    } catch (x) { backupErr = x.error || 'backup failed' }
  }

  let tg = $state(null) // {running, tokenSet, admin}
  let tgErr = $state('')
  let tgOk = $state('')
  async function loadTelegram() {
    try { tg = await api('GET', '/telegram') } catch (x) { tgErr = x.error }
  }
  loadTelegram()

  async function setTelegramToken() {
    const token = prompt('Telegram bot token (from @BotFather):')
    if (!token) return
    const admin = prompt('Admin Telegram numeric id or @username — the only identity the bot will ever respond to:')
    if (!admin) return
    tgErr = ''; tgOk = ''
    try {
      tg = await api('PUT', '/telegram', { Token: token, Admin: admin })
      tgOk = 'Saved. Start the bot below to bring it up.'
    } catch (x) { tgErr = x.error }
  }

  let tgBusy = $state(false)
  async function telegramOp(op) {
    tgErr = ''; tgOk = ''; tgBusy = true
    try { tg = await api('POST', '/telegram/' + op) }
    catch (x) { tgErr = x.error }
    finally { tgBusy = false }
  }
  const tgStart = () => telegramOp('start')
  const tgStop = () => telegramOp('stop')
  const tgRestart = () => telegramOp('restart')
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
        <label class="wide">Custom options
          <textarea bind:value={cfg.Extra} rows="2" placeholder="e.g. client-to-client" disabled={!isAdmin}></textarea>
        </label>
      </div>
      {#if err}<p class="err">{err}</p>{/if}
      {#if ok}<p class="ok">{ok}</p>{/if}
      {#if isAdmin}
        <div class="row">
          <button type="submit">Save configuration</button>
          <button type="button" class="ghost" onclick={start}
            title="Launch openvpn if it isn't running">Start</button>
          <button type="button" class="ghost" onclick={stop}
            title="SIGTERM openvpn; disconnects all clients">Stop</button>
          <button type="button" class="ghost" onclick={restart}
            title="Full stop + fresh start; applies config, key, and CRL changes">Restart</button>
          <button type="button" class="ghost" onclick={reconnect}
            title="Soft session reset (SIGUSR1); keeps the process running">Reconnect</button>
        </div>
        <div class="row row-secondary">
          <button type="button" class="ghost" onclick={renewServer}
            title="Issue a fresh server certificate from the CA; needs Restart to apply">Renew server cert</button>
        </div>
      {:else}
        <p class="muted">Read-only: your role can view but not change settings.</p>
      {/if}
    </form>
  {/if}
</div>

{#if isAdmin}
  <div class="card">
    <h2>Telegram bot</h2>
    <p class="muted small">Notify-only, plus a Start/Stop/Restart menu from one linked admin chat — see Docs for details.</p>
    {#if tgErr}<p class="err">{tgErr}</p>{/if}
    {#if tgOk}<p class="ok">{tgOk}</p>{/if}
    {#if tg}
      <p class="tg-status" class:running={tg.running}>
        {#if !tg.tokenSet}not configured
        {:else}<span class="dot" class:pulse={tgBusy}>{tg.running ? '●' : '○'}</span> {tg.running ? 'running' : 'stopped'} · admin: {tg.admin}{/if}
      </p>
    {/if}
    <div class="row">
      <button type="button" class="ghost" onclick={setTelegramToken} disabled={tgBusy}>
        {tg?.tokenSet ? 'Regenerate token' : 'Set token'}</button>
      {#if tg?.tokenSet}
        <button type="button" class="ghost" onclick={tgStart} disabled={tgBusy}
          title="Bring the poller up (also starts automatically when serve starts, if a token is set)">Start</button>
        <button type="button" class="ghost" onclick={tgStop} disabled={tgBusy}>Stop</button>
        <button type="button" class="ghost" onclick={tgRestart} disabled={tgBusy}>Restart</button>
      {/if}
    </div>
  </div>

  <div class="card">
    <h2>Backup</h2>
    <p class="muted small">Encrypted export of the CA, CRL, tls-crypt key, config, and database.
      Never includes the openvpn server certificate or key — restoring reissues those fresh
      from the CA (<code>ovcp renew-server</code>). Restoring is CLI-only:
      <code>ovcp backup restore FILE</code>.</p>
    {#if backupErr}<p class="err">{backupErr}</p>{/if}
    {#if backupOk}<p class="ok">{backupOk}</p>{/if}
    <button type="button" class="ghost" onclick={downloadBackup}
      title="Download an encrypted archive of the CA, CRL, tls-crypt key, config, and database">Download backup</button>
  </div>
{/if}

<style>
  .row-secondary { padding-top: 10px; margin-top: 10px; border-top: 1px solid var(--line); }
  .tg-status { font-family: var(--mono); font-size: 12px; color: var(--dim); }
  .tg-status.running { color: var(--ok); }
  .tg-status .dot.pulse { display: inline-block; animation: pulse 1s ease-in-out infinite; }
</style>
