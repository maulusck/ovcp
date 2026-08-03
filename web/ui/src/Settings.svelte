<script>
  import { api, apiBlob, downloadBlob, procOp, procDone, flash } from './api.js'
  import { expectRecovery, expectDnsRecovery, telegram, pollOnce } from './status.svelte.js'
  import Msg from './Msg.svelte'
  let { isAdmin, dnsAvailable, upstreamsAvailable } = $props()
  let cfg = $state(null)
  let dns = $state('')
  let err = $state('')
  let ok = $state('')

  async function load() {
    try {
      cfg = await api('GET', '/vpn/config')
      dns = (cfg.DNS || []).join(', ')
    } catch (x) { flash(v => err = v, x.error) }
  }
  load()

  function normalized() {
    cfg.DNS = dns.split(',').map(s => s.trim()).filter(Boolean)
    cfg.Port = +cfg.Port
    return cfg
  }

  async function save(e) {
    e.preventDefault()
    err = ''; ok = ''; preview = null
    try {
      cfg = await api('PUT', '/vpn/config', normalized())
      flash(v => ok = v, 'Saved. Use Restart to apply configuration changes.')
    } catch (x) { flash(v => err = v, x.error) }
  }

  let preview = $state(null) // {diff, changed}
  async function previewConfig() {
    err = ''; ok = ''
    try { preview = await api('POST', '/vpn/config/preview', normalized()) }
    catch (x) { flash(v => err = v, x.error) }
  }

  // Config and CRL changes require a full Restart (fresh root process re-reads
  // the keys); Reconnect only soft-resets live sessions for recovery.
  async function vpn(op, confirmMsg, recoverMs, done, label) {
    err = ''; ok = ''
    try {
      const r = await procOp('/vpn/', op, { confirm: confirmMsg, recoverMs, onRecover: (ms) => expectRecovery(ms, label) })
      if (r) flash(v => ok = v, procDone(op, r, done))
    } catch (x) { flash(v => err = v, x.error) }
  }

  const start     = () => vpn('start', null, 30000, 'Start requested.', 'starting')
  const stop      = () => vpn('stop', 'Stop OpenVPN? All tunnels disconnect.', 0, 'Stopped. All tunnels disconnected.')
  const restart   = () => vpn('restart', 'Restart OpenVPN? Connected clients will briefly drop.', 30000, 'Restarting. Applies all configuration changes.', 'restarting')
  const reconnect = () => vpn('reconnect', null, 15000, 'Reconnect signal sent. Live sessions reset.', 'reconnecting')

  // DNS: dnsmasq lifecycle + block-internet + custom records, one card, same
  // shape as the vpn card above (fields, then one row: save/preview/lifecycle).
  let blockInternet = $state(false)
  let dnsRecords = $state('')
  let dnsPreview = $state(null)
  let dnsErr = $state('')
  let dnsOk = $state('')

  // Advisory only, mirrors api.DNSLeakWarning — never blocks Save.
  const dnsLeakWarning = $derived.by(() => {
    if (!cfg || !blockInternet) return ''
    if (dns.trim()) return 'Manual DNS entries can leak queries around Block internet DNS.'
    if (!cfg.PushInternalDNS) return 'Block internet DNS has no effect unless Push internal DNS is also on.'
    return ''
  })

  async function loadDNS() {
    try {
      blockInternet = (await api('GET', '/dns/config')).blockInternet
      dnsRecords = (await api('GET', '/dns/custom')).content
    } catch (x) { flash(v => dnsErr = v, x.error) }
  }
  $effect(() => { if (dnsAvailable) loadDNS() })

  async function toggleBlockInternet(e) {
    const want = e.target.checked
    try { blockInternet = (await api('PUT', '/dns/config', { BlockInternet: want })).blockInternet }
    catch (x) { flash(v => dnsErr = v, x.error); e.target.checked = !want }
  }

  async function previewDNS() {
    dnsErr = ''; dnsOk = ''
    try { dnsPreview = await api('POST', '/dns/custom/preview', { Content: dnsRecords }) }
    catch (x) { flash(v => dnsErr = v, x.error) }
  }

  async function saveDNS(e) {
    e.preventDefault()
    dnsErr = ''; dnsOk = ''; dnsPreview = null
    try {
      await api('PUT', '/dns/custom', { Content: dnsRecords })
      flash(v => dnsOk = v, 'Saved.')
    } catch (x) { flash(v => dnsErr = v, x.error) }
  }

  async function dnsOp(op, confirmMsg, recoverMs, done, label) {
    dnsErr = ''; dnsOk = ''
    try {
      const r = await procOp('/dns/', op, { confirm: confirmMsg, recoverMs, onRecover: (ms) => expectDnsRecovery(ms, label) })
      if (r) flash(v => dnsOk = v, procDone(op, r, done))
    } catch (x) { flash(v => dnsErr = v, x.error) }
  }
  const dnsStart   = () => dnsOp('start', null, 10000, 'Started.', 'starting')
  const dnsStop    = () => dnsOp('stop', 'Stop internal DNS? Connected clients stop resolving local names.', 0, 'Stopped.')
  const dnsRestart = () => dnsOp('restart', 'Restart internal DNS?', 10000, 'Restarted.', 'restarting')

  // Upstreams: policy-routed VPN egress — a list of named entries (add/del/
  // set-default), not a single-blob form like DNS/logs above.
  let upCfg = $state(null)
  let upErr = $state('')
  let upOk = $state('')
  let newID = $state(''), newIface = $state(''), newGateway = $state(''), newSocks = $state(''), newDesc = $state('')
  let newMode = $state('iface') // 'iface' | 'socks' — which fields the add form sends

  async function loadUpstreams() {
    try { upCfg = await api('GET', '/upstreams') } catch (x) { flash(v => upErr = v, x.error) }
  }
  $effect(() => { if (upstreamsAvailable) loadUpstreams() })

  async function addUpstream(e) {
    e.preventDefault()
    upErr = ''; upOk = ''
    try {
      const body = newMode === 'socks'
        ? { ID: newID, SOCKS: newSocks, Description: newDesc }
        : { ID: newID, Iface: newIface, Gateway: newGateway, Description: newDesc }
      upCfg = await api('POST', '/upstreams', body)
      newID = ''; newIface = ''; newGateway = ''; newSocks = ''; newDesc = ''
      flash(v => upOk = v, 'Added.')
    } catch (x) { flash(v => upErr = v, x.error) }
  }

  async function delUpstream(id) {
    if (!confirm(`Remove upstream "${id}"? Traffic steered through it falls back to the host's own default route.`)) return
    upErr = ''; upOk = ''
    try {
      upCfg = await api('DELETE', '/upstreams/' + encodeURIComponent(id))
      flash(v => upOk = v, 'Removed.')
    } catch (x) { flash(v => upErr = v, x.error) }
  }

  async function setDefaultUpstream(e) {
    const id = e.target.value
    upErr = ''; upOk = ''
    try {
      upCfg = await api('PUT', '/upstreams/default', { ID: id })
      flash(v => upOk = v, id ? `Default: ${id}.` : "Default: off (host's own default route).")
    } catch (x) { flash(v => upErr = v, x.error); loadUpstreams() }
  }

  // Logs: rotation policy for openvpn.log/ovcp.log/dnsmasq.log.
  let logsCfg = $state(null)
  let logsErr = $state('')
  let logsOk = $state('')

  async function loadLogsCfg() {
    try { logsCfg = await api('GET', '/logs/config') } catch (x) { flash(v => logsErr = v, x.error) }
  }
  loadLogsCfg()

  async function saveLogsCfg(e) {
    e.preventDefault()
    logsErr = ''; logsOk = ''
    logsCfg.RetentionDays = +logsCfg.RetentionDays
    logsCfg.KeepUncompressed = +logsCfg.KeepUncompressed
    try {
      logsCfg = await api('PUT', '/logs/config', logsCfg)
      flash(v => logsOk = v, 'Saved.')
    } catch (x) { flash(v => logsErr = v, x.error) }
  }

  async function rotateLogs() {
    logsErr = ''; logsOk = ''
    try {
      await api('POST', '/logs/rotate')
      flash(v => logsOk = v, 'Rotated.')
    } catch (x) { flash(v => logsErr = v, x.error) }
  }

  // Stats: traffic-history sampling/retention policy.
  let statsCfg = $state(null)
  let statsErr = $state('')
  let statsOk = $state('')

  async function loadStatsCfg() {
    try { statsCfg = await api('GET', '/stats/config') } catch (x) { flash(v => statsErr = v, x.error) }
  }
  loadStatsCfg()

  async function saveStatsCfg(e) {
    e.preventDefault()
    statsErr = ''; statsOk = ''
    statsCfg.SampleIntervalSec = +statsCfg.SampleIntervalSec
    statsCfg.RetentionHours = +statsCfg.RetentionHours
    try {
      statsCfg = await api('PUT', '/stats/config', statsCfg)
      flash(v => statsOk = v, 'Saved.')
    } catch (x) { flash(v => statsErr = v, x.error) }
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
      flash(v => backupOk = v, 'Backup downloaded.')
    } catch (x) { flash(v => backupErr = v, x.error || 'backup failed') }
  }

  // telegram itself (running/tokenSet/admin/chatLinked) lives in the shared,
  // app-wide polled state (status.svelte.js), same as vpn/dns — actions
  // below only trigger a refresh, same as vpn/dns's own procOp calls do.
  let tgErr = $state('')
  let tgOk = $state('')

  // Token and admin are independent identities (rotating one must never touch
  // the other, or re-saving an unchanged admin would silently re-link the chat).
  async function setTelegramToken() {
    const token = prompt('Telegram bot token (from @BotFather):')
    if (!token) return
    tgErr = ''; tgOk = ''
    try {
      await api('PUT', '/telegram/config', { Token: token })
      pollOnce()
      flash(v => tgOk = v, 'Token set. Start the bot below to bring it up.')
    } catch (x) { flash(v => tgErr = v, x.error) }
  }

  async function setTelegramAdmin() {
    const admin = prompt('Admin Telegram numeric id or @username — the only identity the bot will ever respond to:')
    if (!admin) return
    tgErr = ''; tgOk = ''
    try {
      await api('PUT', '/telegram/config', { Admin: admin })
      pollOnce()
      flash(v => tgOk = v, 'Admin set.')
    } catch (x) { flash(v => tgErr = v, x.error) }
  }

  async function telegramOp(op, done) {
    tgErr = ''; tgOk = ''
    try {
      const r = await procOp('/telegram/', op)
      pollOnce()
      flash(v => tgOk = v, procDone(op, r, done))
    } catch (x) { flash(v => tgErr = v, x.error) }
  }
  const tgStart = () => telegramOp('start', 'Started.')
  const tgStop = () => telegramOp('stop', 'Stopped.')
  const tgRestart = () => telegramOp('restart', 'Restarted.')

  const tgState = $derived(!telegram.tokenSet ? 'na' : telegram.running ? 'ok' : 'down')
  const tgLabel = $derived(
    tgState === 'na' ? 'not configured' :
    tgState !== 'ok' ? 'stopped' :
    `running · admin: ${telegram.admin}` + (telegram.chatLinked ? '' : ' · chat not linked yet, message the bot once'))
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
        <label>Push DNS
          <input bind:value={dns} placeholder="1.1.1.1, 9.9.9.9" title="comma-separated" disabled={!isAdmin} />
        </label>
        <div class="check-row wide">
          <label class="check">
            <input type="checkbox" bind:checked={cfg.RedirectGW} disabled={!isAdmin} />
            Route all client traffic through the VPN
          </label>
          {#if dnsAvailable}
            <label class="check" title="pushed ahead of the DNS entries above">
              <input type="checkbox" bind:checked={cfg.PushInternalDNS} disabled={!isAdmin} />
              Push internal DNS
            </label>
          {/if}
        </div>
        <label class="wide">Custom options
          <textarea bind:value={cfg.Extra} rows="2" placeholder="e.g. client-to-client" disabled={!isAdmin}></textarea>
        </label>
      </div>
      <Msg type="err" text={dnsLeakWarning} />
      <Msg type="err" text={err} />
      <Msg type="ok" text={ok} />
      {#if preview}
        {#if preview.changed}
          <p class="muted small">Changes vs. the saved server.conf:</p>
          <pre class="diff">{#each preview.diff as line}<span class={line[0] === '+' ? 'add' : 'del'}>{line}
</span>{/each}</pre>
        {:else}
          <p class="muted small">No changes vs. the saved server.conf.</p>
        {/if}
      {/if}
      {#if isAdmin}
        <div class="row">
          <button type="submit">Save</button>
          <button type="button" class="ghost" onclick={previewConfig}
            title="Show what Save would change in server.conf, without applying it">Preview</button>
          <button type="button" class="ghost" onclick={start}
            title="Launch openvpn if it isn't running">Start</button>
          <button type="button" class="ghost" onclick={stop}
            title="SIGTERM openvpn; disconnects all clients">Stop</button>
          <button type="button" class="ghost" onclick={restart}
            title="Full stop + fresh start; applies config, key, and CRL changes">Restart</button>
          <button type="button" class="ghost" onclick={reconnect}
            title="Soft session reset (SIGUSR1); keeps the process running">Reconnect</button>
        </div>
      {:else}
        <p class="muted">Read-only: your role can view but not change settings.</p>
      {/if}
    </form>
  {/if}
</div>

{#if dnsAvailable}
  <div class="card">
    <h2>DNS configuration</h2>
    <p class="muted small">Resolves certificate names for connected clients; optionally blocks all other internet DNS.</p>
    <form onsubmit={saveDNS}>
      <div class="grid">
        <label class="check wide">
          <input type="checkbox" checked={blockInternet} disabled={!isAdmin} onchange={toggleBlockInternet} />
          Block internet DNS (answer only local names; restart to apply)
        </label>
        <label class="wide">Custom records
          <textarea bind:value={dnsRecords} rows="6" placeholder="10.8.0.50 pihole" disabled={!isAdmin}></textarea>
        </label>
      </div>
      <Msg type="err" text={dnsLeakWarning} />
      <Msg type="err" text={dnsErr} />
      <Msg type="ok" text={dnsOk} />
      {#if dnsPreview}
        {#if dnsPreview.changed}
          <p class="muted small">Changes to be saved:</p>
          <pre class="diff">{#each dnsPreview.diff as line}<span class={line[0] === '+' ? 'add' : 'del'}>{line}
</span>{/each}</pre>
        {:else}
          <p class="muted small">No changes.</p>
        {/if}
      {/if}
      {#if isAdmin}
        <div class="row">
          <button type="submit">Save</button>
          <button type="button" class="ghost" onclick={previewDNS}>Preview</button>
          <button type="button" class="ghost" onclick={dnsStart} title="Launch dnsmasq if it isn't running">Start</button>
          <button type="button" class="ghost" onclick={dnsStop} title="SIGTERM dnsmasq; clients stop resolving local names">Stop</button>
          <button type="button" class="ghost" onclick={dnsRestart} title="Full stop + fresh start; applies hosts and config changes">Restart</button>
        </div>
      {:else}
        <p class="muted small">Read-only: your role can view but not change this.</p>
      {/if}
    </form>
  </div>
{/if}

{#if upstreamsAvailable}
  <div class="card">
    <h2>Upstreams</h2>
    <p class="muted small">Route connected clients' traffic out a chosen interface or SOCKS proxy (Tor, proxychains, self-hosted) instead of the host's own default route. ovcp only steers and NATs/relays — bring the interface or SOCKS backend itself up first.</p>
    {#if !upCfg}
      <p class="muted">Loading…</p>
    {:else}
      {#if upCfg.Upstreams?.length}
        <table>
          <thead><tr><th>ID</th><th>Interface</th><th>Gateway / SOCKS</th><th>Description</th><th></th></tr></thead>
          <tbody>
            {#each upCfg.Upstreams as u}
              <tr>
                <td>{u.ID}{u.ID === upCfg.Default ? ' (default)' : ''}</td>
                <td>{u.Iface || (u.SOCKS ? '(socks)' : '')}</td>
                <td>{u.SOCKS || u.Gateway || '(onlink)'}</td>
                <td>{u.Description}</td>
                <td>{#if isAdmin}<button type="button" class="ghost" onclick={() => delUpstream(u.ID)}>Remove</button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <label>Active default
          <select value={upCfg.Default || ''} disabled={!isAdmin} onchange={setDefaultUpstream}>
            <option value="">off (host's own default route)</option>
            {#each upCfg.Upstreams as u}<option value={u.ID}>{u.ID}</option>{/each}
          </select>
        </label>
      {:else}
        <p class="muted small">No upstreams defined yet — clients exit through the host's own default route.</p>
      {/if}
      <Msg type="err" text={upErr} />
      <Msg type="ok" text={upOk} />
      {#if isAdmin}
        <form onsubmit={addUpstream}>
          <div class="grid">
            <label>ID
              <input bind:value={newID} placeholder="wan2" required />
            </label>
            <label>Mode
              <select bind:value={newMode}>
                <option value="iface">Interface</option>
                <option value="socks">SOCKS proxy</option>
              </select>
            </label>
            {#if newMode === 'iface'}
              <label>Interface
                <input bind:value={newIface} placeholder="eth1, wg0" required />
              </label>
              <label>Gateway
                <input bind:value={newGateway} placeholder="empty = onlink" />
              </label>
            {:else}
              <label>SOCKS URL
                <input bind:value={newSocks} placeholder="socks5://[user:pass@]host:port" required />
              </label>
            {/if}
            <label>Description
              <input bind:value={newDesc} placeholder="optional" />
            </label>
          </div>
          <div class="row"><button type="submit">Add upstream</button></div>
        </form>
      {/if}
    {/if}
  </div>
{/if}

<div class="card">
  <h2>Logs configuration</h2>
  <p class="muted small">Daily rotation for log files.</p>
  {#if !logsCfg}
    <p class="muted">Loading…</p>
  {:else}
    <form onsubmit={saveLogsCfg}>
      <div class="grid">
        <label class="check wide">
          <input type="checkbox" bind:checked={logsCfg.Enabled} disabled={!isAdmin} />
          Run daily rotation
        </label>
        <label>Retention (days)
          <input type="number" bind:value={logsCfg.RetentionDays} min="0" title="0 = keep forever" disabled={!isAdmin} />
        </label>
        <label>Keep uncompressed
          <input type="number" bind:value={logsCfg.KeepUncompressed} min="0" title="newest N rotations stay uncompressed, gzip the rest" disabled={!isAdmin} />
        </label>
      </div>
      <Msg type="err" text={logsErr} />
      <Msg type="ok" text={logsOk} />
      {#if isAdmin}
        <div class="row">
          <button type="submit">Save</button>
          <button type="button" class="ghost" onclick={rotateLogs} title="Copytruncate all log files now, same as `ovcp logs rotate`">Rotate now</button>
        </div>
      {:else}
        <p class="muted small">Read-only: your role can view but not change settings.</p>
      {/if}
    </form>
  {/if}
</div>

<div class="card">
  <h2>Stats configuration</h2>
  <p class="muted small">Traffic-history sampling for the Stats tab's graphs and CLI.</p>
  {#if !statsCfg}
    <p class="muted">Loading…</p>
  {:else}
    <form onsubmit={saveStatsCfg}>
      <div class="grid">
        <label>Sample interval (seconds)
          <input type="number" bind:value={statsCfg.SampleIntervalSec} min="1" disabled={!isAdmin} />
        </label>
        <label>Retention (hours)
          <input type="number" bind:value={statsCfg.RetentionHours} min="1" disabled={!isAdmin} />
        </label>
      </div>
      <Msg type="err" text={statsErr} />
      <Msg type="ok" text={statsOk} />
      {#if isAdmin}
        <div class="row"><button type="submit">Save</button></div>
      {:else}
        <p class="muted small">Read-only: your role can view but not change settings.</p>
      {/if}
    </form>
  {/if}
</div>

{#if isAdmin}
  <div class="card">
    <h2>Telegram bot</h2>
    <p class="muted small">Notify-only, plus a Start/Stop/Restart menu from one linked admin chat — see Docs for details.</p>
    <Msg type="err" text={tgErr} />
    <Msg type="ok" text={tgOk} />
    <p class="status-line"><span class="status-dot {tgState}"></span> {tgLabel}</p>
    <div class="row">
      <button type="button" class="ghost" onclick={setTelegramToken}
        title="Set the bot token, independently of admin">{telegram.tokenSet ? 'Regenerate token' : 'Set token'}</button>
      <button type="button" class="ghost" onclick={setTelegramAdmin}
        title="Set the admin identity, independently of token">{telegram.admin ? 'Change admin' : 'Set admin'}</button>
      {#if telegram.tokenSet}
        <button type="button" class="ghost" onclick={tgStart} title="Bring the poller up">Start</button>
        <button type="button" class="ghost" onclick={tgStop} title="Stop the poller; bot goes quiet">Stop</button>
        <button type="button" class="ghost" onclick={tgRestart} title="Full stop + fresh start of the poller">Restart</button>
      {/if}
    </div>
  </div>

  <div class="card">
    <h2>Backup</h2>
    <p class="muted small">Encrypted export of the CA, CRL, tls-crypt key, config, and database.
      Never includes the openvpn server certificate or key — restoring reissues those fresh
      from the CA (<code>ovcp certificate renew</code>). Restoring is CLI-only:
      <code>ovcp backup restore FILE</code>.</p>
    <Msg type="err" text={backupErr} />
    <Msg type="ok" text={backupOk} />
    <button type="button" class="ghost" onclick={downloadBackup}
      title="Download an encrypted archive of the CA, CRL, tls-crypt key, config, and database">Download backup</button>
  </div>
{/if}

