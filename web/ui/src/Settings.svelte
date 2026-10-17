<script>
  import { api, downloadBlob, procOp, procDone, flash, autosize, sortRows, toggleSort, sortMark } from './api.js'
  import { expectRecovery, expectDnsRecovery, telegram, upstreams, pollOnce } from './status.svelte.js'
  import Msg from './Msg.svelte'
  /** @import { Config, Preview, DNSView, UpstreamView, UpstreamRow, LogConfig, StatsConfig } from './api.gen' */
  /** @import { Sort } from './api.js' */
  /** @type {{ isAdmin: boolean, dnsAvailable: boolean, upstreamsAvailable: boolean }} */
  let { isAdmin, dnsAvailable, upstreamsAvailable } = $props()
  let cfg = $state(/** @type {Config | null} */ (null))
  let dns = $state('')
  let err = $state('')
  let ok = $state('')

  async function load() {
    try {
      cfg = await api('GET /api/vpn/config')
      dns = cfg.DNS.join(', ')
    } catch (x) { flash(v => err = v, x.error) }
  }
  load()

  function normalized() {
    const c = /** @type {Config} */ (cfg)
    return { ...c, DNS: dns.split(',').map(s => s.trim()).filter(Boolean), Port: +c.Port }
  }

  async function save(/** @type {SubmitEvent} */ e) {
    e.preventDefault()
    err = ''; ok = ''; preview = null
    try {
      cfg = await api('PUT /api/vpn/config', normalized())
      showDNS(await api('GET /api/dns/config'))
      flash(v => ok = v, 'Saved. Use Restart to apply configuration changes.')
    } catch (x) { flash(v => err = v, x.error) }
  }

  let preview = $state(/** @type {Preview | null} */ (null))
  async function previewConfig() {
    err = ''; ok = ''
    try { preview = await api('POST /api/vpn/config/preview', normalized()) }
    catch (x) { flash(v => err = v, x.error) }
  }

  // Config and CRL changes require a full Restart (fresh root process re-reads
  // the keys); Reconnect only soft-resets live sessions for recovery.
  /** @param {string} op @param {string | null} confirmMsg @param {number} recoverMs @param {string} done @param {string} [label] */
  async function vpn(op, confirmMsg, recoverMs, done, label) {
    err = ''; ok = ''
    try {
      const r = await procOp('POST /api/vpn/{op}', op, { confirm: confirmMsg, recoverMs, onRecover: (ms) => expectRecovery(ms, label) })
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
  let dnsPreview = $state(/** @type {Preview | null} */ (null))
  let dnsWarning = $state('')
  let dnsErr = $state('')
  let dnsOk = $state('')

  // the server's DNS leak advisory (api.DNSLeakWarning) for the saved configs
  const showDNS = (/** @type {DNSView} */ d) => { blockInternet = d.BlockInternet; dnsWarning = d.warning ?? '' }

  async function loadDNS() {
    try {
      showDNS(await api('GET /api/dns/config'))
      dnsRecords = (await api('GET /api/records')).custom
    } catch (x) { flash(v => dnsErr = v, x.error) }
  }
  $effect(() => { if (dnsAvailable) loadDNS() })

  /** @param {Event & { currentTarget: HTMLInputElement }} e */
  async function toggleBlockInternet(e) {
    const want = e.currentTarget.checked
    try { showDNS(await api('PUT /api/dns/config', { BlockInternet: want })) }
    catch (x) { flash(v => dnsErr = v, x.error); e.currentTarget.checked = !want }
  }

  async function previewDNS() {
    dnsErr = ''; dnsOk = ''
    try { dnsPreview = await api('POST /api/records/custom/preview', { Content: dnsRecords }) }
    catch (x) { flash(v => dnsErr = v, x.error) }
  }

  async function saveDNS(/** @type {SubmitEvent} */ e) {
    e.preventDefault()
    dnsErr = ''; dnsOk = ''; dnsPreview = null
    try {
      await api('PUT /api/records/custom', { Content: dnsRecords })
      flash(v => dnsOk = v, 'Saved. Use Restart to apply configuration changes.')
    } catch (x) { flash(v => dnsErr = v, x.error) }
  }

  /** @param {string} op @param {string | null} confirmMsg @param {number} recoverMs @param {string} done @param {string} [label] */
  async function dnsOp(op, confirmMsg, recoverMs, done, label) {
    dnsErr = ''; dnsOk = ''
    try {
      const r = await procOp('POST /api/dns/{op}', op, { confirm: confirmMsg, recoverMs, onRecover: (ms) => expectDnsRecovery(ms, label) })
      if (r) flash(v => dnsOk = v, procDone(op, r, done))
    } catch (x) { flash(v => dnsErr = v, x.error) }
  }
  const dnsStart   = () => dnsOp('start', null, 10000, 'Started.', 'starting')
  const dnsStop    = () => dnsOp('stop', 'Stop internal DNS? Connected clients stop resolving local names.', 0, 'Stopped.')
  const dnsRestart = () => dnsOp('restart', 'Restart internal DNS?', 10000, 'Restarted.', 'restarting')

  // Upstreams: policy-routed VPN egress — a list of named entries (add/del/
  // set-default), not a single-blob form like DNS/logs above.
  let upCfg = $state(/** @type {UpstreamView | null} */ (null))
  let upErr = $state('') // list card: remove/set-default/reconcile
  let upOk = $state('')
  let addErr = $state('') // add-upstream card, own pair — same split as Users' form vs. list
  let addOk = $state('')
  let newID = $state(''), newIface = $state(''), newGateway = $state(''), newSocks = $state(''), newDesc = $state('')
  let newMode = $state('iface') // 'iface' | 'socks' — which fields the add form sends
  let upSort = $state(/** @type {Sort} */ ({ key: null, desc: false }))
  /** @type {Record<string, (u: UpstreamRow) => string | undefined>} */
  const UP_SORT_GETTERS = { id: (u) => u.id, iface: (u) => u.iface, desc: (u) => u.description }
  const sortedUpstreams = $derived.by(() => {
    const rows = upCfg?.upstreams ?? []
    return upSort.key ? sortRows(rows, UP_SORT_GETTERS[upSort.key], upSort.desc) : rows
  })

  async function loadUpstreams() {
    try { upCfg = await api('GET /api/upstreams') } catch (x) { flash(v => upErr = v, x.error) }
  }
  $effect(() => { if (upstreamsAvailable) loadUpstreams() })

  async function addUpstream(/** @type {SubmitEvent} */ e) {
    e.preventDefault()
    addErr = ''; addOk = ''
    try {
      const body = newMode === 'socks'
        ? { ID: newID, SOCKS: newSocks, Description: newDesc }
        : { ID: newID, Iface: newIface, Gateway: newGateway, Description: newDesc }
      upCfg = await api('POST /api/upstreams', body)
      const id = newID
      newID = ''; newIface = ''; newGateway = ''; newSocks = ''; newDesc = ''
      flash(v => addOk = v, `Added ${id}.`)
    } catch (x) { flash(v => addErr = v, x.error) }
  }

  async function delUpstream(/** @type {string} */ id) {
    if (!confirm(`Remove upstream "${id}"? Traffic steered through it falls back to the host's own default route.`)) return
    upErr = ''; upOk = ''
    try {
      upCfg = await api('DELETE /api/upstreams/{id}', { id })
      flash(v => upOk = v, `Removed ${id}.`)
    } catch (x) { flash(v => upErr = v, x.error) }
  }

  /** @param {Event & { currentTarget: HTMLSelectElement }} e */
  async function setDefaultUpstream(e) {
    const id = e.currentTarget.value
    upErr = ''; upOk = ''
    try {
      upCfg = await api('PUT /api/upstreams/default', { ID: id })
      flash(v => upOk = v, id ? `Default: ${id}.` : "Default: off (host's own default route).")
    } catch (x) { flash(v => upErr = v, x.error); loadUpstreams() }
  }

  // Re-applies routing/NAT for whatever's already saved — a real mutation
  // (reprograms nft), so it's this one manual button, not something the
  // background status poll above should ever trigger on its own.
  async function reconcileUpstreams() {
    upErr = ''; upOk = ''
    try {
      const r = await api('POST /api/upstreams/reconcile')
      upCfg = r
      flash(v => upOk = v, r.warning ?? 'Reconciled — all upstreams reachable.')
    } catch (x) { flash(v => upErr = v, x.error) }
  }

  // Logs: rotation policy for openvpn.log/ovcp.log/dnsmasq.log.
  let logsCfg = $state(/** @type {LogConfig | null} */ (null))
  let logsErr = $state('')
  let logsOk = $state('')

  async function loadLogsCfg() {
    try { logsCfg = await api('GET /api/logs/config') } catch (x) { flash(v => logsErr = v, x.error) }
  }
  loadLogsCfg()

  async function saveLogsCfg(/** @type {SubmitEvent} */ e) {
    e.preventDefault()
    logsErr = ''; logsOk = ''
    const c = /** @type {LogConfig} */ (logsCfg)
    try {
      logsCfg = await api('PUT /api/logs/config', { ...c, RetentionDays: +c.RetentionDays, KeepUncompressed: +c.KeepUncompressed })
      flash(v => logsOk = v, 'Saved.')
    } catch (x) { flash(v => logsErr = v, x.error) }
  }

  async function rotateLogs() {
    logsErr = ''; logsOk = ''
    try {
      await api('POST /api/logs/rotate')
      flash(v => logsOk = v, 'Rotated.')
    } catch (x) { flash(v => logsErr = v, x.error) }
  }

  // Stats: traffic-history sampling/retention policy.
  let statsCfg = $state(/** @type {StatsConfig | null} */ (null))
  let statsErr = $state('')
  let statsOk = $state('')

  async function loadStatsCfg() {
    try { statsCfg = await api('GET /api/stats/config') } catch (x) { flash(v => statsErr = v, x.error) }
  }
  loadStatsCfg()

  async function saveStatsCfg(/** @type {SubmitEvent} */ e) {
    e.preventDefault()
    statsErr = ''; statsOk = ''
    const c = /** @type {StatsConfig} */ (statsCfg)
    try {
      statsCfg = await api('PUT /api/stats/config', { ...c, SampleIntervalSec: +c.SampleIntervalSec, RetentionHours: +c.RetentionHours })
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
      const { blob, filename } = await api('POST /api/backup', { Passphrase: passphrase })
      downloadBlob(blob, filename)
      flash(v => backupOk = v, 'Backup downloaded.')
    } catch (x) { flash(v => backupErr = v, x.error) }
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
      await api('PUT /api/telegram/config', { Token: token })
      pollOnce()
      flash(v => tgOk = v, 'Token set. Start the bot below to bring it up.')
    } catch (x) { flash(v => tgErr = v, x.error) }
  }

  async function setTelegramAdmin() {
    const admin = prompt('Admin Telegram numeric id or @username — the only identity the bot will ever respond to:')
    if (!admin) return
    tgErr = ''; tgOk = ''
    try {
      await api('PUT /api/telegram/config', { Admin: admin })
      pollOnce()
      flash(v => tgOk = v, 'Admin set.')
    } catch (x) { flash(v => tgErr = v, x.error) }
  }

  /** @param {string} op @param {string} done */
  async function telegramOp(op, done) {
    tgErr = ''; tgOk = ''
    try {
      const r = await procOp('POST /api/telegram/{op}', op)
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
          <textarea bind:value={cfg.Extra} use:autosize={cfg.Extra} rows="2" placeholder="e.g. client-to-client" disabled={!isAdmin}></textarea>
        </label>
      </div>
      <Msg type="err" text={preview?.warning ?? dnsWarning} />
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
          <textarea bind:value={dnsRecords} use:autosize={dnsRecords} rows="2" placeholder="10.8.0.50 pihole" disabled={!isAdmin}></textarea>
        </label>
      </div>
      <Msg type="err" text={dnsWarning} />
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
  {#if isAdmin && upCfg}
    <form class="card" onsubmit={addUpstream}>
      <h2>Add upstream</h2>
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
      <Msg type="err" text={addErr} />
      <Msg type="ok" text={addOk} />
      <div class="row"><button type="submit">Add upstream</button></div>
    </form>
  {/if}

  <div class="card">
    <h2>Upstreams
      {#if isAdmin && upCfg?.upstreams.length}
        <button type="button" class="ghost" onclick={reconcileUpstreams}
          title="Re-check reachability and re-apply routing/NAT for the saved config">Reconcile</button>
      {/if}
    </h2>
    <p class="muted small">Egress via a named interface or SOCKS proxy (Tor, proxychains, self-hosted) instead of the host's default route; ovcp only steers and NATs — bring the backend up first. Per-client overrides live in the Certificates tab.</p>
    <Msg type="err" text={upErr} />
    <Msg type="ok" text={upOk} />
    {#if !upCfg}
      <p class="muted">Loading…</p>
    {:else if !upCfg.upstreams?.length}
      <p class="muted small">No upstreams defined yet — clients exit through the host's own default route.</p>
    {:else}
      <table>
        <thead><tr>
          <th><button class="th-sort" onclick={() => toggleSort(upSort, 'id')}>ID{sortMark(upSort, 'id')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(upSort, 'iface')}>Interface{sortMark(upSort, 'iface')}</button></th>
          <th>Gateway / SOCKS</th>
          <th><button class="th-sort" onclick={() => toggleSort(upSort, 'desc')}>Description{sortMark(upSort, 'desc')}</button></th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each sortedUpstreams as u}
            <tr>
              <td>{u.id}{u.id === upCfg.default ? ' (default)' : ''}</td>
              <td>{u.iface || (u.socks ? '(socks)' : '')}</td>
              <td>{u.socks || u.gateway || '(onlink)'}</td>
              <td>{u.description}</td>
              <td>{#if isAdmin}<button type="button" class="ghost" onclick={() => delUpstream(u.id)}>Remove</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <label>Active default
        <select value={upCfg.default || ''} disabled={!isAdmin} onchange={setDefaultUpstream}>
          <option value="">off (host's own default route)</option>
          {#each upCfg.upstreams as u}<option value={u.id}>{u.id}</option>{/each}
        </select>
      </label>
      {#if upstreams.warning}<p class="status-line warn">{upstreams.warning}</p>{/if}
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

