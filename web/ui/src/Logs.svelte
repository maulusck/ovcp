<script>
  import { tick } from 'svelte'
  import { api } from './api.js'
  let { isAdmin } = $props()
  let entries = $state([])
  let ovpnLines = $state([])
  let ovcpLines = $state([])
  let ovpnBox = $state(), ovcpBox = $state()
  let auditCard = $state(), ovpnCard = $state(), ovcpCard = $state()
  let debugOn = $state(false)
  let err = $state('')
  const POLL_KEY = 'ovcp_logs_poll'
  let pollSec = $state(Number(localStorage.getItem(POLL_KEY) ?? 15))
  const AUTOSCROLL_KEY = 'ovcp_logs_autoscroll'
  let autoscroll = $state(localStorage.getItem(AUTOSCROLL_KEY) !== '0')
  const OPEN_KEY = 'ovcp_logs_open'
  let openState = $state(Object.assign(
    { audit: true, openvpn: false, ovcp: false },
    JSON.parse(localStorage.getItem(OPEN_KEY) || '{}')))

  async function scrollToBottom(el) {
    if (!autoscroll || !el) return
    await tick()
    el.scrollTop = el.scrollHeight
  }

  async function loadAudit() {
    try { entries = await api('GET', '/audit') } catch (x) { err = x.error }
  }
  async function loadOpenVPN() {
    try { ovpnLines = (await api('GET', '/logs/openvpn')).lines; scrollToBottom(ovpnBox) } catch (x) { err = x.error }
  }
  async function loadOVCP() {
    try { ovcpLines = (await api('GET', '/logs/ovcp')).lines; scrollToBottom(ovcpBox) } catch (x) { err = x.error }
  }
  async function loadDebug() {
    try { debugOn = (await api('GET', '/debug')).debug } catch (x) { err = x.error }
  }
  function refresh() { loadAudit(); loadOpenVPN(); loadOVCP(); loadDebug() }
  refresh()

  async function toggleDebug(e) {
    const want = e.target.checked
    try { debugOn = (await api('POST', '/debug', { Debug: want })).debug }
    catch (x) { err = x.error; e.target.checked = !want }
  }

  let copied = $state('')
  async function copyText(panel, text) {
    try { await navigator.clipboard.writeText(text) }
    catch { prompt('Log text:', text); return }
    copied = panel
    setTimeout(() => (copied = ''), 1200)
  }
  const auditText = () => entries.map(e =>
    `${new Date(e.TS).toLocaleString()} ${e.Actor} ${e.Action} ${e.Detail}`).join('\n')

  // the archive bundle takes no request input at all (fixed server-side
  // filenames) — per-log copy/download stays entirely client-side instead
  // of adding a parametrized single-file endpoint for it.
  const downloadAllLogs = () => (window.location.href = '/api/logs/download')

  function downloadText(filename, text) {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    a.download = filename
    a.click()
    URL.revokeObjectURL(a.href)
  }

  // native Fullscreen API for "maximize" — no custom overlay/z-index CSS,
  // Esc-to-exit and restore both come from the browser for free.
  let maximized = $state(null) // 'audit' | 'openvpn' | 'ovcp' | null
  function toggleMaximize(el) {
    if (!el) return
    if (document.fullscreenElement === el) document.exitFullscreen()
    else el.requestFullscreen()
  }
  $effect(() => {
    function onChange() {
      const el = document.fullscreenElement
      maximized = el === auditCard ? 'audit' : el === ovpnCard ? 'openvpn' : el === ovcpCard ? 'ovcp' : null
    }
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  })

  $effect(() => {
    localStorage.setItem(POLL_KEY, pollSec)
    if (!pollSec) return
    const t = setInterval(refresh, pollSec * 1000)
    return () => clearInterval(t)
  })

  $effect(() => { localStorage.setItem(AUTOSCROLL_KEY, autoscroll ? '1' : '0') })
  $effect(() => { localStorage.setItem(OPEN_KEY, JSON.stringify(openState)) })
</script>

<div class="logs-head">
  {#if err}<p class="err">{err}</p>{/if}
  <label class="poll-pick" title={isAdmin ? 'Verbose logging for troubleshooting' : 'Admin only'}>
    Debug logging
    <input type="checkbox" checked={debugOn} disabled={!isAdmin} onchange={toggleDebug} />
  </label>
  <label class="poll-pick" title="Scroll OpenVPN/OVCP logs to the newest line on refresh">
    Autoscroll
    <input type="checkbox" bind:checked={autoscroll} />
  </label>
  <label class="poll-pick">Auto-refresh
    <select bind:value={pollSec}>
      <option value={0}>Off</option>
      <option value={5}>5s</option>
      <option value={15}>15s</option>
      <option value={30}>30s</option>
    </select>
  </label>
  <button type="button" class="ghost" onclick={downloadAllLogs}
    title="Download the full openvpn.log + ovcp.log as a zip">Download all logs</button>
</div>

<div class="logs-grid">
  <details class="card" bind:open={openState.audit} bind:this={auditCard}>
    <summary>Audit log</summary>
    {#if entries.length === 0}
      <p class="muted">No entries yet.</p>
    {:else}
      <div class="panel-actions">
        <button type="button" class="ghost" onclick={() => copyText('audit', auditText())}>
          {copied === 'audit' ? 'Copied' : 'Copy'}
        </button>
        <button type="button" class="ghost" onclick={() => downloadText('audit.log', auditText())}>Download</button>
        <button type="button" class="ghost" onclick={() => toggleMaximize(auditCard)}>
          {maximized === 'audit' ? 'Restore' : 'Maximize'}
        </button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead>
          <tbody>
            {#each entries as e}
              <tr>
                <td>{new Date(e.TS).toLocaleString()}</td>
                <td>{e.Actor}</td>
                <td>{e.Action}</td>
                <td class="muted">{e.Detail}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </details>

  <details class="card" bind:open={openState.openvpn} bind:this={ovpnCard}>
    <summary>OpenVPN log</summary>
    {#if ovpnLines.length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      <div class="panel-actions">
        <button type="button" class="ghost" onclick={() => copyText('openvpn', ovpnLines.join('\n'))}>
          {copied === 'openvpn' ? 'Copied' : 'Copy'}
        </button>
        <button type="button" class="ghost" title="Downloads what's shown here (last 200 lines) — for the complete file, use Download all logs"
          onclick={() => downloadText('openvpn.log', ovpnLines.join('\n'))}>Download</button>
        <button type="button" class="ghost" onclick={() => toggleMaximize(ovpnCard)}>
          {maximized === 'openvpn' ? 'Restore' : 'Maximize'}
        </button>
      </div>
      <pre class="logbox" bind:this={ovpnBox}>{ovpnLines.join('\n')}</pre>
    {/if}
  </details>

  <details class="card" bind:open={openState.ovcp} bind:this={ovcpCard}>
    <summary>OVCP log</summary>
    {#if ovcpLines.length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      <div class="panel-actions">
        <button type="button" class="ghost" onclick={() => copyText('ovcp', ovcpLines.join('\n'))}>
          {copied === 'ovcp' ? 'Copied' : 'Copy'}
        </button>
        <button type="button" class="ghost" title="Downloads what's shown here (last 200 lines) — for the complete file, use Download all logs"
          onclick={() => downloadText('ovcp.log', ovcpLines.join('\n'))}>Download</button>
        <button type="button" class="ghost" onclick={() => toggleMaximize(ovcpCard)}>
          {maximized === 'ovcp' ? 'Restore' : 'Maximize'}
        </button>
      </div>
      <pre class="logbox" bind:this={ovcpBox}>{ovcpLines.join('\n')}</pre>
    {/if}
  </details>
</div>

<style>
  .logs-head {
    display: flex; flex-wrap: wrap; justify-content: flex-end; align-items: center;
    gap: 6px 14px; margin-bottom: 10px; font-size: 12px;
  }
  .poll-pick { display: flex; align-items: center; gap: 6px; margin: 0; }
  .poll-pick select, .poll-pick input { width: auto; }
  .poll-pick select { padding: 3px 6px; font-size: 12px; }
  .logs-head button.ghost, .panel-actions button.ghost { padding: 3px 10px; font-size: 12px; }
  .panel-actions { display: flex; justify-content: flex-end; gap: 6px; margin-bottom: 6px; }
  /* CSS columns (not grid) so panels reflow natively when a <details> is
     toggled — a closed panel frees its space immediately, no JS layout code. */
  .logs-grid { column-width: 420px; column-gap: 22px; }
  .logs-grid :global(.card) { break-inside: avoid; margin-bottom: 22px; padding: 10px 14px; }
  summary { cursor: pointer; font-size: 15px; font-weight: 600; letter-spacing: .02em; }
  details[open] summary { margin-bottom: 14px; }
  /* compact by default; native resize handle (drag the corner) covers
     "let me make it bigger" without any drag-handler JS or min/max logic —
     the browser already clamps against min-height/max-height for us.
     fit-content caps both ends at the log's actual content size: a short
     log starts smaller than 260px, and dragging can't stretch it past its
     own content (min() also keeps a huge log capped at 80vh either way). */
  .logbox, .table-wrap {
    height: min(260px, fit-content); min-height: 80px; max-height: min(80vh, fit-content);
    overflow: auto; resize: vertical; cursor: grab;
  }
  .logbox {
    font-family: var(--mono); font-size: 12px; line-height: 1.4; white-space: pre-wrap;
    word-break: break-all; margin: 0; color: var(--text);
  }
  /* Maximize = native Fullscreen API on the .card; give the scroll boxes
     the freed-up viewport space instead of staying capped at 260px. */
  .card:fullscreen { padding: 18px; overflow: auto; }
  .card:fullscreen .logbox, .card:fullscreen .table-wrap { max-height: calc(100vh - 100px); resize: none; }
</style>
