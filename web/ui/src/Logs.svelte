<script>
  import { tick } from 'svelte'
  import { api } from './api.js'
  let { isAdmin } = $props()

  // the two plain-text log panels are identical except for these fields;
  // the audit panel stays bespoke (it's a table, newest-first, no autoscroll).
  const LOGS = [
    { id: 'openvpn', title: 'OpenVPN log', file: 'openvpn.log' },
    { id: 'ovcp', title: 'OVCP log', file: 'ovcp.log' },
  ]
  let lines = $state({ openvpn: [], ovcp: [] })
  let entries = $state([])
  let boxes = $state({}) // id -> scroll container ('audit' included)
  let cards = $state({}) // id -> <details> element, for Maximize
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

  // clamp a box's height to its content: CSS fit-content doesn't work in the
  // vertical axis in Firefox, so measure instead. Keeps a short log from
  // showing dead space (on load) and a resize drag from stretching past the
  // end of the log (clamped again on pointerup).
  function fitToContent(el) {
    if (!el) return
    const cur = el.offsetHeight
    el.style.height = 'auto'
    el.style.height = Math.min(cur, el.offsetHeight) + 'px'
  }

  async function loadLog(id) {
    try {
      lines[id] = (await api('GET', '/logs/' + id)).lines
      await tick()
      const el = boxes[id]
      fitToContent(el)
      if (autoscroll && el) el.scrollTop = el.scrollHeight
    } catch (x) { err = x.error }
  }
  async function loadAudit() {
    try { entries = await api('GET', '/audit'); await tick(); fitToContent(boxes.audit) }
    catch (x) { err = x.error }
  }
  async function loadDebug() {
    try { debugOn = (await api('GET', '/debug')).debug } catch (x) { err = x.error }
  }
  function refresh() { loadAudit(); LOGS.forEach((l) => loadLog(l.id)); loadDebug() }
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
  let maximized = $state(null) // panel id | null
  function toggleMaximize(id) {
    const el = cards[id]
    if (!el) return
    if (document.fullscreenElement === el) document.exitFullscreen()
    else el.requestFullscreen()
  }
  $effect(() => {
    const onChange = () =>
      (maximized = Object.keys(cards).find((k) => cards[k] === document.fullscreenElement) ?? null)
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

{#snippet actions(id, filename, text)}
  <div class="panel-actions">
    <button type="button" class="ghost" onclick={() => copyText(id, text())}>
      {copied === id ? 'Copied' : 'Copy'}
    </button>
    <button type="button" class="ghost" title="Downloads what's shown here — for complete files, use Download all logs"
      onclick={() => downloadText(filename, text())}>Download</button>
    <button type="button" class="ghost" onclick={() => toggleMaximize(id)}>
      {maximized === id ? 'Restore' : 'Maximize'}
    </button>
  </div>
{/snippet}

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
  <details class="card" bind:open={openState.audit} bind:this={cards.audit}>
    <summary>Audit log</summary>
    {#if entries.length === 0}
      <p class="muted">No entries yet.</p>
    {:else}
      {@render actions('audit', 'audit.log', auditText)}
      <!-- svelte-ignore a11y_no_static_element_interactions (pointerup only clamps the resize drag, it's not an interactive control) -->
      <div class="scrollbox" bind:this={boxes.audit} onpointerup={(e) => fitToContent(e.currentTarget)}>
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

  {#each LOGS as l}
    <details class="card" bind:open={openState[l.id]} bind:this={cards[l.id]}>
      <summary>{l.title}</summary>
      {#if lines[l.id].length === 0}
        <p class="muted">No log yet.</p>
      {:else}
        {@render actions(l.id, l.file, () => lines[l.id].join('\n'))}
        <pre class="scrollbox logbox" bind:this={boxes[l.id]}
          onpointerup={(e) => fitToContent(e.currentTarget)}>{lines[l.id].join('\n')}</pre>
      {/if}
    </details>
  {/each}
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
  /* grid, not CSS columns: columns rebalance every card across the page
     while a box is being resized (the "bouncing" bug); in a grid each card
     stays in its cell and a drag only grows its own row. min(420px, 100%)
     keeps narrow screens from overflowing horizontally. */
  .logs-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(min(420px, 100%), 1fr));
    gap: 22px; align-items: start;
  }
  .logs-grid :global(.card) { padding: 10px 14px; }
  summary { cursor: pointer; font-size: 15px; font-weight: 600; letter-spacing: .02em; }
  details[open] summary { margin-bottom: 14px; }
  /* compact by default (260px cap, shorter if the log is shorter — see
     fitToContent, which does what CSS fit-content can't cross-browser);
     the native resize handle can grow a box up to 80vh, and fitToContent
     snaps a drag back down to the content height on release. */
  .scrollbox {
    height: 260px; min-height: 60px; max-height: 80vh;
    overflow: auto; resize: vertical; cursor: grab;
  }
  .logbox {
    font-family: var(--mono); font-size: 12px; line-height: 1.4; white-space: pre-wrap;
    word-break: break-all; margin: 0; color: var(--text);
  }
  /* Maximize = native Fullscreen API on the .card; give the scroll box the
     freed-up viewport space instead of staying capped. */
  .card:fullscreen { padding: 18px; overflow: auto; }
  .card:fullscreen .scrollbox {
    /* !important so fullscreen wins over the inline height set by drags/fitToContent */
    height: auto !important; max-height: calc(100vh - 100px); resize: none;
  }
</style>
