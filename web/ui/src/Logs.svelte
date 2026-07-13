<script>
  import { tick } from 'svelte'
  import { api, downloadBlob, copyToClipboard } from './api.js'
  let { isAdmin } = $props()

  // one shared format for every timestamp in this file (audit + both log
  // tables) — 24h, no AM/PM, no date/time comma, browser locale otherwise.
  const fmtTime = (d) => d.toLocaleString(undefined, { hour12: false }).replace(',', '')

  // Splits a line into time/level/msg. Two known prefixes: ovcp's own
  // "time=... level=X ..." and openvpn's "YYYY-MM-DD HH:MM:SS ..." (see the
  // fixture in internal/api/logs_test.go). The raw timestamp is reformatted
  // with fmtTime so all three panels show one consistent format instead of
  // three raw wire formats (and the ISO string's "Z" never leaks through —
  // fmtTime always renders in the browser's local time).
  function parseLine(line) {
    let raw = '', msg = line, level
    let m = line.match(/^time=(\S+)\s+level=(\w+)\s+(.*)$/)
    if (m) {
      raw = m[1]; level = m[2].toLowerCase(); msg = m[3]
    } else {
      m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$/)
      if (m) { raw = m[1]; msg = m[2] }
      level = /\b(error|fatal|fail(ed|ure)?)\b/i.test(msg) ? 'error'
        : /\bwarn(ing)?\b/i.test(msg) ? 'warn' : 'info'
    }
    const d = raw && new Date(raw.replace(' ', 'T'))
    return { time: d && !isNaN(d) ? fmtTime(d) : '', level, msg }
  }

  // the two log panels render as a table like the audit panel; audit stays
  // bespoke in one way (newest-first, no autoscroll) since it's real
  // structured rows, not parsed text.
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

  // clamp a box's height to its content: CSS fit-content doesn't work in
  // the vertical axis in Firefox, so measure instead (also re-clamps a
  // resize drag on pointerup, so it can't stretch past the log's end).
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
  let refreshing = $state(false)
  async function refresh() {
    if (refreshing) return
    refreshing = true
    try { await Promise.all([loadAudit(), ...LOGS.map((l) => loadLog(l.id)), loadDebug()]) }
    finally { refreshing = false }
  }
  refresh()

  const setAllOpen = (open) => (openState = { audit: open, ...Object.fromEntries(LOGS.map((l) => [l.id, open])) })

  async function toggleDebug(e) {
    const want = e.target.checked
    try { debugOn = (await api('POST', '/debug', { Debug: want })).debug }
    catch (x) { err = x.error; e.target.checked = !want }
  }

  let copied = $state('')
  async function copyText(panel, text) {
    if (!(await copyToClipboard(text, 'Log text'))) return
    copied = panel
    setTimeout(() => (copied = ''), 1200)
  }
  const auditText = () => entries.map(e =>
    `${fmtTime(new Date(e.TS))} ${e.Actor} ${e.Action} ${e.Detail}`).join('\n')

  // the archive bundle takes no request input at all (fixed server-side
  // filenames) — per-log copy/download stays entirely client-side instead
  // of adding a parametrized single-file endpoint for it.
  const downloadAllLogs = () => (window.location.href = '/api/logs/download')

  const downloadText = (filename, text) => downloadBlob(new Blob([text], { type: 'text/plain' }), filename)

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
  <button type="button" class="ghost" onclick={refresh} disabled={refreshing} title="Reload all three panels now">
    {refreshing ? 'Refreshing…' : 'Refresh now'}</button>
  <button type="button" class="ghost" onclick={() => setAllOpen(true)}>Expand all</button>
  <button type="button" class="ghost" onclick={() => setAllOpen(false)}>Collapse all</button>
  <button type="button" class="ghost" onclick={downloadAllLogs}
    title="Full audit package: logs, audit trail, VPN/cert/user/config status — unencrypted, for security/ops review">
    Download audit package</button>
</div>

<div class="logs-grid">
  <details class="card" style="order: {openState.audit ? 0 : 1}" bind:open={openState.audit} bind:this={cards.audit}>
    <summary>Audit log</summary>
    {#if entries.length === 0}
      <p class="muted">No entries yet.</p>
    {:else}
      {@render actions('audit', 'audit.log', auditText)}
      <!-- svelte-ignore a11y_no_static_element_interactions (pointerup only clamps the resize drag, it's not an interactive control) -->
      <div class="scrollbox" bind:this={boxes.audit} onpointerup={(e) => fitToContent(e.currentTarget)}>
        <table class="logtable">
          <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead>
          <tbody>
            {#each entries as e}
              <tr>
                <td class="muted">{fmtTime(new Date(e.TS))}</td>
                <td>{e.Actor}</td>
                <td>{e.Action}</td>
                <td>{e.Detail}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </details>

  {#each LOGS as l}
    <details class="card" style="order: {openState[l.id] ? 0 : 1}" bind:open={openState[l.id]} bind:this={cards[l.id]}>
      <summary>{l.title}</summary>
      {#if lines[l.id].length === 0}
        <p class="muted">No log yet.</p>
      {:else}
        {@render actions(l.id, l.file, () => lines[l.id].join('\n'))}
        <!-- svelte-ignore a11y_no_static_element_interactions (pointerup only clamps the resize drag, it's not an interactive control) -->
        <div class="scrollbox" bind:this={boxes[l.id]} onpointerup={(e) => fitToContent(e.currentTarget)}>
          <table class="logtable">
            <thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead>
            <tbody>
              {#each lines[l.id] as line}
                {@const p = parseLine(line)}
                <tr>
                  <td class="muted">{p.time}</td>
                  <td class="log-{p.level}">{p.level}</td>
                  <td class="log-{p.level}">{p.msg}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
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
  /* grid not columns: columns rebalance every card while one resizes (bouncing).
     order is set inline from openState so open cards stay first without drag/drop.
     600px min caps it at 2 columns even on the widened logs main (600*3
     doesn't fit) — a 3rd card wraps below instead of squeezing 3 across;
     still collapses to 1 column on narrow/mobile like before. */
  .logs-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(min(600px, 100%), 1fr));
    gap: 22px; align-items: start;
  }
  .logs-grid :global(.card) { padding: 10px 14px; }
  summary { cursor: pointer; font-size: 15px; font-weight: 600; letter-spacing: .02em; }
  details[open] summary { margin-bottom: 14px; }
  /* height clamps to content via fitToContent (CSS fit-content isn't cross-browser);
     the resize handle can grow it, fitToContent snaps back down on release. */
  .scrollbox {
    height: 260px; min-height: 60px; max-height: 80vh;
    overflow: auto; resize: vertical; cursor: grab;
  }
  /* desktop: fill down toward the window bottom by default instead of a
     cramped fixed 260px (fitToContent still shrinks it for short logs);
     mobile keeps the compact fixed height — same breakpoint as App.svelte's
     nav collapse, so it stays the one stacked-card mobile layout. */
  @media (min-width: 701px) {
    .scrollbox { height: calc(100vh - 320px); }
  }
  /* shared by all three panels (audit + openvpn + ovcp) — denser than the
     default table, rows are numerous. first column (time) never wraps; last
     column (message/detail, the free-text one) wraps anywhere. */
  .logtable { font-size: 12px; }
  .logtable th, .logtable td { padding: 2px 8px; }
  .logtable td:first-child { white-space: nowrap; }
  .logtable td:last-child { white-space: pre-wrap; overflow-wrap: anywhere; }
  .logtable tbody tr:hover { background: var(--line); }
  .logtable .log-error { color: var(--bad); }
  .logtable .log-warn { color: var(--amber); }
  .logtable .log-debug { color: var(--dim); }
  /* Maximize = native Fullscreen API on the .card; give the scroll box the
     freed-up viewport space instead of staying capped. */
  .card:fullscreen { padding: 18px; overflow: auto; }
  .card:fullscreen .scrollbox {
    /* !important so fullscreen wins over the inline height set by drags/fitToContent */
    height: auto !important; max-height: calc(100vh - 100px); resize: none;
  }
</style>
