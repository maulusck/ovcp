<script>
  import { tick } from 'svelte'
  import { api, downloadBlob, copyToClipboard, matchesQuery, sortRows, toggleSort, sortMark, toggleSearch, autofocus, fmtTimestamp, flash } from './api.js'
  import Msg from './Msg.svelte'
  let { isAdmin, canOperate } = $props()

  // dnsmasq's syslog line has no year — same fmtTimestamp shape, just without one.
  const fmtTimeNoYear = (d) => d.toLocaleString(navigator.language || 'en-US',
    { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).replace(',', '')

  // Splits a line into time/level/msg: ovcp's "time=... level=X ..." text, its -log-json
  // form, openvpn's "YYYY-MM-DD HH:MM:SS ...", or dnsmasq's yearless syslog
  // style "Mon D HH:MM:SS proc[pid]: ...".
  function parseLine(line) {
    let raw = '', msg = line, level
    if (line[0] === '{') {
      try {
        const j = JSON.parse(line)
        const extra = Object.keys(j).filter(k => k !== 'time' && k !== 'level' && k !== 'msg')
          .map(k => `${k}=${j[k]}`).join(' ')
        raw = j.time; level = (j.level || 'info').toLowerCase()
        msg = extra ? `${j.msg} ${extra}` : j.msg
        return { time: fmtTimestamp(new Date(raw)), ts: new Date(raw).getTime(), level, msg }
      } catch { /* not JSON after all — fall through to text parsing */ }
    }
    let m = line.match(/^time=(\S+)\s+level=(\w+)\s+(.*)$/)
    if (m) {
      raw = m[1]; level = m[2].toLowerCase(); msg = m[3]
    } else if ((m = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+:\s*(.*)$/))) {
      msg = m[2]
      level = /\b(error|fatal|fail(ed|ure)?)\b/i.test(msg) ? 'error'
        : /\bwarn(ing)?\b/i.test(msg) ? 'warn' : 'info'
      // year is a parsing scratch value only — never shown (fmtTimeNoYear omits it)
      const d = new Date(m[1] + ' 2000')
      return { time: isNaN(d) ? '' : fmtTimeNoYear(d), ts: isNaN(d) ? 0 : d.getTime(), level, msg }
    } else {
      m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$/)
      if (m) { raw = m[1]; msg = m[2] }
      level = /\b(error|fatal|fail(ed|ure)?)\b/i.test(msg) ? 'error'
        : /\bwarn(ing)?\b/i.test(msg) ? 'warn' : 'info'
    }
    const d = raw && new Date(raw.replace(' ', 'T'))
    return { time: d && !isNaN(d) ? fmtTimestamp(d) : '', ts: d && !isNaN(d) ? d.getTime() : 0, level, msg }
  }

  // the two log panels render as a table like the audit panel; audit stays bespoke
  // (newest-first, no autoscroll) since it's real structured rows, not parsed text.
  const LOGS = [
    { id: 'openvpn', title: 'OpenVPN log', file: 'openvpn.log' },
    { id: 'ovcp', title: 'OVCP log', file: 'ovcp.log' },
    { id: 'dnsmasq', title: 'Dnsmasq log', file: 'dnsmasq.log' },
  ]
  const PANEL_IDS = ['audit', ...LOGS.map((l) => l.id)] // initial order
  let lines = $state({ openvpn: [], ovcp: [], dnsmasq: [] })
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
    { audit: true, openvpn: false, ovcp: true, dnsmasq: false },
    JSON.parse(localStorage.getItem(OPEN_KEY) || '{}')))

  // MRU order for expanded panels only: opening one moves it to front.
  // Collapsed panels always sort after, in fixed PANEL_IDS order — no
  // tracking needed for those.
  const ORDER_KEY = 'ovcp_logs_order'
  const savedOrder = JSON.parse(localStorage.getItem(ORDER_KEY) || 'null') || []
  let order = $state([
    ...savedOrder.filter((id) => PANEL_IDS.includes(id)),
    ...PANEL_IDS.filter((id) => !savedOrder.includes(id)),
  ])
  const bumpFront = (id) => (order = [id, ...order.filter((x) => x !== id)])

  // clamp a box's height to content: CSS fit-content doesn't work vertically in Firefox,
  // so measure instead (also re-clamps a resize drag on pointerup).
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
      err = ''
    } catch (x) { flash(v => err = v, x.error) }
  }
  async function loadAudit() {
    try { entries = await api('GET', '/audit'); await tick(); fitToContent(boxes.audit); err = '' }
    catch (x) { flash(v => err = v, x.error) }
  }
  async function loadDebug() {
    try { debugOn = (await api('GET', '/debug')).debug; err = '' } catch (x) { flash(v => err = v, x.error) }
  }
  // per-panel refresh (maximized view's own button) — every id already has a loader.
  const refreshOne = (id) => (id === 'audit' ? loadAudit() : loadLog(id))
  let refreshing = $state(false)
  async function refresh() {
    if (refreshing) return
    refreshing = true
    try { await Promise.all([loadAudit(), ...LOGS.map((l) => loadLog(l.id)), loadDebug()]) }
    finally { refreshing = false }
  }
  refresh()

  const setAllOpen = (open) => (openState = { audit: open, ...Object.fromEntries(LOGS.map((l) => [l.id, open])) })

  // odd expanded count leaves one dangling grid cell — stack collapsed panels into it.
  const openIds = $derived(order.filter((id) => openState[id]))
  const collapsedIds = $derived(PANEL_IDS.filter((id) => !openState[id]))
  const stackCollapsed = $derived(openIds.length % 2 === 1 && collapsedIds.length > 0)

  // per-panel filter (audit + each log) — one {open, query} per id, same
  // shape/toggle as every other table (see api.js's toggleSearch).
  let search = $state({
    audit: { open: false, query: '' }, openvpn: { open: false, query: '' },
    ovcp: { open: false, query: '' }, dnsmasq: { open: false, query: '' },
  })
  const AUDIT_SORT_GETTERS = { ts: (e) => e.TS, actor: (e) => e.Actor, action: (e) => e.Action, detail: (e) => e.Detail }
  let auditSort = $state({ key: null, desc: false })
  const filteredEntries = $derived.by(() => {
    const out = entries.filter((e) => matchesQuery(e, search.audit.query, (x) => x.Actor, (x) => x.Action, (x) => x.Detail))
    return auditSort.key ? sortRows(out, AUDIT_SORT_GETTERS[auditSort.key], auditSort.desc) : out
  })

  // level-only filter, openvpn/ovcp panels only (audit has no level) —
  // 'all' skips it entirely so the common case parses each line once, not twice.
  const LEVEL_RANK = { debug: 0, info: 1, warn: 2, error: 3 }
  let levelFilter = $state({ openvpn: 'all', ovcp: 'all', dnsmasq: 'all' })
  const LOG_SORT_GETTERS = {
    ts: (line) => parseLine(line).ts, level: (line) => LEVEL_RANK[parseLine(line).level] ?? 1,
    msg: (line) => parseLine(line).msg,
  }
  let logSort = $state({ openvpn: { key: null, desc: false }, ovcp: { key: null, desc: false }, dnsmasq: { key: null, desc: false } })
  const visibleLines = (id) => {
    const out = lines[id]
      .filter((line) => matchesQuery(line, search[id].query, (x) => x))
      .filter((line) => levelFilter[id] === 'all' || LEVEL_RANK[parseLine(line).level] >= LEVEL_RANK[levelFilter[id]])
    return logSort[id].key ? sortRows(out, LOG_SORT_GETTERS[logSort[id].key], logSort[id].desc) : out
  }

  async function toggleDebug(e) {
    const want = e.target.checked
    try { debugOn = (await api('POST', '/debug', { Debug: want })).debug; err = '' }
    catch (x) { flash(v => err = v, x.error); e.target.checked = !want }
  }

  let copied = $state('')
  async function copyText(panel, text) {
    if (!(await copyToClipboard(text, 'Log text'))) return
    flash(v => copied = v, panel, 1200)
  }
  const auditText = () => filteredEntries.map(e =>
    `${fmtTimestamp(new Date(e.TS))} ${e.Actor} ${e.Action} ${e.Detail}`).join('\n')

  // archive download has fixed server-side filenames, no request input — per-log
  // copy/download stays client-side instead of adding a parametrized endpoint.
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
  $effect(() => { localStorage.setItem(ORDER_KEY, JSON.stringify(order)) })
</script>

{#snippet actions(id, filename, text, hasLevel)}
  <div class="panel-actions">
    {#if hasLevel}
      <select bind:value={levelFilter[id]} title="Show only this level and above">
        <option value="all">All levels</option>
        <option value="warn">Warn+</option>
        <option value="error">Errors only</option>
      </select>
    {/if}
    <button type="button" class="ghost" class:active={search[id].open} onclick={() => toggleSearch(search[id])}>Filter</button>
    {#if search[id].open}
      <input type="search" class="search-input" bind:value={search[id].query} placeholder="Filter…" use:autofocus
        onkeydown={(e) => e.key === 'Enter' && refresh()} />
    {/if}
    <button type="button" class="ghost" onclick={() => copyText(id, text())}>
      {copied === id ? 'Copied' : 'Copy'}
    </button>
    <button type="button" class="ghost" title="Downloads what's shown here — for complete files, use Download all logs"
      onclick={() => downloadText(filename, text())}>Download</button>
    <button type="button" class="ghost" onclick={() => toggleMaximize(id)}>
      {maximized === id ? 'Restore' : 'Maximize'}
    </button>
    {#if maximized === id}
      <button type="button" class="ghost icon-btn" title="Refresh log" onclick={() => refreshOne(id)}>
        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12a9 9 0 1 1-3-6.7" /><polyline points="21 3 21 9 15 9" />
        </svg>
      </button>
    {/if}
  </div>
{/snippet}

<div class="logs-head">
  <Msg type="err" text={err} />
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
      <option value={60}>60s</option>
    </select>
  </label>
  <button type="button" class="ghost" onclick={refresh} disabled={refreshing} title="Reload all three panels now">
    {refreshing ? 'Refreshing…' : 'Refresh now'}</button>
  <button type="button" class="ghost" onclick={() => setAllOpen(true)}>Expand all</button>
  <button type="button" class="ghost" onclick={() => setAllOpen(false)}>Collapse all</button>
  <button type="button" class="ghost" onclick={downloadAllLogs} disabled={!canOperate}
    title={canOperate ? "Full audit package: logs, audit trail, VPN/cert/user/config status — unencrypted, for security/ops review" : "Operator or higher"}>
    Download audit package</button>
</div>

{#snippet auditPanel()}
  <details class="card" bind:open={openState.audit} bind:this={cards.audit}
    ontoggle={(e) => e.target.open && bumpFront('audit')}>
    <summary onclick={(e) => maximized === 'audit' && e.preventDefault()}>Audit log</summary>
    {#if entries.length === 0}
      <p class="muted">No entries yet.</p>
    {:else}
      {@render actions('audit', 'audit.log', auditText)}
      {#if filteredEntries.length === 0}
        <p class="muted">No entries match.</p>
      {:else}
      <!-- svelte-ignore a11y_no_static_element_interactions (pointerup only clamps the resize drag, it's not an interactive control) -->
      <div class="scrollbox" bind:this={boxes.audit} onpointerup={(e) => fitToContent(e.currentTarget)}>
        <table class="logtable">
          <thead><tr>
            <th><button class="th-sort" onclick={() => toggleSort(auditSort, 'ts')}>Time{sortMark(auditSort, 'ts')}</button></th>
            <th><button class="th-sort" onclick={() => toggleSort(auditSort, 'actor')}>Actor{sortMark(auditSort, 'actor')}</button></th>
            <th><button class="th-sort" onclick={() => toggleSort(auditSort, 'action')}>Action{sortMark(auditSort, 'action')}</button></th>
            <th><button class="th-sort" onclick={() => toggleSort(auditSort, 'detail')}>Detail{sortMark(auditSort, 'detail')}</button></th>
          </tr></thead>
          <tbody>
            {#each filteredEntries as e}
              <tr>
                <td class="muted">{fmtTimestamp(new Date(e.TS))}</td>
                <td>{e.Actor}</td>
                <td>{e.Action}</td>
                <td>{e.Detail}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {/if}
    {/if}
  </details>
{/snippet}

{#snippet logPanel(l)}
  <details class="card" bind:open={openState[l.id]} bind:this={cards[l.id]}
    ontoggle={(e) => e.target.open && bumpFront(l.id)}>
    <summary onclick={(e) => maximized === l.id && e.preventDefault()}>{l.title}</summary>
    {#if lines[l.id].length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      {@render actions(l.id, l.file, () => visibleLines(l.id).join('\n'), true)}
      {#if visibleLines(l.id).length === 0}
        <p class="muted">No log lines match.</p>
      {:else}
      <!-- svelte-ignore a11y_no_static_element_interactions (pointerup only clamps the resize drag, it's not an interactive control) -->
      <div class="scrollbox" bind:this={boxes[l.id]} onpointerup={(e) => fitToContent(e.currentTarget)}>
        <table class="logtable">
          <thead><tr>
            <th><button class="th-sort" onclick={() => toggleSort(logSort[l.id], 'ts')}>Time{sortMark(logSort[l.id], 'ts')}</button></th>
            <th><button class="th-sort" onclick={() => toggleSort(logSort[l.id], 'level')}>Level{sortMark(logSort[l.id], 'level')}</button></th>
            <th><button class="th-sort" onclick={() => toggleSort(logSort[l.id], 'msg')}>Message{sortMark(logSort[l.id], 'msg')}</button></th>
          </tr></thead>
          <tbody>
            {#each visibleLines(l.id) as line}
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
    {/if}
  </details>
{/snippet}

{#snippet panel(id)}
  {#if id === 'audit'}{@render auditPanel()}{:else}{@render logPanel(LOGS.find((l) => l.id === id))}{/if}
{/snippet}

<div class="logs-grid">
  {#each openIds as id (id)}{@render panel(id)}{/each}
  {#if stackCollapsed}
    <div class="collapsed-stack">
      {#each collapsedIds as id (id)}{@render panel(id)}{/each}
    </div>
  {:else}
    {#each collapsedIds as id (id)}{@render panel(id)}{/each}
  {/if}
</div>

<style>
  .panel-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; margin-bottom: 6px; }
  /* same size/shape as sibling .ghost buttons, just square instead of wide */
  .panel-actions :global(button.icon-btn) { padding: 3px; aspect-ratio: 1; display: grid; place-items: center; }
  /* 600px min caps it at 2 columns even on the widened logs main;
     dense backfills gaps left by a resized/collapsed neighbor */
  .logs-grid { grid-template-columns: repeat(auto-fit, minmax(min(600px, 100%), 1fr)); grid-auto-flow: dense; }
  .logs-grid :global(.card) { padding: 10px 14px; }
  /* fills the one dangling grid cell; full-width cards stacked top to bottom */
  .collapsed-stack { display: flex; flex-direction: column; gap: 4px; }
  summary { cursor: pointer; font-size: 15px; font-weight: 600; letter-spacing: .02em; }
  summary:hover { color: var(--amber); }
  details[open] summary { margin-bottom: 14px; }
  /* height clamps to content via fitToContent (CSS fit-content isn't cross-browser);
     the resize handle can grow it, fitToContent snaps back down on release. */
  .scrollbox {
    height: 260px; min-height: 60px; max-height: 80vh;
    overflow: auto; resize: vertical; cursor: grab;
  }
  /* desktop: fill toward window bottom instead of a cramped fixed 260px (fitToContent
     still shrinks for short logs); mobile keeps the fixed height, App.svelte's nav breakpoint. */
  @media (min-width: 701px) {
    .scrollbox { height: calc(100vh - 320px); }
  }
  /* shared by all three panels; no cell wraps — scrollbox scrolls horizontally instead,
     same as Users/Certs tables, so long lines stay on one line and stay readable. */
  .logtable { font-size: 12px; }
  .logtable th, .logtable td { padding: 2px 8px; }
  .logtable td { white-space: pre; }
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
  /* toggle is disabled while maximized (see onclick guards above); the arrow would be a dead affordance */
  .card:fullscreen summary { list-style: none; cursor: default; color: var(--amber); font-size: 17px; }
  .card:fullscreen summary::-webkit-details-marker { display: none; }
</style>
