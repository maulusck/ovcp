<script>
  import {
    api, fmtBytes, sortRows, matchesQuery, toggleSort, sortMark, toggleSearch, autofocus,
  } from './api.js'

  let samples = $state([])
  let sessions = $state([])
  let revokedCNs = $state(new Set())
  let search = $state({ open: false, query: '' })
  let err = $state('')

  let sort = $state({ key: null, desc: false })
  const SORT_GETTERS = {
    cn: (s) => s.CN, disconnected: (s) => s.DisconnectedAt,
    duration: (s) => new Date(s.DisconnectedAt) - new Date(s.ConnectedAt),
    recv: (s) => s.BytesRecv, sent: (s) => s.BytesSent,
  }

  const POLL_KEY = 'ovcp_stats_poll'
  let pollSec = $state(Number(localStorage.getItem(POLL_KEY) ?? 30))

  async function load() {
    try {
      const [d, certs] = await Promise.all([api('GET', '/stats'), api('GET', '/certs')])
      samples = d.samples || []
      sessions = d.sessions || []
      revokedCNs = new Set(certs.filter(c => c.Revoked).map(c => c.CN))
    } catch (x) { err = x.error }
  }
  load()

  $effect(() => {
    localStorage.setItem(POLL_KEY, pollSec)
    if (!pollSec) return
    const t = setInterval(load, pollSec * 1000)
    return () => clearInterval(t)
  })

  // per-client view: filter the same session history instead of a second
  // query — it's already capped at 200 rows, plenty to filter client-side.
  const filtered = $derived.by(() => {
    const out = sessions.filter((s) => matchesQuery(s, search.query, (x) => x.CN))
    return sort.key ? sortRows(out, SORT_GETTERS[sort.key], sort.desc) : out
  })

  const dropsLast24h = $derived(
    sessions.filter(s => Date.now() - new Date(s.DisconnectedAt).getTime() < 86400000).length)

  // equal-spaced sparkline: samples are one/minute so gaps (VPN down) just
  // compress visually rather than needing real time-axis math.
  function points(vals, h = 30) {
    if (vals.length < 2) return ''
    const max = Math.max(...vals, 1)
    const step = 100 / (vals.length - 1)
    return vals.map((v, i) => `${(i * step).toFixed(2)},${(h - (v / max) * h).toFixed(2)}`).join(' ')
  }
  function fmtDur(sec) {
    if (sec < 60) return Math.round(sec) + 's'
    if (sec < 3600) return Math.round(sec / 60) + 'm'
    return (sec / 3600).toFixed(1) + 'h'
  }
</script>

<div class="stats-head">
  {#if err}<p class="err">{err}</p>{/if}
  <label class="poll-pick">Auto-refresh
    <select bind:value={pollSec}>
      <option value={0}>Off</option>
      <option value={15}>15s</option>
      <option value={30}>30s</option>
      <option value={60}>60s</option>
    </select>
  </label>
</div>

<div class="stats-grid">
  <div class="card">
    <h2>Connected clients</h2>
    {#if samples.length < 2}
      <p class="muted">Not enough history yet — sampled every minute.</p>
    {:else}
      <svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none">
        <polyline points={points(samples.map(s => s.Clients))} />
      </svg>
      <p class="muted">{samples.at(-1).Clients} now · last {samples.length} samples</p>
    {/if}
  </div>

  <div class="card">
    <h2>Traffic</h2>
    {#if samples.length < 2}
      <p class="muted">Not enough history yet — sampled every minute.</p>
    {:else}
      <svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none">
        <polyline class="recv" points={points(samples.map(s => s.BytesRecv))} />
        <polyline class="sent" points={points(samples.map(s => s.BytesSent))} />
      </svg>
      <p class="muted">
        <span class="recv-label">received</span> / <span class="sent-label">sent</span>
        — {fmtBytes(samples.at(-1).BytesRecv)} / {fmtBytes(samples.at(-1).BytesSent)} now
      </p>
    {/if}
  </div>

  <div class="card wide">
    <h2>Per-client sessions
      <button type="button" class="ghost" class:active={search.open} onclick={() => toggleSearch(search)}>Filter</button>
      {#if search.open}
        <input type="search" class="search-input" bind:value={search.query} placeholder="Filter by common name…" use:autofocus />
      {/if}
    </h2>
    <p class="muted">{dropsLast24h} disconnect{dropsLast24h === 1 ? '' : 's'} in the last 24h</p>
    {#if filtered.length === 0}
      <p class="muted">No completed sessions{search.query ? ' match' : ' yet'}.</p>
    {:else}
      <table>
        <thead><tr>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'cn')}>Common name{sortMark(sort, 'cn')}</button></th>
          <th>Real address</th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'disconnected')}>Disconnected{sortMark(sort, 'disconnected')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'duration')}>Duration{sortMark(sort, 'duration')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'recv')}>Received{sortMark(sort, 'recv')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'sent')}>Sent{sortMark(sort, 'sent')}</button></th>
        </tr></thead>
        <tbody>
          {#each filtered as s}
            <tr>
              <td>{s.CN}{#if revokedCNs.has(s.CN)}<span class="revoked" title="Certificate revoked">revoked</span>{/if}</td>
              <td>{s.RealAddress}</td>
              <td>{new Date(s.DisconnectedAt).toLocaleString()}</td>
              <td>{fmtDur((new Date(s.DisconnectedAt) - new Date(s.ConnectedAt)) / 1000)}</td>
              <td>{fmtBytes(s.BytesRecv)}</td>
              <td>{fmtBytes(s.BytesSent)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<style>
  .stats-head { display: flex; justify-content: flex-end; margin-bottom: 10px; font-size: 12px; }
  .stats-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(min(320px, 100%), 1fr));
    gap: 22px; align-items: start;
  }
  .card.wide { grid-column: 1 / -1; }
  .spark { width: 100%; height: 60px; display: block; }
  .spark polyline { fill: none; stroke: var(--amber); stroke-width: 1.5; vector-effect: non-scaling-stroke; }
  .spark polyline.recv { stroke: var(--ok); }
  .spark polyline.sent { stroke: var(--bad); }
  .recv-label { color: var(--ok); }
  .sent-label { color: var(--bad); }
  .revoked {
    margin-left: 6px; font-family: var(--mono); font-size: 10px; text-transform: uppercase;
    color: var(--bad); border: 1px solid var(--bad); border-radius: 999px; padding: 1px 6px;
  }
</style>
