<script>
  import { tick } from 'svelte'
  import { api } from './api.js'
  let { isAdmin } = $props()
  let entries = $state([])
  let ovpnLines = $state([])
  let ovcpLines = $state([])
  let ovpnBox = $state(), ovcpBox = $state()
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
</div>

<div class="logs-grid">
  <details class="card" bind:open={openState.audit}>
    <summary>Audit log</summary>
    {#if entries.length === 0}
      <p class="muted">No entries yet.</p>
    {:else}
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
    {/if}
  </details>

  <details class="card" bind:open={openState.openvpn}>
    <summary>OpenVPN log</summary>
    {#if ovpnLines.length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      <pre class="logbox" bind:this={ovpnBox}>{ovpnLines.join('\n')}</pre>
    {/if}
  </details>

  <details class="card" bind:open={openState.ovcp}>
    <summary>OVCP log</summary>
    {#if ovcpLines.length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      <pre class="logbox" bind:this={ovcpBox}>{ovcpLines.join('\n')}</pre>
    {/if}
  </details>
</div>

<style>
  .logs-head { display: flex; justify-content: flex-end; align-items: center; gap: 12px; margin-bottom: 14px; }
  .poll-pick { display: flex; align-items: center; gap: 8px; margin: 0; font-size: 13px; }
  .poll-pick select, .poll-pick input { width: auto; }
  /* CSS columns (not grid) so panels reflow natively when a <details> is
     toggled — a closed panel frees its space immediately, no JS layout code. */
  .logs-grid { column-width: 420px; column-gap: 22px; }
  .logs-grid :global(.card) { break-inside: avoid; margin-bottom: 22px; }
  summary { cursor: pointer; font-size: 15px; font-weight: 600; letter-spacing: .02em; }
  details[open] summary { margin-bottom: 14px; }
  .logbox {
    font-family: var(--mono); font-size: 12px; white-space: pre-wrap; word-break: break-all;
    max-height: 420px; overflow-y: auto; margin: 0; color: var(--text);
  }
</style>
