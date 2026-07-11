<script>
  import { api } from './api.js'
  let entries = $state([])
  let ovpnLines = $state([])
  let ovcpLines = $state([])
  let err = $state('')
  let pollSec = $state(15)

  async function loadAudit() {
    try { entries = await api('GET', '/audit') } catch (x) { err = x.error }
  }
  async function loadOpenVPN() {
    try { ovpnLines = (await api('GET', '/logs/openvpn')).lines } catch (x) { err = x.error }
  }
  async function loadOVCP() {
    try { ovcpLines = (await api('GET', '/logs/ovcp')).lines } catch (x) { err = x.error }
  }
  function refresh() { loadAudit(); loadOpenVPN(); loadOVCP() }
  refresh()

  $effect(() => {
    if (!pollSec) return
    const t = setInterval(refresh, pollSec * 1000)
    return () => clearInterval(t)
  })
</script>

<div class="logs-head">
  {#if err}<p class="err">{err}</p>{/if}
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
  <details class="card" open>
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

  <details class="card">
    <summary>OpenVPN log</summary>
    {#if ovpnLines.length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      <pre class="logbox">{ovpnLines.join('\n')}</pre>
    {/if}
  </details>

  <details class="card">
    <summary>OVCP log</summary>
    {#if ovcpLines.length === 0}
      <p class="muted">No log yet.</p>
    {:else}
      <pre class="logbox">{ovcpLines.join('\n')}</pre>
    {/if}
  </details>
</div>

<style>
  .logs-head { display: flex; justify-content: flex-end; align-items: center; gap: 12px; margin-bottom: 14px; }
  .poll-pick { display: flex; align-items: center; gap: 8px; margin: 0; font-size: 13px; }
  .poll-pick select { width: auto; }
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
