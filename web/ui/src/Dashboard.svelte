<script>
  import { api, fmtBytes, sortRows, matchesQuery, toggleSort, sortMark, toggleSearch, autofocus, fmtTimestamp, flash } from './api.js'
  import { vpn, pollOnce } from './status.svelte.js'
  import Msg from './Msg.svelte'
  let { canOperate, goToCert, dnsAvailable, caCN, caNotAfter, caStatus } = $props()
  let err = $state('')

  // At-a-glance health: cert count/warnings and the DNS leak check both
  // already exist server-side (Status()/DNSLeakWarning) — this just surfaces
  // them here instead of only in Certificates/Settings.
  let certSummary = $state({ total: 0, warn: 0 })
  api('GET', '/certs').then((certs) => {
    certSummary = { total: certs.length, warn: certs.filter((c) => c.Status === 'expiring' || c.Status === 'expired').length }
  }).catch(() => {})

  let dnsWarning = $state('')
  $effect(() => {
    if (!dnsAvailable) return
    api('GET', '/dns/config').then((d) => (dnsWarning = d.warning || '')).catch(() => {})
  })

  // no local poll loop: App.svelte already polls status app-wide (for the
  // header pill) and caches the full client list on the shared vpn state.
  async function kill(cn) {
    if (!confirm(`Disconnect ${cn}?`)) return
    try { await api('POST', '/clients/kill', { CN: cn }); pollOnce(); err = '' }
    catch (x) { flash(v => err = v, x.error) }
  }

  let search = $state({ open: false, query: '' })
  let sort = $state({ key: null, desc: false })
  const SORT_GETTERS = {
    cn: (c) => c.CN, recv: (c) => c.BytesRecv, sent: (c) => c.BytesSent,
    since: (c) => c.ConnectedSince,
  }
  const filtered = $derived.by(() => {
    const out = vpn.clientList.filter((c) => matchesQuery(c, search.query, (x) => x.CN))
    return sort.key ? sortRows(out, SORT_GETTERS[sort.key], sort.desc) : out
  })
</script>

<div class="health">
  <span class="pill mono">📜 {certSummary.total} cert{certSummary.total === 1 ? '' : 's'}{certSummary.warn ? ` · ${certSummary.warn} need attention` : ''}</span>
  {#if caCN}
    <span class="pill mono" class:warn={caStatus !== 'valid'}>🔏 CA "{caCN}" until {new Date(caNotAfter).toISOString().slice(0, 10)}</span>
  {/if}
  {#if dnsWarning}<span class="pill mono warn">⚠️ {dnsWarning}</span>{/if}
</div>

<div class="card">
  <h2>Connected clients
    <button type="button" class="ghost" class:active={search.open} onclick={() => toggleSearch(search)}>Filter</button>
    {#if search.open}
      <input type="search" class="search-input" bind:value={search.query} placeholder="Filter by CN…" use:autofocus />
    {/if}
  </h2>
  <Msg type="err" text={err} />
  {#if vpn.phase === 'reloading'}
    <p class="muted">OpenVPN is restarting…</p>
  {:else if !vpn.up}
    <p class="muted">VPN is not reachable over the management socket.</p>
  {:else if vpn.clientList.length === 0}
    <p class="muted">No clients connected.</p>
  {:else if filtered.length === 0}
    <p class="muted">No clients match.</p>
  {:else}
    <table>
      <thead><tr>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'cn')}>Common name{sortMark(sort, 'cn')}</button></th>
        <th>Real address</th><th>VPN address</th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'recv')}>Received{sortMark(sort, 'recv')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'sent')}>Sent{sortMark(sort, 'sent')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'since')}>Connected since{sortMark(sort, 'since')}</button></th>
        {#if canOperate}<th></th>{/if}
      </tr></thead>
      <tbody>
        {#each filtered as c}
          <tr>
            <td><button type="button" class="cn-link" onclick={() => goToCert(c.CN)}
              title="Jump to this certificate in the Certificates tab">{c.CN}</button></td>
            <td>{c.RealAddress}</td>
            <td>{c.VirtualAddress}</td>
            <td>{fmtBytes(c.BytesRecv)}</td>
            <td>{fmtBytes(c.BytesSent)}</td>
            <td>{fmtTimestamp(new Date(c.ConnectedSince))}</td>
            {#if canOperate}
              <td><button class="ghost" onclick={() => kill(c.CN)}
                title="Kill this session; cert stays valid, client can reconnect immediately">Disconnect</button></td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .health { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
  .pill.mono { font-family: var(--mono); }
  .pill.warn { border-color: var(--amber); color: var(--amber); }
</style>
