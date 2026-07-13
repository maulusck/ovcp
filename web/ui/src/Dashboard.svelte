<script>
  import { api, fmtBytes, sortRows, matchesQuery, toggleSort, sortMark, toggleSearch, autofocus } from './api.js'
  import { vpn, pollOnce } from './status.svelte.js'
  let { canOperate } = $props()
  let err = $state('')

  // no local poll loop: App.svelte already polls status app-wide (for the
  // header pill) and caches the full client list on the shared vpn state.
  async function kill(cn) {
    if (!confirm(`Disconnect ${cn}?`)) return
    try { await api('POST', '/clients/kill', { CN: cn }); pollOnce() }
    catch (x) { err = x.error }
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

<div class="card">
  <h2>Connected clients
    <button type="button" class="ghost" class:active={search.open} onclick={() => toggleSearch(search)}>Filter</button>
    {#if search.open}
      <input type="search" class="search-input" bind:value={search.query} placeholder="Filter by CN…" use:autofocus />
    {/if}
  </h2>
  {#if err}<p class="err">{err}</p>{/if}
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
            <td>{c.CN}</td>
            <td>{c.RealAddress}</td>
            <td>{c.VirtualAddress}</td>
            <td>{fmtBytes(c.BytesRecv)}</td>
            <td>{fmtBytes(c.BytesSent)}</td>
            <td>{new Date(c.ConnectedSince).toLocaleString()}</td>
            {#if canOperate}
              <td><button class="ghost" onclick={() => kill(c.CN)}>Disconnect</button></td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
