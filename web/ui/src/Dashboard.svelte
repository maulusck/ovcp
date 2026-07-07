<script>
  import { api, fmtBytes } from './api.js'
  import { vpn, pollOnce } from './status.svelte.js'
  let { canOperate } = $props()
  let clients = $state([])
  let err = $state('')

  async function refresh() {
    const d = await pollOnce()
    clients = d.clients || []
  }
  $effect(() => {
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  })

  async function kill(cn) {
    if (!confirm(`Disconnect ${cn}?`)) return
    try { await api('POST', '/clients/kill', { CN: cn }); refresh() }
    catch (x) { err = x.error }
  }
</script>

<div class="card">
  <h2>Connected clients</h2>
  {#if err}<p class="err">{err}</p>{/if}
  {#if vpn.phase === 'reloading'}
    <p class="muted">OpenVPN is restarting…</p>
  {:else if !vpn.up}
    <p class="muted">VPN is not reachable over the management socket.</p>
  {:else if clients.length === 0}
    <p class="muted">No clients connected.</p>
  {:else}
    <table>
      <thead><tr>
        <th>Common name</th><th>Real address</th><th>VPN address</th>
        <th>Received</th><th>Sent</th><th>Connected since</th>
        {#if canOperate}<th></th>{/if}
      </tr></thead>
      <tbody>
        {#each clients as c}
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
