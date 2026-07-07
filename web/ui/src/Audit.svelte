<script>
  import { api } from './api.js'
  let entries = $state([])
  let err = $state('')
  async function load() {
    try { entries = await api('GET', '/audit') } catch (x) { err = x.error }
  }
  load()
</script>

<div class="card">
  <h2>Audit log</h2>
  {#if err}<p class="err">{err}</p>{/if}
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
</div>
