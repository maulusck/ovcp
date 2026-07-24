<script>
  import { api, procOp } from './api.js'
  let { isAdmin } = $props()

  let dnsErr = $state('')
  let dnsOk = $state('')

  let blockInternet = $state(false)
  async function loadBlockInternet() {
    try { blockInternet = (await api('GET', '/dns/block-internet')).blockInternet } catch (x) { dnsErr = x.error }
  }
  loadBlockInternet()

  async function toggleBlockInternet(e) {
    const want = e.target.checked
    try { blockInternet = (await api('POST', '/dns/block-internet', { BlockInternet: want })).blockInternet }
    catch (x) { dnsErr = x.error; e.target.checked = !want }
  }

  async function dns(op, confirmMsg, done) {
    dnsErr = ''; dnsOk = ''
    try {
      const r = await procOp('/dns/', op, { confirm: confirmMsg })
      if (r) dnsOk = done
    } catch (x) { dnsErr = x.error }
  }
  const start = () => dns('start', null, 'Started.')
  const stop = () => dns('stop', 'Stop internal DNS? Connected clients stop resolving local names.', 'Stopped.')
  const restart = () => dns('restart', 'Restart internal DNS?', 'Restarted.')

  let content = $state('')
  let preview = $state(null) // {diff, changed}
  let customErr = $state('')
  let customOk = $state('')

  async function loadCustom() {
    try { content = (await api('GET', '/dns/custom')).content } catch (x) { customErr = x.error }
  }
  loadCustom()

  async function previewCustom() {
    customErr = ''; customOk = ''; preview = null
    try { preview = await api('POST', '/dns/custom/preview', { Content: content }) }
    catch (x) { customErr = x.error }
  }

  async function saveCustom(e) {
    e.preventDefault()
    customErr = ''; customOk = ''; preview = null
    try {
      await api('PUT', '/dns/custom', { Content: content })
      customOk = 'Saved.'
    } catch (x) { customErr = x.error }
  }
</script>

<div class="card">
  <h2>Internal DNS service</h2>
  <p class="muted small">Resolves certificate names for connected clients. Certificates are included or excluded from the Certificates tab.</p>
  {#if dnsErr}<p class="err">{dnsErr}</p>{/if}
  {#if dnsOk}<p class="ok">{dnsOk}</p>{/if}
  <label class="check">
    <input type="checkbox" checked={blockInternet} disabled={!isAdmin} onchange={toggleBlockInternet} />
    Block internet DNS (answer only local names; restart to apply)
  </label>
  {#if isAdmin}
    <div class="row">
      <button type="button" class="ghost" onclick={start}>Start</button>
      <button type="button" class="ghost" onclick={stop}>Stop</button>
      <button type="button" class="ghost" onclick={restart}>Restart</button>
    </div>
  {:else}
    <p class="muted small">Read-only: your role can view but not change this.</p>
  {/if}
</div>

<div class="card">
  <h2>Custom records</h2>
  <p class="muted small">One hosts-file entry per line, e.g. <code>10.8.0.50 pihole</code>.</p>
  <form onsubmit={saveCustom}>
    <label class="wide">Custom records
      <textarea bind:value={content} rows="6" placeholder="10.8.0.50 pihole" disabled={!isAdmin}></textarea>
    </label>
    {#if customErr}<p class="err">{customErr}</p>{/if}
    {#if customOk}<p class="ok">{customOk}</p>{/if}
    {#if preview}
      {#if preview.changed}
        <p class="muted small">Changes to be saved:</p>
        <pre class="diff">{#each preview.diff as line}<span class={line[0] === '+' ? 'add' : 'del'}>{line}
</span>{/each}</pre>
      {:else}
        <p class="muted small">No changes.</p>
      {/if}
    {/if}
    {#if isAdmin}
      <div class="row">
        <button type="submit">Save</button>
        <button type="button" class="ghost" onclick={previewCustom}>Preview</button>
      </div>
    {:else}
      <p class="muted small">Read-only: your role can view but not change this.</p>
    {/if}
  </form>
</div>
