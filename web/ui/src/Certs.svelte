<script>
  import { api, apiBlob, downloadBlob, copyToClipboard } from './api.js'
  let { canOperate } = $props()
  let certs = $state([])
  let err = $state('')
  let ok = $state('')
  let form = $state({ cn: '', remote: '', passphrase: '', days: 365, keypass: '' })

  async function refresh() {
    try { certs = await api('GET', '/certs'); err = '' }
    catch (x) { err = x.error }
  }
  refresh()

  async function exportBundle(e) {
    e.preventDefault()
    err = ''; ok = ''
    try {
      const { blob } = await apiBlob('POST', '/certs/export', { CN: form.cn, Remote: form.remote,
        Passphrase: form.passphrase, Days: +form.days, KeyPassphrase: form.keypass })
      downloadBlob(blob, form.cn + '.ovpn')
      ok = `Issued ${form.cn} and downloaded the profile.`
      form.cn = ''; form.passphrase = ''; form.keypass = ''
      refresh()
    } catch (x) { err = x.error || 'export failed' }
  }

  let copied = $state('')
  async function copySerial(serial) {
    if (!(await copyToClipboard(serial, 'Serial'))) return
    copied = serial
    setTimeout(() => (copied = ''), 1200)
  }

  async function revoke(serial, cn) {
    const passphrase = prompt(`CA passphrase to revoke ${cn}:`)
    if (!passphrase) return
    err = ''; ok = ''
    try {
      await api('POST', '/certs/revoke', { Serial: serial, Passphrase: passphrase })
      ok = `Revoked ${cn}. CRL updated.`
      refresh()
    } catch (x) { err = x.error }
  }

  const EXPIRY_WARN_DAYS = 30

  function status(c) {
    if (c.Revoked) return { text: 'revoked', cls: 'rv' }
    const days = Math.ceil((new Date(c.NotAfter) - Date.now()) / 86400000)
    if (days < 0) return { text: 'expired', cls: 'rv' }
    if (days <= EXPIRY_WARN_DAYS) return { text: `expires in ${days}d`, cls: 'soon' }
    return { text: 'valid', cls: '' }
  }

  // Renewal is just reissuing under the same CN (no escrow, so there's
  // nothing to "renew" server-side) — this just pre-fills the form above.
  function renewCN(cn) {
    form.cn = cn
    document.querySelector('.issue')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
</script>

{#if canOperate}
  <form class="card issue" onsubmit={exportBundle}>
    <h2>Issue client profile</h2>
    <div class="grid">
      <label>Common name <span class="req">*</span>
        <input bind:value={form.cn} required placeholder="alice-laptop" />
      </label>
      <label>Server address
        <input bind:value={form.remote} placeholder="defaults to server CN" />
      </label>
      <label>Valid for (days)
        <input type="number" bind:value={form.days} min="1" max="3650" />
      </label>
      <label>CA passphrase <span class="req">*</span>
        <input type="password" bind:value={form.passphrase} required />
      </label>
      <label>Profile password
        <input type="password" bind:value={form.keypass} />
      </label>
    </div>
    <button type="submit">Issue and download .ovpn</button>
    <p class="muted small">The private key exists only in this download — it is never stored on the server. Lost profile? Revoke and reissue. With a profile password set, OpenVPN asks for it on connect.</p>
  </form>
{/if}

<div class="card">
  <h2>Certificates</h2>
  {#if err}<p class="err">{err}</p>{/if}
  {#if ok}<p class="ok">{ok}</p>{/if}
  {#if certs.length === 0}
    <p class="muted">No certificates yet.</p>
  {:else}
    <table>
      <thead><tr>
        <th>Common name</th><th>Kind</th><th>Status</th><th>Expires</th><th>Serial</th><th></th>
        {#if canOperate}<th></th>{/if}
      </tr></thead>
      <tbody>
        {#each certs as c}
          <tr>
            <td>{c.CN}</td>
            <td>{c.Kind}</td>
            <td class={status(c).cls}>{status(c).text}</td>
            <td>{new Date(c.NotAfter).toISOString().slice(0, 10)}</td>
            <td>
              <button class="serial" title={c.Serial + ' — click to copy'}
                onclick={() => copySerial(c.Serial)}>
                {copied === c.Serial ? 'copied' : c.Serial.slice(0, 12) + '…'}
              </button>
            </td>
            <td><a class="dl" href={'/api/certs/download?serial=' + c.Serial}
              download={c.CN + '.crt'}>Download</a></td>
            {#if canOperate}
              <td>{#if !c.Revoked}
                {#if c.Kind === 'client' && status(c).cls !== ''}
                  <button class="ghost" onclick={() => renewCN(c.CN)}
                    title="Pre-fill the issue form with this CN to reissue it">Renew</button>
                {/if}
                <button class="ghost" onclick={() => revoke(c.Serial, c.CN)}
                  title="Revoke this certificate and regenerate the CRL">Revoke</button>
              {/if}</td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .issue { margin-bottom: 18px; }
  .small { font-size: 12px; margin: 8px 0 0; }
  .soon { color: var(--amber); }
  .serial {
    background: none; border: 0; padding: 0; color: var(--dim);
    font-family: var(--mono); font-size: 13px; cursor: copy;
  }
  .serial:hover { color: var(--text); text-decoration: underline dotted; }
  .dl { color: var(--amber); font-size: 12px; font-family: system-ui, sans-serif; }
</style>
