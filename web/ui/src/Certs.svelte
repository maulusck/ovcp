<script>
  import { api, csrf } from './api.js'
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
      const res = await fetch('/api/certs/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-OVCP-CSRF': csrf() },
        body: JSON.stringify({ CN: form.cn, Remote: form.remote,
          Passphrase: form.passphrase, Days: +form.days,
          KeyPassphrase: form.keypass }),
      })
      if (!res.ok) throw await res.json()
      const blob = await res.blob()
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = form.cn + '.ovpn'
      a.click()
      URL.revokeObjectURL(a.href)
      ok = `Issued ${form.cn} and downloaded the profile.`
      form.cn = ''; form.passphrase = ''; form.keypass = ''
      refresh()
    } catch (x) { err = x.error || 'export failed' }
  }

  let copied = $state('')
  async function copySerial(serial) {
    try { await navigator.clipboard.writeText(serial) }
    catch { prompt('Serial:', serial); return }
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
</script>

{#if canOperate}
  <form class="card issue" onsubmit={exportBundle}>
    <h2>Issue client profile</h2>
    <div class="grid">
      <label>Common name
        <input bind:value={form.cn} required placeholder="alice-laptop" />
      </label>
      <label>Server address (optional)
        <input bind:value={form.remote} placeholder="defaults to server CN" />
      </label>
      <label>Valid for (days)
        <input type="number" bind:value={form.days} min="1" max="3650" />
      </label>
      <label>CA passphrase
        <input type="password" bind:value={form.passphrase} required />
      </label>
      <label>Profile password (optional)
        <input type="password" bind:value={form.keypass}
          placeholder="encrypts the key in the profile" />
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
            <td class={c.Revoked ? 'rv' : ''}>{c.Revoked ? 'revoked' : 'valid'}</td>
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
                <button class="ghost" onclick={() => revoke(c.Serial, c.CN)}>Revoke</button>
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
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0 14px; }
  .small { font-size: 12px; margin: 8px 0 0; }
  .ok { color: var(--ok); font-size: 13px; }
  .rv { color: var(--bad); }
  .serial {
    background: none; border: 0; padding: 0; color: var(--dim);
    font-family: var(--mono); font-size: 13px; cursor: copy;
  }
  .serial:hover { color: var(--text); text-decoration: underline dotted; }
  .dl { color: var(--amber); font-size: 12px; font-family: system-ui, sans-serif; }
</style>
