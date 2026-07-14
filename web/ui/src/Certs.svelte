<script>
  import { tick } from 'svelte'
  import {
    api, apiBlob, downloadBlob, copyToClipboard, sortRows, matchesQuery,
    toggleSort, sortMark, toggleSearch, autofocus,
  } from './api.js'
  let { canOperate, focusCN = $bindable('') } = $props()
  let certs = $state([])
  let err = $state('')
  let ok = $state('')
  let form = $state({ cn: '', remote: '', passphrase: '', days: 365, keypass: '', splitTunnel: false, customOpts: '' })
  let redirectGW = $state(false)

  const STATUS_KEY = 'ovcp_certs_status'
  let statusFilter = $state(localStorage.getItem(STATUS_KEY) || 'all')
  const KIND_KEY = 'ovcp_certs_kind'
  let kindFilter = $state(localStorage.getItem(KIND_KEY) || 'all')
  $effect(() => localStorage.setItem(STATUS_KEY, statusFilter))
  $effect(() => localStorage.setItem(KIND_KEY, kindFilter))

  let search = $state({ open: false, query: '' })
  let sort = $state({ key: null, desc: false })
  const SORT_GETTERS = { cn: (c) => c.CN, kind: (c) => c.Kind, expiry: (c) => new Date(c.NotAfter).getTime() }

  const filtered = $derived.by(() => {
    let out = certs
    if (statusFilter === 'active') out = out.filter((c) => !c.Revoked)
    else if (statusFilter === 'revoked') out = out.filter((c) => c.Revoked)
    if (kindFilter !== 'all') out = out.filter((c) => c.Kind === kindFilter)
    out = out.filter((c) => matchesQuery(c, search.query, (x) => x.CN, (x) => x.Serial))
    return sort.key ? sortRows(out, SORT_GETTERS[sort.key], sort.desc) : out
  })

  async function refresh() {
    try { certs = await api('GET', '/certs'); err = '' }
    catch (x) { err = x.error }
  }
  refresh()
  api('GET', '/config').then(c => (redirectGW = c.RedirectGW)).catch(() => {})

  // arrival from Dashboard's "jump to this cert" click: clear whatever
  // filters might be hiding it, then scroll to and flash the matching row.
  $effect(() => {
    if (!focusCN || certs.length === 0) return
    statusFilter = 'all'; kindFilter = 'all'; search.query = ''
    const cn = focusCN
    tick().then(() => {
      const el = document.querySelector(`tr[data-cn="${CSS.escape(cn)}"]`)
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' })
        el.classList.add('flash')
        setTimeout(() => el.classList.remove('flash'), 1500)
      }
    })
    focusCN = ''
  })

  async function exportBundle(e) {
    e.preventDefault()
    err = ''; ok = ''
    try {
      const { blob } = await apiBlob('POST', '/certs/export', { CN: form.cn, Remote: form.remote,
        Passphrase: form.passphrase, Days: +form.days, KeyPassphrase: form.keypass,
        SplitTunnel: form.splitTunnel, Extra: form.customOpts })
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
  <form class="card form-card" onsubmit={exportBundle}>
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
      {#if redirectGW}
        <label class="check">
          <input type="checkbox" bind:checked={form.splitTunnel} />
          Split tunnel (keep client's own default route)
        </label>
      {/if}
      <label class="wide">Custom options
        <textarea bind:value={form.customOpts} rows="2" placeholder="e.g. block-outside-dns"></textarea>
      </label>
    </div>
    <div class="row">
      <button type="submit">Issue and download .ovpn</button>
    </div>
    <p class="muted small">The private key exists only in this download — it is never stored on the server. Lost profile? Revoke and reissue. With a profile password set, OpenVPN asks for it on connect.</p>
  </form>
{/if}

<div class="card">
  <h2>Certificates
    <button type="button" class="ghost" class:active={search.open} onclick={() => toggleSearch(search)}>Filter</button>
    {#if search.open}
      <input type="search" class="search-input" bind:value={search.query} placeholder="Filter by CN or serial…" use:autofocus />
    {/if}
  </h2>
  <div class="row">
    <label class="poll-pick">Status
      <select bind:value={statusFilter}>
        <option value="all">all</option>
        <option value="active">active</option>
        <option value="revoked">revoked</option>
      </select>
    </label>
    <label class="poll-pick">Kind
      <select bind:value={kindFilter}>
        <option value="all">all</option>
        <option value="client">client</option>
        <option value="server">server</option>
      </select>
    </label>
  </div>
  {#if err}<p class="err">{err}</p>{/if}
  {#if ok}<p class="ok">{ok}</p>{/if}
  {#if certs.length === 0}
    <p class="muted">No certificates yet.</p>
  {:else if filtered.length === 0}
    <p class="muted">No certificates match.</p>
  {:else}
    <table>
      <thead><tr>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'cn')}>Common name{sortMark(sort, 'cn')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'kind')}>Kind{sortMark(sort, 'kind')}</button></th>
        <th>Status</th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'expiry')}>Expires{sortMark(sort, 'expiry')}</button></th>
        <th>Serial</th><th></th>
        {#if canOperate}<th></th>{/if}
      </tr></thead>
      <tbody>
        {#each filtered as c}
          <tr data-cn={c.CN}>
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
  .soon { color: var(--amber); }
  .serial {
    background: none; border: 0; padding: 0; color: var(--dim);
    font-family: var(--mono); font-size: 13px; cursor: copy;
  }
  .serial:hover { color: var(--text); text-decoration: underline dotted; }
  .dl { color: var(--amber); font-size: 12px; font-family: system-ui, sans-serif; }
  :global(tr.flash) { animation: flash 1.5s ease-out; }
  @keyframes flash { 0% { background: var(--amber); } 100% { background: transparent; } }
</style>
