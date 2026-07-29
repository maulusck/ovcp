<script>
  import { tick } from 'svelte'
  import {
    api, apiBlob, downloadBlob, copyToClipboard, sortRows, matchesQuery,
    toggleSort, sortMark, toggleSearch, autofocus, flash, fmtDate,
  } from './api.js'
  import { vpn } from './status.svelte.js'
  import Msg from './Msg.svelte'
  let { canOperate, isAdmin, focusCN = $bindable('') } = $props()
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
  const SORT_GETTERS = {
    cn: (c) => c.CN, kind: (c) => c.Kind, expiry: (c) => new Date(c.NotAfter).getTime(),
    status: (c) => c.Status, serial: (c) => c.Serial, dns: (c) => c.IncludeDNS,
  }

  const filtered = $derived.by(() => {
    let out = certs
    if (statusFilter === 'active') out = out.filter((c) => !c.Revoked)
    else if (statusFilter === 'revoked') out = out.filter((c) => c.Revoked)
    if (kindFilter !== 'all') out = out.filter((c) => c.Kind === kindFilter)
    out = out.filter((c) => matchesQuery(c, search.query, (x) => x.CN, (x) => x.Serial))
    return sort.key ? sortRows(out, SORT_GETTERS[sort.key], sort.desc) : out
  })

  // The one signal for "this submit renews instead of issuing": does the
  // typed/pre-filled CN already match a live client cert — no separate flag,
  // same rule AddCert enforces (one active row per CN+kind), so a revoked-only CN reissues, an active one renews.
  const hasActiveClient = (cn) => certs.some((c) => c.CN === cn && c.Kind === 'client' && !c.Revoked)
  const willRenew = $derived(hasActiveClient(form.cn))

  async function refresh() {
    try { certs = await api('GET', '/certs'); err = '' }
    catch (x) { flash(v => err = v, x.error) }
  }
  refresh()
  api('GET', '/vpn/config').then(c => (redirectGW = c.RedirectGW)).catch(() => {})

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
    const renewing = willRenew
    try {
      const { blob } = await apiBlob('POST', '/certs/export', { CN: form.cn, Remote: form.remote,
        Passphrase: form.passphrase, Days: +form.days, KeyPassphrase: form.keypass,
        SplitTunnel: form.splitTunnel, Extra: form.customOpts, Renew: renewing })
      downloadBlob(blob, form.cn + '.ovpn')
      flash(v => ok = v, `${renewing ? 'Renewed' : 'Issued'} ${form.cn} and downloaded the profile.`)
      form.cn = ''; form.passphrase = ''; form.keypass = ''
      refresh()
    } catch (x) { flash(v => err = v, x.error || 'export failed') }
  }

  let copied = $state('')
  async function copySerial(serial) {
    if (!(await copyToClipboard(serial, 'Serial'))) return
    flash(v => copied = v, serial, 1200)
  }
  async function copyIP(ip) {
    if (!(await copyToClipboard(ip, 'IP'))) return
    flash(v => copied = v, ip, 1200)
  }
  const liveIP = (cn) => vpn.clientList.find((c) => c.CN === cn)?.VirtualAddress

  async function revoke(serial, cn) {
    const passphrase = prompt(`CA passphrase to revoke ${cn}:`)
    if (!passphrase) return
    err = ''; ok = ''
    try {
      await api('POST', '/certs/revoke', { Serial: serial, Passphrase: passphrase })
      flash(v => ok = v, `Revoked ${cn}. CRL updated.`)
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }

  async function toggleDNS(serial, include) {
    err = ''
    try {
      await api('PATCH', `/certs/${serial}/dns`, { IncludeDNS: include })
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }

  // c.Status is the API's classification (store.Cert.Status(), the one
  // place the expiry threshold lives) — this only turns it into display text.
  function status(c) {
    if (c.Status === 'revoked') return { text: 'revoked', cls: 'rv' }
    if (c.Status === 'expired') return { text: 'expired', cls: 'rv' }
    if (c.Status === 'expiring') {
      const days = Math.ceil((new Date(c.NotAfter) - Date.now()) / 86400000)
      return { text: `expires in ${days}d`, cls: 'soon' }
    }
    return { text: 'valid', cls: '' }
  }

  // Client renewal is just export, aimed at a CN with an active cert
  // (willRenew, above) — clicking a CN only ever pre-fills and scrolls;
  // nothing is revoked until the form is actually submitted.
  function prefillRenew(cn) {
    form.cn = cn
    document.querySelector('.issue')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  // Server renewal is the opposite of client: the key never leaves the
  // machine, so there's nothing to hand back — one call, done. Only ever
  // one server cert (this row), so this replaces it in place.
  async function renewServer(cn) {
    const passphrase = prompt(`CA passphrase to renew the server certificate (${cn}):`)
    if (!passphrase) return
    err = ''; ok = ''
    try {
      const r = await api('POST', '/certs/renew', { Passphrase: passphrase })
      flash(v => ok = v, `Server cert renewed (serial ${r.serial.slice(0, 12)}…). Restart openvpn (Settings) to apply.`)
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }
</script>

{#if canOperate}
  <form class="card" onsubmit={exportBundle}>
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
        <label class="check wide">
          <input type="checkbox" bind:checked={form.splitTunnel} />
          Split tunnel (keep client's own default route)
        </label>
      {/if}
      <label class="wide">Custom options
        <textarea bind:value={form.customOpts} rows="2" placeholder="e.g. block-outside-dns"></textarea>
      </label>
    </div>
    <Msg type="err" text={willRenew ? `${form.cn} already exists — this revokes it and issues a replacement.` : ''} />
    <div class="row">
      <button type="submit">{willRenew ? 'Renew and download .ovpn' : 'Issue and download .ovpn'}</button>
    </div>
    <p class="muted small">The private key exists only in this download — it is never stored on the server. With a profile password set, OpenVPN asks for it on connect.</p>
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
  <Msg type="err" text={err} />
  <Msg type="ok" text={ok} />
  {#if certs.length === 0}
    <p class="muted">No certificates yet.</p>
  {:else if filtered.length === 0}
    <p class="muted">No certificates match.</p>
  {:else}
    <table>
      <thead><tr>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'cn')}>Common name{sortMark(sort, 'cn')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'kind')}>Kind{sortMark(sort, 'kind')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'status')}>Status{sortMark(sort, 'status')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'expiry')}>Expires{sortMark(sort, 'expiry')}</button></th>
        <th><button class="th-sort" onclick={() => toggleSort(sort, 'serial')}>Serial{sortMark(sort, 'serial')}</button></th><th></th>
        <th class="dns-col" title="Resolve via internal DNS while connected">
          <button class="th-sort" onclick={() => toggleSort(sort, 'dns')}>DNS{sortMark(sort, 'dns')}</button>
        </th>
        {#if canOperate}<th></th>{/if}
      </tr></thead>
      <tbody>
        {#each filtered as c}
          <tr data-cn={c.CN}>
            <td>
              {#if canOperate && c.Kind === 'client' && (!c.Revoked || !hasActiveClient(c.CN))}
                <button type="button" class="cn-link" onclick={() => prefillRenew(c.CN)}
                  title={c.Revoked ? 'Reissue: previous certificate was revoked, this issues a new one'
                                    : 'Renew: revokes the current cert, issues a fresh one'}>{c.CN}</button>
              {:else if !c.Revoked && canOperate && isAdmin && c.Kind === 'server'}
                <button type="button" class="cn-link" onclick={() => renewServer(c.CN)}
                  title="Renew: revokes the current cert, issues a fresh one (needs a restart to apply)">{c.CN}</button>
              {:else}
                {c.CN}
              {/if}
            </td>
            <td>{c.Kind}</td>
            <td class={status(c).cls}>{status(c).text}</td>
            <td>{fmtDate(new Date(c.NotAfter))}</td>
            <td>
              <button class="mono serial" title={c.Serial + ' — click to copy'}
                onclick={() => copySerial(c.Serial)}>
                {copied === c.Serial ? 'copied' : c.Serial.slice(0, 12) + '…'}
              </button>
            </td>
            <td><a class="dl" href={'/api/certs/download?serial=' + c.Serial}
              download={c.CN + '.crt'}>Download</a></td>
            <td class="dns-col">
              {#if !c.Revoked && c.Kind !== 'server'}
                <span class="dns-cell">
                  <input type="checkbox" checked={c.IncludeDNS} disabled={!canOperate}
                    onchange={() => toggleDNS(c.Serial, !c.IncludeDNS)} />
                  {#if c.IncludeDNS && liveIP(c.CN)}
                    <button type="button" class="dns-live" onclick={() => copyIP(liveIP(c.CN))}
                      title={(copied === liveIP(c.CN) ? 'copied: ' : 'resolving at ') + liveIP(c.CN)}>
                      <span class="status-dot ok"></span>
                    </button>
                  {/if}
                </span>
              {/if}
            </td>
            {#if canOperate}
              <!-- plain td, same as Download beside it: this cell only ever holds
                   one button (or none, revoked) — .actions' flex/wrap exists for
                   Users' four-button row, not a fit here, don't force it. -->
              <td>{#if !c.Revoked}
                <button class="ghost danger" onclick={() => revoke(c.Serial, c.CN)}
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
  .serial { background: none; border: 0; padding: 0; color: var(--dim); cursor: copy; }
  .serial:hover { color: var(--text); text-decoration: underline dotted; }
  .dl { color: var(--amber); font-size: 12px; font-family: system-ui, sans-serif; }
  .dns-col { text-align: center; }
  .dns-cell { display: inline-flex; align-items: center; gap: 4px; }
  .dns-cell input { margin: 0; } /* browser UA default offsets checkboxes right of th text */
  .dns-live { background: none; border: 0; padding: 0; display: inline-flex; cursor: copy; }
  :global(tr.flash) { animation: flash 1.5s ease-out; }
  @keyframes flash { 0% { background: var(--amber); } 100% { background: transparent; } }
</style>
