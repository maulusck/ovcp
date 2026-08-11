<script>
  import { api, sortRows, matchesQuery, toggleSort, sortMark, toggleSearch, autofocus, fmtTimestamp, flash } from './api.js'
  import Msg from './Msg.svelte'
  let { isAdmin, me, minLen, minClasses } = $props()
  let users = $state([])
  let err = $state('') // row actions (table below) — Msg lives in that card, not this form's
  let ok = $state('')
  let formErr = $state('')
  let formOk = $state('')
  let form = $state({ username: '', password: '', role: 'operator' })
  let enrolled = $state(null) // {username, secret, url, qr}
  let qrDialog = $state() // bind:this — imperative .showModal()/.close(), never read reactively

  const STATUS_KEY = 'ovcp_users_status'
  let statusFilter = $state(localStorage.getItem(STATUS_KEY) || 'all')
  const ROLE_KEY = 'ovcp_users_role'
  let roleFilter = $state(localStorage.getItem(ROLE_KEY) || 'all')
  $effect(() => localStorage.setItem(STATUS_KEY, statusFilter))
  $effect(() => localStorage.setItem(ROLE_KEY, roleFilter))

  let search = $state({ open: false, query: '' })
  let sort = $state({ key: null, desc: false })
  const SORT_GETTERS = {
    username: (u) => u.Username, role: (u) => u.Role, created: (u) => u.CreatedAt,
    status: (u) => u.Disabled, totp: (u) => u.TOTP,
  }
  const filtered = $derived.by(() => {
    let out = users
    if (statusFilter === 'enabled') out = out.filter((u) => !u.Disabled)
    else if (statusFilter === 'disabled') out = out.filter((u) => u.Disabled)
    if (roleFilter !== 'all') out = out.filter((u) => u.Role === roleFilter)
    out = out.filter((u) => matchesQuery(u, search.query, (x) => x.Username))
    return sort.key ? sortRows(out, SORT_GETTERS[sort.key], sort.desc) : out
  })

  async function refresh() {
    try { users = await api('GET', '/users'); err = '' }
    catch (x) { flash(v => err = v, x.error) }
  }
  $effect(() => { if (isAdmin) refresh() })

  async function addUser(e) {
    e.preventDefault()
    formErr = ''; formOk = ''
    try {
      await api('POST', '/users', { Username: form.username, Password: form.password, Role: form.role })
      flash(v => formOk = v, `Added ${form.username}.`)
      form = { username: '', password: '', role: 'operator' }
      refresh()
    } catch (x) { flash(v => formErr = v, x.error) }
  }

  async function toggleDisabled(u) {
    err = ''; ok = ''
    try {
      await api('PATCH', `/users/${u.Username}`, { Disabled: !u.Disabled })
      flash(v => ok = v, `${u.Disabled ? 'Enabled' : 'Disabled'} ${u.Username}.`)
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }

  async function remove(u) {
    if (!confirm(`Delete user ${u.Username}? This cannot be undone.`)) return
    err = ''; ok = ''
    try {
      await api('DELETE', `/users/${u.Username}`)
      flash(v => ok = v, `Deleted ${u.Username}.`)
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }

  async function setPassword(u) {
    const pw = prompt(`New password for ${u.Username} (min ${minLen} chars, ${minClasses} of upper/lower/digit/symbol):`)
    if (!pw) return
    err = ''; ok = ''
    try {
      await api('POST', `/users/${u.Username}/password`, { Password: pw })
      flash(v => ok = v, `Password updated for ${u.Username}.`)
    } catch (x) { flash(v => err = v, x.error) }
  }

  async function enrollTOTP(u) {
    err = ''; ok = ''; enrolled = null
    try {
      const r = await api('POST', `/users/${u.Username}/totp`)
      enrolled = { username: u.Username, ...r }
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }

  async function disableTOTP(u) {
    if (!confirm(`Disable 2FA for ${u.Username}?`)) return
    err = ''; ok = ''
    try {
      await api('DELETE', `/users/${u.Username}/totp`)
      flash(v => ok = v, `2FA disabled for ${u.Username}.`)
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }
</script>

{#if !isAdmin}
  <div class="card"><p class="muted">Admin access required to manage users.</p></div>
{:else}
  <form class="card" onsubmit={addUser}>
    <h2>Add user</h2>
    <div class="grid">
      <label>Username <span class="req">*</span>
        <input bind:value={form.username} required autocomplete="off" />
      </label>
      <label>Password <span class="req">*</span>
        <input type="password" bind:value={form.password} required minlength={minLen} />
      </label>
      <label>Role
        <select bind:value={form.role}>
          <option value="admin">admin</option>
          <option value="operator">operator</option>
          <option value="readonly">readonly</option>
        </select>
      </label>
    </div>
    <Msg type="err" text={formErr} />
    <Msg type="ok" text={formOk} />
    <p class="muted small">Password: min {minLen} chars, {minClasses} of upper/lower/digit/symbol.</p>
    <button type="submit">Add user</button>
  </form>

  {#if enrolled}
    <div class="card">
      <h2>2FA enrollment — {enrolled.username}
        <button type="button" class="ghost" onclick={() => (enrolled = null)}>Done</button>
      </h2>
      <p class="muted small">Scan with an authenticator app, or enter the secret manually. This QR is shown once.</p>
      <button type="button" class="qr-btn" onclick={() => qrDialog.showModal()} title="Click to enlarge">
        <img class="qr" src={enrolled.qr} alt="TOTP QR code — click to enlarge" width="96" height="96" />
      </button>
      <p class="mono">secret: <code>{enrolled.secret}</code> · <a class="totp-link" href={enrolled.url}>open in authenticator app</a></p>
    </div>

    <!-- native <dialog>: ESC-to-close and backdrop dismiss are enough, no Close
         button needed — a click landing on the dialog element itself (not its
         children) means it hit the backdrop area. -->
    <dialog class="card qr-dialog" bind:this={qrDialog}
      onclick={(e) => e.target === qrDialog && qrDialog.close()}>
      <img class="qr" src={enrolled.qr} alt="TOTP QR code" width="240" height="240" />
    </dialog>
  {/if}

  <div class="card">
    <h2>Users
      <button type="button" class="ghost" class:active={search.open} onclick={() => toggleSearch(search)}>Filter</button>
      {#if search.open}
        <input type="search" class="search-input" bind:value={search.query} placeholder="Filter by username…" use:autofocus />
      {/if}
    </h2>
    <div class="row">
      <label class="poll-pick">Status
        <select bind:value={statusFilter}>
          <option value="all">all</option>
          <option value="enabled">enabled</option>
          <option value="disabled">disabled</option>
        </select>
      </label>
      <label class="poll-pick">Role
        <select bind:value={roleFilter}>
          <option value="all">all</option>
          <option value="admin">admin</option>
          <option value="operator">operator</option>
          <option value="readonly">readonly</option>
        </select>
      </label>
    </div>
    <Msg type="err" text={err} />
    <Msg type="ok" text={ok} />
    {#if users.length === 0}
      <p class="muted">No users yet.</p>
    {:else if filtered.length === 0}
      <p class="muted">No users match.</p>
    {:else}
      <table>
        <thead><tr>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'username')}>Username{sortMark(sort, 'username')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'role')}>Role{sortMark(sort, 'role')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'status')}>Status{sortMark(sort, 'status')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'totp')}>2FA{sortMark(sort, 'totp')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'created')}>Created{sortMark(sort, 'created')}</button></th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each filtered as u}
            <tr>
              <td>{u.Username}</td>
              <td>{u.Role}</td>
              <td class={u.Disabled ? 'rv' : ''}>{u.Disabled ? 'disabled' : 'enabled'}</td>
              <td>{u.TOTP ? '2fa' : '-'}</td>
              <td>{fmtTimestamp(new Date(u.CreatedAt))}</td>
              <td class="actions">
                <button class="ghost" onclick={() => setPassword(u)}>Set password</button>
                {#if u.TOTP}
                  <button class="ghost" onclick={() => disableTOTP(u)}
                    title="Removes the TOTP requirement; account falls back to password-only login">Turn off 2FA</button>
                {:else}
                  <button class="ghost" onclick={() => enrollTOTP(u)}>Enroll 2FA</button>
                {/if}
                <button class="ghost" onclick={() => toggleDisabled(u)}
                  disabled={u.Username === me}
                  title={u.Disabled ? 'Restore login access' : 'Block login; account and its certs stay intact'}>{u.Disabled ? 'Enable' : 'Disable'}</button>
                <button class="ghost danger" onclick={() => remove(u)}
                  disabled={u.Username === me}
                  title="Remove the account permanently; VPN certs are unaffected">Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
{/if}

<style>
  .qr { background: #fff; padding: 8px; border-radius: 4px; }
  /* same hover-reveal as .cn-link/.dl app-wide — amber, no underline until hover */
  .totp-link { color: var(--amber); text-decoration: none; }
  .totp-link:hover { text-decoration: underline dotted; }
  .qr-btn { background: none; border: 0; padding: 0; cursor: zoom-in; display: inline-block; }
  /* dialog:modal's UA default is margin:auto (dead-center); pin it near the
     top instead, still horizontally centered — no Close button to align with. */
  .qr-dialog { text-align: center; margin: 8vh auto auto; }
  .qr-dialog::backdrop { background: rgba(0, 0, 0, .55); } /* same dim as .reconnect-overlay */
</style>
