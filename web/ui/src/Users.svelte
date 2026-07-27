<script>
  import { api, sortRows, matchesQuery, toggleSort, sortMark, toggleSearch, autofocus, fmtTimestamp, flash } from './api.js'
  import Msg from './Msg.svelte'
  let { isAdmin, me, minLen, minClasses } = $props()
  let users = $state([])
  let err = $state('')
  let ok = $state('')
  let form = $state({ username: '', password: '', role: 'operator' })
  let enrolled = $state(null) // {username, secret, url, qr}

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
    err = ''; ok = ''
    try {
      await api('POST', '/users', { Username: form.username, Password: form.password, Role: form.role })
      flash(v => ok = v, `Added ${form.username}.`)
      form = { username: '', password: '', role: 'operator' }
      refresh()
    } catch (x) { flash(v => err = v, x.error) }
  }

  async function toggleDisabled(u) {
    err = ''; ok = ''
    try {
      await api('PATCH', `/users/${u.Username}`, { Disabled: !u.Disabled })
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
    <p class="muted small">Password: min {minLen} chars, {minClasses} of upper/lower/digit/symbol.</p>
    <button type="submit">Add user</button>
  </form>

  <Msg type="err" text={err} />
  <Msg type="ok" text={ok} />

  {#if enrolled}
    <div class="card">
      <h2>2FA enrollment — {enrolled.username}</h2>
      <p class="muted small">Scan with an authenticator app, or enter the secret manually. This QR is shown once.</p>
      <img class="qr" src={enrolled.qr} alt="TOTP QR code" width="160" height="160" />
      <p class="mono">secret: <code>{enrolled.secret}</code></p>
      <button type="button" class="ghost" onclick={() => (enrolled = null)}>Done</button>
    </div>
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
</style>
