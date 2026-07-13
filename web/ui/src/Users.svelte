<script>
  import { api, sortRows, matchesQuery, toggleSort, sortMark, toggleSearch, autofocus } from './api.js'
  let { isAdmin, me } = $props()
  let users = $state([])
  let err = $state('')
  let ok = $state('')
  let form = $state({ username: '', password: '', role: 'operator' })
  let enrolled = $state(null) // {username, secret, url, qr}

  let search = $state({ open: false, query: '' })
  let sort = $state({ key: null, desc: false })
  const SORT_GETTERS = {
    username: (u) => u.Username, role: (u) => u.Role, created: (u) => u.CreatedAt,
  }
  const filtered = $derived.by(() => {
    const out = users.filter((u) => matchesQuery(u, search.query, (x) => x.Username))
    return sort.key ? sortRows(out, SORT_GETTERS[sort.key], sort.desc) : out
  })

  async function refresh() {
    try { users = await api('GET', '/users'); err = '' }
    catch (x) { err = x.error }
  }
  $effect(() => { if (isAdmin) refresh() })

  async function addUser(e) {
    e.preventDefault()
    err = ''; ok = ''
    try {
      await api('POST', '/users', { Username: form.username, Password: form.password, Role: form.role })
      ok = `Added ${form.username}.`
      form = { username: '', password: '', role: 'operator' }
      refresh()
    } catch (x) { err = x.error }
  }

  async function toggleDisabled(u) {
    err = ''; ok = ''
    try {
      await api('PATCH', `/users/${u.Username}`, { Disabled: !u.Disabled })
      refresh()
    } catch (x) { err = x.error }
  }

  async function remove(u) {
    if (!confirm(`Delete user ${u.Username}? This cannot be undone.`)) return
    err = ''; ok = ''
    try {
      await api('DELETE', `/users/${u.Username}`)
      ok = `Deleted ${u.Username}.`
      refresh()
    } catch (x) { err = x.error }
  }

  async function setPassword(u) {
    const pw = prompt(`New password for ${u.Username} (min 8 chars):`)
    if (!pw) return
    err = ''; ok = ''
    try {
      await api('POST', `/users/${u.Username}/password`, { Password: pw })
      ok = `Password updated for ${u.Username}.`
    } catch (x) { err = x.error }
  }

  async function enrollTOTP(u) {
    err = ''; ok = ''; enrolled = null
    try {
      const r = await api('POST', `/users/${u.Username}/totp`)
      enrolled = { username: u.Username, ...r }
      refresh()
    } catch (x) { err = x.error }
  }

  async function disableTOTP(u) {
    if (!confirm(`Disable 2FA for ${u.Username}?`)) return
    err = ''; ok = ''
    try {
      await api('DELETE', `/users/${u.Username}/totp`)
      ok = `2FA disabled for ${u.Username}.`
      refresh()
    } catch (x) { err = x.error }
  }
</script>

{#if !isAdmin}
  <div class="card"><p class="muted">Admin access required to manage users.</p></div>
{:else}
  <form class="card issue" onsubmit={addUser}>
    <h2>Add user</h2>
    <div class="grid">
      <label>Username <span class="req">*</span>
        <input bind:value={form.username} required autocomplete="off" />
      </label>
      <label>Password <span class="req">*</span>
        <input type="password" bind:value={form.password} required minlength="8" />
      </label>
      <label>Role
        <select bind:value={form.role}>
          <option value="admin">admin</option>
          <option value="operator">operator</option>
          <option value="readonly">readonly</option>
        </select>
      </label>
    </div>
    <button type="submit">Add user</button>
  </form>

  {#if err}<p class="err">{err}</p>{/if}
  {#if ok}<p class="ok">{ok}</p>{/if}

  {#if enrolled}
    <div class="card">
      <h2>2FA enrollment — {enrolled.username}</h2>
      <p class="muted small">Scan with an authenticator app, or enter the secret manually. This QR is shown once.</p>
      <img class="qr" src={enrolled.qr} alt="TOTP QR code" width="160" height="160" />
      <p class="secret">secret: <code>{enrolled.secret}</code></p>
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
    {#if users.length === 0}
      <p class="muted">No users yet.</p>
    {:else if filtered.length === 0}
      <p class="muted">No users match.</p>
    {:else}
      <table>
        <thead><tr>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'username')}>Username{sortMark(sort, 'username')}</button></th>
          <th><button class="th-sort" onclick={() => toggleSort(sort, 'role')}>Role{sortMark(sort, 'role')}</button></th>
          <th>Status</th><th>2FA</th>
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
              <td>{new Date(u.CreatedAt).toLocaleDateString()}</td>
              <td class="actions">
                <button class="ghost" onclick={() => setPassword(u)}>Set password</button>
                {#if u.TOTP}
                  <button class="ghost" onclick={() => disableTOTP(u)}>Turn off 2FA</button>
                {:else}
                  <button class="ghost" onclick={() => enrollTOTP(u)}>Enroll 2FA</button>
                {/if}
                <button class="ghost" onclick={() => toggleDisabled(u)}
                  disabled={u.Username === me}>{u.Disabled ? 'Enable' : 'Disable'}</button>
                <button class="ghost" onclick={() => remove(u)}
                  disabled={u.Username === me}>Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
{/if}

<style>
  .issue { margin-bottom: 18px; }
  .small { font-size: 12px; margin: 8px 0; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .qr { background: #fff; padding: 8px; border-radius: 4px; }
  .secret { font-family: var(--mono); font-size: 13px; }
</style>
