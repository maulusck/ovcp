<script>
  import { api } from './api.js'
  import { vpn, pollOnce } from './status.svelte.js'
  import { theme, setTheme, THEMES } from './theme.svelte.js'
  import Logo from './Logo.svelte'
  import Dashboard from './Dashboard.svelte'
  import Certs from './Certs.svelte'
  import Settings from './Settings.svelte'
  import Users from './Users.svelte'
  import Logs from './Logs.svelte'
  import Docs from './Docs.svelte'

  const tabs = [
    ['dashboard', 'Dashboard'],
    ['certs', 'Certificates'],
    ['settings', 'Settings'],
    ['users', 'Users'],
    ['logs', 'Logs'],
    ['docs', 'Docs'],
  ]

  const TAB_KEY = 'ovcp_tab'
  const savedTab = localStorage.getItem(TAB_KEY)

  let user = $state(null)
  let tab = $state(tabs.some(([id]) => id === savedTab) ? savedTab : 'dashboard')
  let login = $state({ username: '', password: '', totp: '' })
  let step = $state('creds') // creds | totp
  let err = $state('')

  async function boot() {
    try { user = await api('GET', '/me') } catch { user = null }
  }
  boot()

  // app-wide live status poll while signed in
  $effect(() => {
    if (!user) return
    pollOnce()
    const t = setInterval(pollOnce, 3000)
    return () => clearInterval(t)
  })

  $effect(() => { localStorage.setItem(TAB_KEY, tab) })

  async function doLogin(e) {
    e.preventDefault()
    err = ''
    try {
      user = await api('POST', '/login', {
        Username: login.username, Password: login.password, TOTP: login.totp,
      })
      login = { username: '', password: '', totp: '' }; step = 'creds'
    } catch (x) {
      if (x.error === 'totp required') { step = 'totp'; return }
      err = 'sign-in failed'
      step = 'creds'
      login = { ...login, password: '', totp: '' }
    }
  }

  async function doLogout() {
    try { await api('POST', '/logout') } catch {}
    user = null
    tab = 'dashboard'
  }

  // deterministic per-username "identicon": a symmetric 5x3 bit grid seeded
  // by a cheap string hash — no avatar library, no network image.
  function identicon(seed, size = 24) {
    let h = 0
    for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0
    const cell = size / 5
    let rects = ''
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 3; x++) {
        if ((h >> (y * 3 + x)) & 1) {
          rects += `<rect x="${x * cell}" y="${y * cell}" width="${cell}" height="${cell}"/>`
          if (x < 2) rects += `<rect x="${(4 - x) * cell}" y="${y * cell}" width="${cell}" height="${cell}"/>`
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">` +
      `<rect width="100%" height="100%" fill="var(--ink)"/><g fill="hsl(${h % 360} 65% 55%)">${rects}</g></svg>`
  }

  const canOperate = $derived(user && user.role !== 'readonly')
  const isAdmin = $derived(user && user.role === 'admin')
  const phaseText = $derived(
    vpn.phase === 'ok' ? `VPN running · ${vpn.clients} client${vpn.clients === 1 ? '' : 's'} connected` :
    vpn.phase === 'reloading' ? 'VPN restarting…' : 'VPN unreachable')
</script>

{#if !user}
  <main class="gate">
    <form class="card login" onsubmit={doLogin}>
      <div class="login-head">
        <h1>OVCP</h1>
        <Logo size={36} />
      </div>
      <p class="sub">OpenVPN Control Plane</p>
      {#if step === 'creds'}
        <label>Username
          <input bind:value={login.username} autocomplete="username" required />
        </label>
        <label>Password
          <input type="password" bind:value={login.password} autocomplete="current-password" required />
        </label>
      {:else}
        <label>Authenticator code
          <!-- svelte-ignore a11y_autofocus -->
          <input bind:value={login.totp} inputmode="numeric" maxlength="6"
            autocomplete="one-time-code" placeholder="000000" required autofocus />
        </label>
      {/if}
      {#if err}<p class="err" role="alert">{err}</p>{/if}
      <button type="submit">{step === 'creds' ? 'Sign in' : 'Verify'}</button>
    </form>
  </main>
{:else}
  <header>
    <div class="brand">
      <Logo />
      <strong>OVCP</strong>
      <span class="pill {vpn.phase}" title={phaseText} role="status">
        <i></i>{vpn.phase === 'ok' ? 'vpn up' : vpn.phase === 'reloading' ? 'restarting' : 'vpn down'}
      </span>
    </div>
    <nav>
      {#each tabs as [id, label]}
        <button class:active={tab === id} onclick={() => (tab = id)}>{label}</button>
      {/each}
    </nav>
    <div class="who">
      <select class="theme-pick" value={theme.name} onchange={(e) => setTheme(e.target.value)}
        title="UI theme">
        {#each THEMES as t}
          <option value={t.name} style="background:{t.bg}; color:{t.fg}">{t.label}</option>
        {/each}
      </select>
      <div class="account" title="{user.username} — {user.role}">
        <span class="avatar">{@html identicon(user.username)}</span>
        <span class="acct-name">{user.username}</span>
        <span class="role-pill role-{user.role}">{user.role}</span>
      </div>
      <button class="ghost" onclick={doLogout}>Sign out</button>
    </div>
  </header>
  <main>
    {#if tab === 'dashboard'}
      <Dashboard {canOperate} />
    {:else if tab === 'certs'}
      <Certs {canOperate} />
    {:else if tab === 'settings'}
      <Settings {isAdmin} />
    {:else if tab === 'users'}
      <Users {isAdmin} me={user.username} />
    {:else if tab === 'logs'}
      <Logs {isAdmin} />
    {:else}
      <Docs />
    {/if}
  </main>
{/if}

<style>
  :global(:root) {
    --ink: #10161d;
    --panel: #171f28;
    --line: #26313d;
    --text: #e8e4da;
    --dim: #8c96a0;
    --amber: #e0a136;
    --ok: #5fb578;
    --bad: #d06a5a;
    --mono: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
  }
  :global(:root[data-theme='matrix']) {
    --ink: #000000; --panel: #0a0f0a; --line: #14351a; --text: #8fe38f; --dim: #4f9a54;
    --amber: #33ff33; --ok: #33ff33; --bad: #ff5555;
  }
  :global(:root[data-theme='retrocrt']) {
    --ink: #050200; --panel: #120a02; --line: #3d2400; --text: #ffb000; --dim: #a06800;
    --amber: #ffb000; --ok: #c8d400; --bad: #ff3b1f;
  }
  :global(:root[data-theme='frutiger']) {
    --ink: #eaf6fb; --panel: #ffffff; --line: #bfe3f0; --text: #1b3a4b; --dim: #5c7a89;
    --amber: #1f7fb8; --ok: #2fae6b; --bad: #e0524a;
  }
  :global(*) { box-sizing: border-box; }
  :global(body) {
    margin: 0; background: var(--ink); color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, sans-serif;
  }
  :global(button) {
    font: inherit; color: var(--ink); background: var(--amber);
    border: 0; border-radius: 4px; padding: 7px 14px; cursor: pointer;
    transition: opacity .15s, background .15s;
  }
  :global(button:hover:not(:disabled)) { opacity: .85; }
  :global(button:focus-visible), :global(input:focus-visible), :global(select:focus-visible) {
    outline: 2px solid var(--amber); outline-offset: 1px;
  }
  :global(button.ghost) {
    background: transparent; color: var(--dim); border: 1px solid var(--line);
  }
  :global(button.ghost:hover:not(:disabled)) {
    background: var(--line); color: var(--text); opacity: 1;
  }
  :global(button:disabled) { opacity: .45; cursor: not-allowed; }
  :global(input), :global(select) {
    font: inherit; color: var(--text); background: var(--ink);
    border: 1px solid var(--line); border-radius: 4px; padding: 7px 10px; width: 100%;
  }
  :global(label) { display: block; font-size: 13px; color: var(--dim); margin-bottom: 10px; }
  :global(.card) {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 6px; padding: 18px;
  }
  :global(h2) { font-size: 15px; font-weight: 600; margin: 0 0 12px; letter-spacing: .02em; }
  :global(table) { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
  :global(th) {
    text-align: left; color: var(--dim); font-weight: 500;
    padding: 6px 10px; border-bottom: 1px solid var(--line);
    font-family: system-ui, sans-serif; font-size: 12px;
  }
  :global(td) { padding: 7px 10px; border-bottom: 1px solid var(--line); }
  :global(.err) { color: var(--bad); font-size: 13px; }
  :global(.muted) { color: var(--dim); }

  .gate { min-height: 100vh; display: grid; place-items: center; }
  .login { width: min(340px, 92vw); }
  .login-head { display: flex; align-items: center; justify-content: space-between; }
  .login h1 { margin: 0; font-size: 22px; letter-spacing: .12em; }
  .login .sub { margin: 2px 0 18px; color: var(--dim); font-size: 13px; }
  .login button { width: 100%; margin-top: 6px; }

  header {
    display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
    padding: 10px 18px; border-bottom: 1px solid var(--line); background: var(--panel);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand strong { letter-spacing: .12em; }

  .pill {
    display: inline-flex; align-items: center; gap: 7px;
    font-family: var(--mono); font-size: 11px; color: var(--dim);
    border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px;
  }
  .pill i { width: 8px; height: 8px; border-radius: 50%; }
  .pill.ok i { background: var(--ok); box-shadow: 0 0 6px 1px var(--ok); }
  .pill.down i { background: var(--bad); box-shadow: 0 0 6px 1px var(--bad); }
  .pill.reloading i {
    background: var(--amber); box-shadow: 0 0 6px 1px var(--amber);
    animation: pulse 1s ease-in-out infinite;
  }
  @keyframes pulse { 50% { opacity: .35; } }

  nav { display: flex; gap: 4px; }
  nav button { background: transparent; color: var(--dim); padding: 6px 12px; }
  nav button:hover:not(.active):not(:disabled) { background: var(--ink); color: var(--text); opacity: 1; }
  nav button.active { color: var(--text); background: var(--ink); }
  .who { margin-left: auto; display: flex; align-items: center; gap: 12px; font-size: 13px; color: var(--dim); }
  .theme-pick { width: auto; padding: 5px 8px; font-size: 12px; }
  .account { display: flex; align-items: center; gap: 8px; }
  .avatar { display: inline-flex; width: 24px; height: 24px; border-radius: 6px; overflow: hidden; flex-shrink: 0; }
  .acct-name { color: var(--text); font-weight: 600; }
  .role-pill {
    font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: .04em;
    border: 1px solid var(--line); border-radius: 999px; padding: 2px 8px; color: var(--dim);
  }
  .role-pill.role-admin { color: var(--amber); border-color: var(--amber); }
  .role-pill.role-operator { color: var(--ok); border-color: var(--ok); }
  main { padding: 18px; max-width: 1100px; margin: 0 auto; }
  @media (prefers-reduced-motion: reduce) { :global(*) { transition: none !important; animation: none !important; } }
</style>
