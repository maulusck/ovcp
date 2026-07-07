<script>
  import { api } from './api.js'
  import { vpn, pollOnce } from './status.svelte.js'
  import Dashboard from './Dashboard.svelte'
  import Certs from './Certs.svelte'
  import Settings from './Settings.svelte'
  import Audit from './Audit.svelte'

  let user = $state(null)
  let tab = $state('dashboard')
  let login = $state({ username: '', password: '', totp: '' })
  let step = $state('creds') // creds | totp
  let err = $state('')

  const tabs = [
    ['dashboard', 'Dashboard'],
    ['certs', 'Certificates'],
    ['settings', 'Settings'],
    ['audit', 'Audit'],
  ]

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

  const canOperate = $derived(user && user.role !== 'readonly')
  const isAdmin = $derived(user && user.role === 'admin')
  const phaseText = $derived(
    vpn.phase === 'ok' ? 'VPN running' :
    vpn.phase === 'reloading' ? 'VPN restarting…' : 'VPN unreachable')
</script>

{#if !user}
  <main class="gate">
    <form class="card login" onsubmit={doLogin}>
      <h1>OVCP</h1>
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
      <span>{user.username} · {user.role}</span>
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
    {:else}
      <Audit />
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
  :global(*) { box-sizing: border-box; }
  :global(body) {
    margin: 0; background: var(--ink); color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, sans-serif;
  }
  :global(button) {
    font: inherit; color: var(--ink); background: var(--amber);
    border: 0; border-radius: 4px; padding: 7px 14px; cursor: pointer;
  }
  :global(button:focus-visible), :global(input:focus-visible), :global(select:focus-visible) {
    outline: 2px solid var(--amber); outline-offset: 1px;
  }
  :global(button.ghost) {
    background: transparent; color: var(--dim); border: 1px solid var(--line);
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
  .login h1 { margin: 0; font-size: 22px; letter-spacing: .12em; }
  .login .sub { margin: 2px 0 18px; color: var(--dim); font-size: 13px; }
  .login button { width: 100%; margin-top: 6px; }
  .hint { color: var(--amber); font-size: 13px; margin: 0 0 10px; }

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
  nav button.active { color: var(--text); background: var(--ink); }
  .who { margin-left: auto; display: flex; align-items: center; gap: 12px; font-size: 13px; color: var(--dim); }
  main { padding: 18px; max-width: 1100px; margin: 0 auto; }
  @media (prefers-reduced-motion: reduce) { :global(*) { transition: none !important; animation: none !important; } }
</style>
