<script>
  import { api } from './api.js'
  import { vpn, dns, pollOnce } from './status.svelte.js'
  import { theme, setTheme, THEMES } from './theme.svelte.js'
  import Logo from './Logo.svelte'
  import Dashboard from './Dashboard.svelte'
  import Stats from './Stats.svelte'
  import Certs from './Certs.svelte'
  import Records from './Records.svelte'
  import Settings from './Settings.svelte'
  import Users from './Users.svelte'
  import Logs from './Logs.svelte'
  import Docs from './Docs.svelte'

  const ALL_TABS = [
    ['dashboard', 'Dashboard'],
    ['stats', 'Stats'],
    ['certs', 'Certificates'],
    ['records', 'Records'],
    ['settings', 'Settings'],
    ['users', 'Users'],
    ['logs', 'Logs'],
    ['docs', 'Docs'],
  ]

  const TAB_KEY = 'ovcp_tab'
  const savedTab = localStorage.getItem(TAB_KEY)

  // source repo the OVCP logo links to; hardcoded, not a runtime git lookup, since a
  // packaged/container install ships the binary, not a .git directory.
  const REPO_URL = 'https://goldrake.bot.nu/c/maulusck/ovcp.git'

  let user = $state(null)
  // Records only appears once dnsmasq is confirmed on PATH — same
  // modular, advisory-only gating openvpn itself gets, per the original ask.
  const tabs = $derived(ALL_TABS.filter(([id]) => id !== 'records' || user?.dnsmasqVersion))
  let verLong = $state(false) // footer: short "ovcp X" vs long "ovcp X · openvpn Y (path)"
  // validated against ALL_TABS (not the dnsmasq-filtered tabs, whose value
  // depends on `user` loading first) so restoring "records" isn't racy.
  let tab = $state(ALL_TABS.some(([id]) => id === savedTab) ? savedTab : 'dashboard')
  let navOpen = $state(false)
  let themeOpen = $state(false)
  // set by Dashboard's CN click, consumed (and cleared) by Certs to scroll/flash the matching row
  let focusCN = $state('')
  function goToCert(cn) { tab = 'certs'; focusCN = cn }
  let login = $state({ username: '', password: '', totp: '' })
  let step = $state('creds') // creds | totp
  let err = $state('')

  async function boot() {
    try { user = await api('GET', '/me') } catch { user = null }
    // tab title: server CN identifies which VPN this is, useful with several open
    document.title = user?.serverCN ? `OVCP · ${user.serverCN}` : 'OVCP'
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

  // close the mobile nav/theme dropdowns on an outside tap (native <details> has no such behavior)
  $effect(() => {
    if (!navOpen && !themeOpen) return
    const onClick = (e) => {
      if (!e.target.closest('.nav-mobile')) navOpen = false
      if (!e.target.closest('.theme-mobile')) themeOpen = false
    }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  })

  async function doLogin(e) {
    e.preventDefault()
    err = ''
    try {
      await api('POST', '/login', {
        Username: login.username, Password: login.password, TOTP: login.totp,
      })
      await boot() // /login's response lacks version/platform fields; /me has them
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
  const currentTheme = $derived(THEMES.find(t => t.name === theme.name) ?? THEMES[0])
  const phaseText = $derived(
    vpn.phase === 'ok' ? `VPN running · up ${vpn.uptime} · ${vpn.clients} client${vpn.clients === 1 ? '' : 's'} connected` +
      (vpn.ovcpUptime ? ` · ovcp up ${vpn.ovcpUptime}` : '') :
    vpn.phase === 'reloading' ? `VPN ${vpn.reloadLabel}…` : 'VPN unreachable')
  // second pill, same ok/down/reloading shape as vpn.phase — passive/dim
  // (not red) when dnsmasq was never installed, that's a normal deployment,
  // not an alarm.
  const dnsState = $derived(!user?.dnsmasqVersion ? 'na' : dns.phase)
  const dnsText = $derived(
    dnsState === 'na' ? 'DNS: not installed' :
    dnsState === 'ok' ? `DNS running · up ${dns.uptime}` :
    dnsState === 'reloading' ? `DNS ${dns.reloadLabel}…` : 'DNS unreachable')
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
      <a class="brand-link" href={REPO_URL} target="_blank" rel="noopener">
        <Logo />
        <strong>OVCP</strong>
      </a>
      <span class="pill" title={phaseText} role="status">
        <span class="status-dot {vpn.phase}"></span>
        <span class="pill-text">{vpn.phase === 'ok' ? 'vpn up' : vpn.phase === 'reloading' ? vpn.reloadLabel : 'vpn down'}</span>
      </span>
      <span class="pill" title={dnsText} role="status">
        <span class="status-dot {dnsState}"></span>
        <span class="pill-text">{dnsState === 'ok' ? 'dns up' : dnsState === 'reloading' ? dns.reloadLabel : dnsState === 'down' ? 'dns down' : 'dns —'}</span>
      </span>
    </div>
    <nav>
      {#each tabs as [id, label]}
        <button class:active={tab === id} onclick={() => (tab = id)}>{label}</button>
      {/each}
    </nav>
    <!-- mobile-only dropdown twin of the nav above; hidden by default so
         desktop CSS/markup above is untouched (see @media max-width:700px) -->
    <details class="nav-mobile" bind:open={navOpen}>
      <summary>{tabs.find(([id]) => id === tab)?.[1]}</summary>
      <div class="nav-menu">
        {#each tabs as [id, label]}
          <button class:active={tab === id} onclick={() => { tab = id; navOpen = false }}>{label}</button>
        {/each}
      </div>
    </details>
    <div class="who">
      <select class="theme-pick" value={theme.name} onchange={(e) => setTheme(e.target.value)}
        title="UI theme">
        {#each THEMES as t}
          <option value={t.name} style="background:{t.bg}; color:{t.fg}">{t.label}</option>
        {/each}
      </select>
      <!-- mobile-only twin: icon-sized button (theme's initial) instead of the full-text select above -->
      <details class="theme-mobile" bind:open={themeOpen}>
        <summary style="background:{currentTheme.bg}; color:{currentTheme.fg}" title="UI theme: {currentTheme.label}">{currentTheme.label[0]}</summary>
        <div class="nav-menu">
          {#each THEMES as t}
            <button class:active={theme.name === t.name} onclick={() => { setTheme(t.name); themeOpen = false }}>{t.label}</button>
          {/each}
        </div>
      </details>
      <div class="account" title="user: {user.username}  role: {user.role}">
        <span class="avatar">{@html identicon(user.username)}</span>
        <span class="acct-name">{user.username}</span>
        <span class="role-pill role-{user.role}">{user.role}</span>
      </div>
      <button class="ghost" onclick={doLogout}>Sign out</button>
    </div>
  </header>
  <main class:wide={tab === 'logs'}>
    {#if tab === 'dashboard'}
      <Dashboard {canOperate} {goToCert} />
    {:else if tab === 'stats'}
      <Stats />
    {:else if tab === 'certs'}
      <Certs {canOperate} bind:focusCN />
    {:else if tab === 'records'}
      <Records {isAdmin} />
    {:else if tab === 'settings'}
      <Settings {isAdmin} />
    {:else if tab === 'users'}
      <Users {isAdmin} me={user.username} minLen={user.minSecretLen} minClasses={user.minSecretClasses} />
    {:else if tab === 'logs'}
      <Logs {isAdmin} {canOperate} />
    {:else}
      <Docs />
    {/if}
  </main>
  <footer>
    <button type="button" class="ver-toggle" onclick={() => (verLong = !verLong)}
      title={verLong ? 'Show less' : 'Show openvpn version'}>
      {#if verLong}
        ovcp {user.version || 'dev'} · {user.platform || '?'}{user.buildTarget ? ` (${user.buildTarget})` : ''} · openvpn {user.openvpnVersion || 'not found'}{user.openvpnPath ? ` (${user.openvpnPath})` : ''}{user.dnsmasqVersion ? ` · dnsmasq ${user.dnsmasqVersion}${user.dnsmasqPath ? ` (${user.dnsmasqPath})` : ''}` : ''}
      {:else}
        ovcp {user.version || 'dev'}
      {/if}
    </button>
  </footer>
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
  /* amber is the accent/highlight color; must stay distinct from --text and --ok or
     accents vanish into body text / warning reads as success. WCAG AA (4.5:1) checked below. */
  /* deep-black hacker terminal; accent is BIOS/DOS-interface blue (not gold — gold
     is the default theme's identity) so warnings read as a distinct hue from ok/bad. */
  :global(:root[data-theme='matrix']) {
    --ink: #000000; --panel: #030603; --line: #123318; --text: #4fdd5f; --dim: #3a9a48;
    --amber: #5566ff; --ok: #39ff14; --bad: #ff2b2b;
  }
  /* dark-cockpit avionics: amber is the main glow, cyan marks "nominal" status
     (glass-cockpit convention: amber=caution, cyan/green=nominal, red=critical). */
  :global(:root[data-theme='retrocrt']) {
    --ink: #030201; --panel: #14100b; --line: #3a4a4a; --text: #e2a100; --dim: #a87a00;
    --amber: #ffcf4d; --ok: #29e6e6; --bad: #ff4020;
  }
  /* readability comes from the contrast fix above, not glow — a body-wide bloom just
     blurs small text; glow stays a titles-only flourish. */
  :global(:root[data-theme='matrix'] h1),
  :global(:root[data-theme='matrix'] h2),
  :global(:root[data-theme='retrocrt'] h1),
  :global(:root[data-theme='retrocrt'] h2) {
    text-shadow: 0 0 6px currentColor;
  }
  /* "follow the white rabbit" — the brand wordmark only, never body text. */
  :global(:root[data-theme='matrix'] .login h1),
  :global(:root[data-theme='matrix'] .brand strong) {
    color: #eafff0; text-shadow: 0 0 8px #39ff14;
  }
  /* Frutiger Aero = Vista-era glossy chrome + Frutiger's nature photography (sky meeting
     grass) — teal bridges the two instead of plain aero blue; panel/ink toned down from icy white. */
  :global(:root[data-theme='frutiger']) {
    --ink: #e3f2f0; --panel: #f5fbf8; --line: #cfe8de; --text: #163a30; --dim: #4f6f63;
    --amber: #0d6b80; --ok: #1c7a46; --bad: #c9392f;
  }
  :global(:root[data-theme='frutiger'] body) {
    /* fixed attachment: gradient spans the viewport once, no hard seam
       partway down a scrolled page (the old document-relative version had one). */
    background: linear-gradient(180deg, #bfe3f5 0%, #eef7f2 55%, #dcefe0 100%) fixed;
  }
  /* teletext: Ceefax/closed-caption coding, a bright hue per role on near-black —
     the real 80s teletext palette (white/yellow/cyan/green/magenta/red). */
  :global(:root[data-theme='teletext']) {
    --ink: #000000; --panel: #050006; --line: #3a1f45; --text: #ffdd00; --dim: #29c2c2;
    --amber: #e619e6; --ok: #33ff66; --bad: #ff3333;
  }
  :global(*) { box-sizing: border-box; }
  :global(body) {
    margin: 0; background: var(--ink); color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, sans-serif;
  }
  :global(button) {
    font: inherit; color: var(--ink); background: var(--amber);
    border: 0; border-radius: 4px; padding: 4px 14px; cursor: pointer;
    transition: opacity .15s, background .15s;
  }
  :global(button:hover:not(:disabled)) { opacity: .85; }
  :global(button:focus-visible), :global(input:focus-visible),
  :global(select:focus-visible), :global(summary:focus-visible) {
    outline: 1px solid var(--amber); outline-offset: 1px;
  }
  :global(button.ghost) {
    background: transparent; color: var(--dim); border: 1px solid var(--line);
  }
  :global(button.ghost:hover:not(:disabled)) {
    background: var(--line); color: var(--text); border-color: var(--text); opacity: 1;
  }
  /* toggled-on state (e.g. the Filter button while its input is open) */
  :global(button.ghost.active) { background: var(--amber); color: var(--ink); border-color: var(--amber); }
  :global(button.ghost.active:hover:not(:disabled)) { background: var(--amber); opacity: .85; }
  :global(button:disabled) { opacity: .45; cursor: not-allowed; }
  :global(input), :global(select) {
    font: inherit; color: var(--text); background: var(--ink);
    border: 1px solid var(--line); border-radius: 4px; padding: 7px 10px; width: 100%;
  }
  :global(input:hover), :global(select:hover) { border-color: var(--amber); }
  :global(label) { display: block; font-size: 13px; color: var(--dim); margin-bottom: 10px; }
  :global(.card) {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 6px; padding: 18px; overflow-x: auto;
  }
  :global(h2) { font-size: 15px; font-weight: 600; margin: 0 0 12px; letter-spacing: .02em; }
  :global(table) { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
  :global(th) {
    text-align: left; color: var(--dim); font-weight: 500;
    padding: 6px 10px; border-bottom: 1px solid var(--line);
    font-family: system-ui, sans-serif; font-size: 12px;
  }
  :global(td) { padding: 7px 10px; border-bottom: 1px solid var(--line); }
  /* every data row hoverable — one shared rule, not per-table. Explicit row height fixes
     rows drifting apart: a row-action <button>'s own padding+border stacks on the td's,
     making an action row taller than a plain-text row unless clamped to one floor. */
  :global(tbody tr:hover) { background: var(--line); }
  :global(tbody tr:hover button.ghost) { border-color: var(--dim); }
  :global(tbody tr) { height: 42px; }
  /* row-action buttons (Certs/Users/Dashboard) — same "operator button" family as
     Settings' Start/Stop/Restart/Backup, just shorter to fit a table row. */
  :global(td button.ghost) { padding: 4px 14px; }
  :global(.err) { color: var(--bad); font-size: 13px; }
  :global(.muted) { color: var(--dim); }
  /* inline "Label [control]" pairs — filter dropdowns (Certs/Users), Logs tab's own options */
  :global(.poll-pick) { display: flex; align-items: center; gap: 6px; margin: 0; font-size: 12px; }
  :global(.poll-pick select), :global(.poll-pick input) { width: auto; }
  :global(.poll-pick select) { padding: 3px 6px; font-size: 12px; }
  /* one shared size for every small ghost button and the filter input, so the input's
     box height always matches the button/.poll-pick select beside it instead of drifting. */
  :global(h2 button.ghost), :global(.panel-actions button.ghost),
  :global(.logs-head button.ghost), :global(.stats-head button.ghost) { padding: 3px 10px; font-size: 12px; }
  :global(h2 button.ghost) { margin-left: 8px; vertical-align: middle; }
  /* grid's column-width floor differs per file, left as a local override */
  :global(.logs-head), :global(.stats-head) {
    display: flex; flex-wrap: wrap; justify-content: flex-end; align-items: center;
    gap: 6px 14px; margin-bottom: 10px; font-size: 12px;
  }
  :global(.logs-grid), :global(.stats-grid) { display: grid; gap: 22px; align-items: start; }
  :global(.search-input) { width: auto; display: inline-block; margin-left: 8px; padding: 3px 8px; font-size: 12px; }
  :global(.panel-actions select) { width: auto; padding: 3px 8px; font-size: 12px; }
  :global(.th-sort) {
    background: none; border: 0; padding: 0; margin: 0; color: inherit; font: inherit; cursor: pointer;
  }
  :global(.th-sort:hover) { color: var(--text); }
  /* shared by Certs.svelte and Users.svelte's forms/tables */
  :global(.grid) { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0 14px; }
  :global(.req) { color: var(--bad); }
  :global(.ok) { color: var(--ok); font-size: 13px; }
  :global(.rv) { color: var(--bad); }
  /* stacked sibling cards (Certs/Settings/Users) always get a gap, not just
     the ones a page happens to mark .form-card */
  :global(.card + .card) { margin-top: 18px; }
  /* .logs-grid/.stats-grid cards are adjacent .card siblings too, so the rule above leaks
     in, stacking atop the grid's own `gap` and misaligning columns once 2+ fit per row. */
  :global(.logs-grid > .card), :global(.stats-grid > .card) { margin-top: 0; }
  /* shared by Certs/Settings/Users' forms: a non-stretching checkbox, full-width
     textarea, button row, and small print. */
  :global(.check) { grid-column: 1 / -1; display: flex; align-items: center; gap: 8px; }
  :global(.check input) { width: auto; }
  :global(.wide) { grid-column: 1 / -1; }
  :global(.wide textarea) {
    width: 100%; font-family: var(--mono); font-size: 13px; resize: vertical;
    background: var(--ink); color: var(--text); border: 1px solid var(--line);
    border-radius: 4px; padding: 7px 10px;
  }
  :global(.row) { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 6px; }
  :global(.small) { font-size: 12px; margin: 8px 0; }
  /* config-preview diffs (Settings' server.conf, Records' custom.hosts) */
  :global(.diff) { font-family: var(--mono); font-size: 12px; white-space: pre; overflow-x: auto;
    background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 8px; }
  :global(.diff .add) { color: var(--ok); }
  :global(.diff .del) { color: var(--bad); }

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
  .brand-link { display: flex; align-items: center; gap: 12px; color: inherit; text-decoration: none; }
  .brand strong { letter-spacing: .12em; }

  .pill {
    display: inline-flex; align-items: center; gap: 7px;
    font-family: var(--mono); font-size: 11px; color: var(--dim);
    border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px;
  }
  /* ok/down/na/reloading dot — shared with Settings.svelte's Telegram status line */
  :global(.status-dot) { width: 8px; height: 8px; border-radius: 50%; }
  :global(.status-dot.ok) { background: var(--ok); box-shadow: 0 0 6px 1px var(--ok); }
  :global(.status-dot.down) { background: var(--bad); box-shadow: 0 0 6px 1px var(--bad); }
  :global(.status-dot.na) { background: var(--dim); opacity: .45; } /* not installed/configured — same "inactive" look as :disabled, not an alarm */
  :global(.status-dot.reloading) {
    background: var(--amber); box-shadow: 0 0 6px 1px var(--amber);
    animation: pulse 1s ease-in-out infinite;
  }
  @keyframes pulse { 50% { opacity: .35; } }

  nav { display: flex; gap: 4px; }
  nav button, .nav-menu button { background: transparent; color: var(--dim); padding: 6px 12px; }
  nav button:hover:not(.active):not(:disabled), .nav-menu button:hover:not(.active):not(:disabled) {
    background: var(--ink); color: var(--text); opacity: 1;
  }
  nav button.active, .nav-menu button.active { color: var(--text); background: var(--ink); }
  .nav-mobile, .theme-mobile { display: none; } /* shown only under the mobile breakpoint below */
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
  main.wide { max-width: 1600px; } /* Logs: rows are the widest content on any tab */

  footer { text-align: center; padding: 6px 18px 14px; }
  .ver-toggle {
    background: transparent; border: none; color: var(--dim); opacity: .55;
    font-family: var(--mono); font-size: 11px; padding: 2px 6px; cursor: pointer;
  }
  .ver-toggle:hover { opacity: 1; }
  @media (prefers-reduced-motion: reduce) { :global(*) { transition: none !important; animation: none !important; } }

  @media (max-width: 700px) {
    header { padding: 8px 12px; gap: 10px; }
    main { padding: 12px; }
    .brand :global(.glyph), .brand strong, .acct-name, .avatar, .pill-text { display: none; } /* status dot, role pill still identify things */
    nav { display: none; }
    .nav-mobile, .theme-mobile { display: block; position: relative; }
    .theme-pick { display: none; }
    /* select ignores vertical padding, so height+line-height is what actually equalizes the two */
    .nav-mobile summary, .theme-mobile summary {
      display: block; height: 31px; line-height: 29px; font-size: 13px; cursor: pointer; list-style: none;
      border: 1px solid var(--line); border-radius: 4px;
    }
    .nav-mobile summary { padding: 0 12px; color: var(--text); background: var(--ink); }
    .nav-mobile summary:hover { border-color: var(--amber); }
    .theme-mobile summary { width: 31px; text-align: center; font-weight: 700; text-transform: uppercase; }
    .nav-mobile summary::-webkit-details-marker, .theme-mobile summary::-webkit-details-marker { display: none; }
    .nav-mobile summary::after { content: ' \25be'; }
    .nav-menu {
      display: none; flex-direction: column; position: absolute; top: calc(100% + 4px); z-index: 10;
      min-width: 220px; background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
      padding: 4px; box-shadow: 0 8px 20px rgba(0,0,0,.35);
    }
    .nav-mobile .nav-menu { left: 0; }
    .theme-mobile .nav-menu { right: 0; min-width: 140px; }
    .nav-mobile[open] .nav-menu, .theme-mobile[open] .nav-menu { display: flex; }
    .nav-menu button { text-align: left; }
  }
</style>
