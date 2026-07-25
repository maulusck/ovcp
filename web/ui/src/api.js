function csrf() {
  const m = document.cookie.match(/(?:^|; )ovcp_csrf=([^;]+)/)
  return m ? m[1] : ''
}

function req(method, path, body) {
  return fetch('/api' + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(method !== 'GET' ? { 'X-OVCP-CSRF': csrf() } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
}

export async function api(method, path, body) {
  const res = await req(method, path, body)
  const ct = res.headers.get('Content-Type') || ''
  const data = ct.includes('json') ? await res.json() : await res.text()
  if (!res.ok) throw { status: res.status, error: data.error || String(data) }
  return data
}

// procOp: confirm (if asked), POST prefix+op, and hand back the result —
// shared by the vpn and dns control panels. onRecover (e.g. expectRecovery)
// is opt-in, not baked in: only vpn's header pill tracks a recovery window.
export async function procOp(prefix, op, { confirm: confirmMsg, recoverMs, onRecover } = {}) {
  if (confirmMsg && !confirm(confirmMsg)) return null
  const result = await api('POST', prefix + op)
  if (recoverMs && onRecover) onRecover(recoverMs)
  return result
}

// apiBlob: api()'s counterpart for file-download endpoints — same CSRF'd POST, but
// returns the raw blob and server-suggested filename instead of parsed JSON.
export async function apiBlob(method, path, body) {
  const res = await req(method, path, body)
  if (!res.ok) throw await res.json()
  const filename = res.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1]
  return { blob: await res.blob(), filename }
}

// clipboard copy with a prompt() fallback (Safari/insecure-context denials) —
// shared by Certs.svelte (serial numbers) and Logs.svelte (log/audit text).
export async function copyToClipboard(text, fallbackLabel) {
  try { await navigator.clipboard.writeText(text); return true }
  catch { prompt(fallbackLabel + ':', text); return false }
}

export function downloadBlob(blob, filename) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

// One shared timestamp format for the whole UI: 24h, no AM/PM, date order
// from the browser's own locale (en-US if it has none).
export function fmtTimestamp(d) {
  return d.toLocaleString(navigator.language || 'en-US', { hour12: false }).replace(',', '')
}

export function fmtBytes(n) {
  if (n < 1024) return n + ' B'
  const u = ['KiB', 'MiB', 'GiB', 'TiB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return n.toFixed(1) + ' ' + u[i]
}

// Sample rates are already bytes/sec (internal/store's Rate); this just appends
// "/s" — never re-derives a rate from raw counters.
export function fmtRate(n) { return fmtBytes(n) + '/s' }

// shared by every sortable table (Certs/Users/Dashboard/Stats): click-a-<th>
// sort, no per-table comparator logic.
export function sortRows(rows, get, desc = false) {
  return [...rows].sort((a, b) => {
    const av = get(a), bv = get(b), cmp = av < bv ? -1 : av > bv ? 1 : 0
    return desc ? -cmp : cmp
  })
}

// shared by every searchable table/panel: case-insensitive substring match
// across whichever fields the caller says are searchable.
export function matchesQuery(row, query, ...getters) {
  if (!query) return true
  const q = query.toLowerCase()
  return getters.some((get) => String(get(row) ?? '').toLowerCase().includes(q))
}

// Shared sort state ({key, desc}, mutated in place) so every sortable table
// (Certs/Users/Dashboard/Stats) shares click/flip logic and the indicator glyph.
export function toggleSort(sort, key) {
  if (sort.key === key) sort.desc = !sort.desc
  else { sort.key = key; sort.desc = false }
}
export function sortMark(sort, key) {
  return sort.key === key ? (sort.desc ? ' ↓' : ' ↑') : ''
}

// Shared search state ({open, query}, mutated in place): autofocus on open, autoclear
// on close — reused by every filterable table/log panel instead of reimplementing it.
export function toggleSearch(search) {
  search.open = !search.open
  if (!search.open) search.query = ''
}

// use:autofocus focuses a conditionally-rendered element on mount — the native
// `autofocus` attr doesn't fire here since Svelte sets it after insertion.
export function autofocus(node) {
  node.focus()
}
