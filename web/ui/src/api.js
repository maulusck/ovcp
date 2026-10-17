function csrf() {
  const m = document.cookie.match(/(?:^|; )ovcp_csrf=([^;]+)/)
  return m ? m[1] : ''
}

/** @import { Routes } from './api.gen' */

// api calls route, a pattern from internal/api's route table ('PATCH
// /api/certs/{serial}/dns'): in fills its {wildcards}, then the query (GET) or
// the JSON body. It returns the route's JSON, or for a file its blob.
/**
 * @template {keyof Routes} R
 * @param {R} route
 * @param {Routes[R]['in']} [input]
 * @returns {Promise<Routes[R]['out']>}
 */
export async function api(route, input = {}) {
  let [method, path] = route.split(' ')
  /** @type {Record<string, any>} */
  const rest = { ...input }
  path = path.replace(/{(\w+)}/g, (_, k) => { const v = rest[k]; delete rest[k]; return encodeURIComponent(v) })
  const get = method === 'GET'
  if (get && Object.keys(rest).length) path += '?' + new URLSearchParams(rest)
  const res = await fetch(path, {
    method,
    headers: get ? {} : { 'Content-Type': 'application/json', 'X-OVCP-CSRF': csrf() },
    body: get ? undefined : JSON.stringify(rest),
  })
  const json = res.headers.get('Content-Type')?.includes('json')
  if (!res.ok) throw { status: res.status, error: json ? (await res.json()).error : res.statusText }
  if (json) return res.json()
  const filename = res.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] ?? ''
  return /** @type {any} */ ({ blob: await res.blob(), filename })
}

// procOp: confirm (if asked), run op on a lifecycle route, and hand back the
// result. onRecover (e.g. expectRecovery) is opt-in: only vpn's header pill
// tracks a recovery window.
/**
 * @param {'POST /api/vpn/{op}' | 'POST /api/dns/{op}' | 'POST /api/telegram/{op}'} route
 * @param {string} op
 * @param {{ confirm?: string | null, recoverMs?: number, onRecover?: (ms: number) => void }} [opts]
 */
export async function procOp(route, op, { confirm: confirmMsg, recoverMs, onRecover } = {}) {
  if (confirmMsg && !confirm(confirmMsg)) return null
  const result = await api(route, { op })
  if (recoverMs && onRecover) onRecover(recoverMs)
  return result
}

// procOp's `changed` flag only means something for start/stop (restart always
// does a real stop+start regardless) — same distinction the CLI's text output
// already makes (`already started`/`already stopped`).
/**
 * @param {string} op
 * @param {{ changed: boolean } | null} result
 * @param {string} done
 */
export function procDone(op, result, done) {
  if (result && result.changed === false && (op === 'start' || op === 'stop')) {
    return `Already ${op === 'start' ? 'started' : 'stopped'}.`
  }
  return done
}

// clipboard copy with a prompt() fallback (Safari/insecure-context denials) —
// shared by Certs.svelte (serial numbers) and Logs.svelte (log/audit text).
/** @param {string} text @param {string} fallbackLabel */
export async function copyToClipboard(text, fallbackLabel) {
  try { await navigator.clipboard.writeText(text); return true }
  catch { prompt(fallbackLabel + ':', text); return false }
}

/** @param {Blob} blob @param {string} filename */
export function downloadBlob(blob, filename) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

// One fixed timestamp format for the whole UI: local time, "YYYY-MM-DD
// HH:MM:SS" — deterministic, unlike toLocaleString's locale-dependent order.
/** @param {Date} d */
export function fmtTimestamp(d) {
  const p = (/** @type {number} */ n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// Date-only prefix of fmtTimestamp — local time, not toISOString's UTC
// (which can land on the wrong day near a timezone boundary).
/** @param {Date} d */
export function fmtDate(d) { return fmtTimestamp(d).slice(0, 10) }

/** @param {number} n */
export function fmtBytes(n) {
  if (n < 1024) return n + ' B'
  const u = ['KiB', 'MiB', 'GiB', 'TiB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return n.toFixed(1) + ' ' + u[i]
}

// Sample rates are already bytes/sec (internal/store's Rate); this just appends
// "/s" — never re-derives a rate from raw counters.
/** @param {number} n */
export function fmtRate(n) { return fmtBytes(n) + '/s' }

// shared by every sortable table (Certs/Users/Dashboard/Stats): click-a-<th>
// sort, no per-table comparator logic.
/**
 * @template T
 * @param {T[]} rows
 * @param {(row: T) => any} get
 */
export function sortRows(rows, get, desc = false) {
  return [...rows].sort((a, b) => {
    const av = get(a), bv = get(b), cmp = av < bv ? -1 : av > bv ? 1 : 0
    return desc ? -cmp : cmp
  })
}

// shared by every searchable table/panel: case-insensitive substring match
// across whichever fields the caller says are searchable.
/**
 * @template T
 * @param {T} row
 * @param {string} query
 * @param {...(row: T) => unknown} getters
 */
export function matchesQuery(row, query, ...getters) {
  if (!query) return true
  const q = query.toLowerCase()
  return getters.some((get) => String(get(row) ?? '').toLowerCase().includes(q))
}

// Shared sort state ({key, desc}, mutated in place) so every sortable table
// (Certs/Users/Dashboard/Stats) shares click/flip logic and the indicator glyph.
/** @typedef {{ key: string | null, desc: boolean }} Sort */
/** @param {Sort} sort @param {string} key */
export function toggleSort(sort, key) {
  if (sort.key === key) sort.desc = !sort.desc
  else { sort.key = key; sort.desc = false }
}
/** @param {Sort} sort @param {string} key */
export function sortMark(sort, key) {
  return sort.key === key ? (sort.desc ? ' ↓' : ' ↑') : ''
}

// Shared search state ({open, query}, mutated in place): autofocus on open, autoclear
// on close — reused by every filterable table/log panel instead of reimplementing it.
/** @param {{ open: boolean, query: string }} search */
export function toggleSearch(search) {
  search.open = !search.open
  if (!search.open) search.query = ''
}

// use:autofocus focuses a conditionally-rendered element on mount — the native
// `autofocus` attr doesn't fire here since Svelte sets it after insertion.
/** @param {HTMLElement} node */
export function autofocus(node) {
  node.focus()
}

// use:autosize={value} grows a textarea to fit its content, 2-10 lines, then
// scrolls — CSS field-sizing:content isn't reliably supported yet. Pass the
// bound value as the action's argument so `update` also re-fires when it
// changes programmatically (an async config load), not just on keystrokes.
/** @param {HTMLTextAreaElement} node @param {unknown} [_value] */
export function autosize(node, _value) {
  function resize() {
    node.style.height = 'auto'
    const cs = getComputedStyle(node)
    const lh = parseFloat(cs.lineHeight) || 16
    const box = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom) +
      parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth)
    const clamped = Math.min(Math.max(node.scrollHeight, lh * 2 + box), lh * 10 + box)
    node.style.height = clamped + 'px'
  }
  node.addEventListener('input', resize)
  resize()
  return { update: resize, destroy: () => node.removeEventListener('input', resize) }
}

// flash sets a message state then clears it after ms — the one place every
// err/ok line's auto-dismiss timing lives, paired with <Msg> for the fade.
export const FLASH_MS = 5000
/** @param {(v: string) => void} set @param {string} value */
export function flash(set, value, ms = FLASH_MS) {
  set(value)
  if (value) setTimeout(() => set(''), ms)
}
