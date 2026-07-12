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

// apiBlob is api()'s counterpart for endpoints that return a file instead
// of JSON (export/backup/logs downloads) — same CSRF'd POST, but hands back
// the raw blob and any server-suggested filename instead of parsing JSON.
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

export function fmtBytes(n) {
  if (n < 1024) return n + ' B'
  const u = ['KiB', 'MiB', 'GiB', 'TiB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return n.toFixed(1) + ' ' + u[i]
}
