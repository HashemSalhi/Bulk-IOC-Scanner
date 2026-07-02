/**
 * Bulk-IOC-Scanner API client.
 * All requests go to /api (proxied to backend in dev, same-origin in prod).
 */

const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const err = await res.json()
      detail = err.detail || detail
    } catch {}
    throw new Error(detail)
  }
  return res.json()
}

// ── Scan ──────────────────────────────────────────────────────────────────────

export const scanIOCs = (iocs, force = false) =>
  request(`/scan${force ? '?force=true' : ''}`, {
    method: 'POST',
    body: JSON.stringify({ iocs }),
  })

// Force a fresh scan of a single IOC, bypassing the cache
export const rescan = (ioc) =>
  request('/scan?force=true', {
    method: 'POST',
    body: JSON.stringify({ iocs: [ioc] }),
  }).then((results) => results[0])

export const scanText = (text) =>
  request('/scan/text', {
    method: 'POST',
    body: JSON.stringify({ text }),
  })

// Stream results as each IOC completes; calls onResult(result) per NDJSON line.
export async function scanStream(iocs, onResult, { force = false } = {}) {
  const res = await fetch(`${BASE}/scan/stream${force ? '?force=true' : ''}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ iocs }),
  })
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try { detail = (await res.json()).detail || detail } catch {}
    throw new Error(detail)
  }
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  const handleLine = (line) => {
    const t = line.trim()
    if (t) onResult(JSON.parse(t))
  }
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let nl
    while ((nl = buffer.indexOf('\n')) >= 0) {
      handleLine(buffer.slice(0, nl))
      buffer = buffer.slice(nl + 1)
    }
  }
  handleLine(buffer)
}

export const scanFiles = async (fileList) => {
  const formData = new FormData()
  for (const file of fileList) {
    formData.append('files', file)
  }
  const res = await fetch(`${BASE}/scan/files`, {
    method: 'POST',
    body: formData,
  })
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const err = await res.json()
      detail = err.detail || detail
    } catch {}
    throw new Error(detail)
  }
  return res.json()
}

export const tagScan = (scanId, tag) =>
  request(`/scan/${scanId}/tag`, {
    method: 'PATCH',
    body: JSON.stringify({ tag }),
  })

export const saveNotes = (scanId, notes) =>
  request(`/scan/${scanId}/notes`, {
    method: 'PATCH',
    body: JSON.stringify({ notes }),
  })

// ── History ───────────────────────────────────────────────────────────────────

// Returns { items, total }
export const getHistory = ({ limit = 50, offset = 0, q = '', tag = '' } = {}) => {
  const params = new URLSearchParams({ limit, offset })
  if (q) params.set('q', q)
  if (tag) params.set('tag', tag)
  return request(`/history?${params.toString()}`)
}

// Clear history. With no args clears everything; pass { q, tag } to clear only
// the scans matching the current filters. Returns { status, deleted }.
export const clearHistory = ({ q = '', tag = '' } = {}) => {
  const params = new URLSearchParams()
  if (q) params.set('q', q)
  if (tag) params.set('tag', tag)
  const qs = params.toString()
  return request(`/history${qs ? `?${qs}` : ''}`, { method: 'DELETE' })
}

export const getHistoryStats = () => request('/history/stats')

export const getScanDetail = (id) => request(`/history/${id}`)

// ── Settings ──────────────────────────────────────────────────────────────────

export const getSettings = () => request('/settings')

// keys: { providerId: keyValue } — empty string clears, omitted leaves unchanged
export const updateApiKeys = (keys) =>
  request('/settings/keys', {
    method: 'PUT',
    body: JSON.stringify({ keys }),
  })

// Turn a provider on/off without removing its key
export const toggleProvider = (provider, enabled) =>
  request('/settings/toggle', {
    method: 'PUT',
    body: JSON.stringify({ provider, enabled }),
  })
