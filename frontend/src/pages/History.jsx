import { useCallback, useEffect, useState } from 'react'
import { clearHistory, getScanDetail, getHistory } from '../api/client'
import RiskBadge from '../components/RiskBadge'
import ResultDetailModal from '../components/ResultDetailModal'

const TAGS = ['', 'Malware', 'Phishing', 'Investigation', 'False Positive']
const PAGE_SIZE = 50

export default function HistoryPage() {
  const [history, setHistory] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  // Filters / pagination
  const [search, setSearch] = useState('')
  const [tag, setTag] = useState('')
  const [page, setPage] = useState(0)

  // Clear-history confirmation
  const [confirmClear, setConfirmClear] = useState(false)
  const [clearing, setClearing] = useState(false)

  const filtered = Boolean(search || tag)

  const load = useCallback(() => {
    setLoading(true)
    getHistory({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, q: search, tag })
      .then(res => { setHistory(res.items); setTotal(res.total) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, search, tag])

  // Debounce search/tag/page changes
  useEffect(() => {
    const t = setTimeout(load, 250)
    return () => clearTimeout(t)
  }, [load])

  const maxPage = Math.max(0, Math.ceil(total / PAGE_SIZE) - 1)

  async function handleRowClick(item) {
    setLoadingDetail(true)
    try {
      const detail = await getScanDetail(item.id)
      setSelected(detail)
    } catch (e) {
      // Fall back to the history item without provider results
      setSelected(item)
    } finally {
      setLoadingDetail(false)
    }
  }

  function handleTagUpdated(id, tag) {
    setHistory(prev => prev.map(h => h.id === id ? { ...h, tag } : h))
    if (selected?.id === id) setSelected(prev => ({ ...prev, tag }))
  }

  function handleRescanned(old, updated) {
    // A forced re-scan creates a new history row; prepend it and show it
    setHistory(prev => [updated, ...prev])
    setSelected(updated)
  }

  async function handleClear() {
    setClearing(true)
    try {
      await clearHistory(filtered ? { q: search, tag } : {})
      setConfirmClear(false)
      setPage(0)
      load()
    } catch (e) {
      setError(e.message)
    } finally {
      setClearing(false)
    }
  }

  if (error) return <div className="p-6 text-red-400 font-mono text-sm">✕ {error}</div>

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      <div>
        <h1 className="text-xl font-mono font-bold text-slate-200">Scan History</h1>
        <p className="text-xs text-slate-500 mt-1">{total} scans stored · click a row to view details</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <input
          value={search}
          onChange={e => { setPage(0); setSearch(e.target.value) }}
          placeholder="Search IOC…"
          className="bg-slate-900 border border-[#1e2d4a] rounded px-3 py-1.5 text-xs font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-700 w-56"
        />
        <select
          value={tag}
          onChange={e => { setPage(0); setTag(e.target.value) }}
          className="bg-slate-900 border border-[#1e2d4a] rounded px-2 py-1.5 text-xs font-mono text-slate-400 focus:outline-none focus:border-cyan-700"
        >
          {TAGS.map(t => <option key={t} value={t}>{t === '' ? 'All tags' : t}</option>)}
        </select>
        {loading && <span className="text-xs font-mono text-slate-600">loading…</span>}

        {/* Clear history */}
        <div className="ml-auto flex items-center gap-2">
          {confirmClear ? (
            <>
              <span className="text-xs font-mono text-amber-400">
                {filtered ? `Delete ${total} matching scan${total === 1 ? '' : 's'}?` : `Delete all ${total} scans?`}
              </span>
              <button
                onClick={handleClear}
                disabled={clearing}
                className="px-3 py-1.5 text-xs font-mono border border-red-800 bg-red-950/40 text-red-300 rounded hover:bg-red-900/50 disabled:opacity-50 transition-all"
              >
                {clearing ? 'Clearing…' : 'Confirm delete'}
              </button>
              <button
                onClick={() => setConfirmClear(false)}
                disabled={clearing}
                className="px-3 py-1.5 text-xs font-mono border border-[#1e2d4a] text-slate-400 rounded hover:text-slate-200 hover:border-slate-600 transition-all"
              >
                Cancel
              </button>
            </>
          ) : (
            <button
              onClick={() => setConfirmClear(true)}
              disabled={total === 0}
              title={filtered ? 'Delete the scans matching the current filters' : 'Delete all scan history'}
              className="px-3 py-1.5 text-xs font-mono border border-[#1e2d4a] text-slate-400 rounded hover:text-red-400 hover:border-red-800 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              🗑 {filtered ? 'Clear matching' : 'Clear history'}
            </button>
          )}
        </div>
      </div>

      {history.length === 0 ? (
        <div className="text-center py-20 text-slate-600 font-mono text-sm">
          {search || tag ? 'No scans match your filters.' : 'No scans yet — run your first scan from the Scan page.'}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-[#1e2d4a]">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2d4a] bg-slate-900/60">
                {['IOC', 'Type', 'Risk', 'Detection', 'Tag', 'Source', 'Date'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] uppercase tracking-widest text-slate-500">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.map(item => (
                <tr
                  key={item.id}
                  onClick={() => handleRowClick(item)}
                  className="border-b border-[#1e2d4a]/50 hover:bg-cyan-950/10 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 text-slate-300 max-w-[220px]">
                    <span className="truncate block" title={item.ioc}>{item.ioc}</span>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{item.ioc_type?.toUpperCase()}</td>
                  <td className="px-4 py-3"><RiskBadge band={item.risk_band} score={item.risk_score} /></td>
                  <td className="px-4 py-3 text-slate-400">{item.detection_ratio || '—'}</td>
                  <td className="px-4 py-3 text-slate-500">{item.tag || '—'}</td>
                  <td className="px-4 py-3 text-slate-600 max-w-[100px] truncate">{item.source_filename || '—'}</td>
                  <td className="px-4 py-3 text-slate-600">
                    {item.created_at ? new Date(item.created_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-xs font-mono text-slate-500">
          <span>Page {page + 1} of {maxPage + 1}</span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 border border-[#1e2d4a] rounded hover:text-cyan-400 hover:border-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              ← Prev
            </button>
            <button
              onClick={() => setPage(p => Math.min(maxPage, p + 1))}
              disabled={page >= maxPage}
              className="px-3 py-1 border border-[#1e2d4a] rounded hover:text-cyan-400 hover:border-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next →
            </button>
          </div>
        </div>
      )}

      {loadingDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="text-cyan-400 font-mono text-sm">Loading…</div>
        </div>
      )}

      {selected && !loadingDetail && (
        <ResultDetailModal
          key={selected.id}
          result={selected}
          onClose={() => setSelected(null)}
          onTagged={handleTagUpdated}
          onRescanned={handleRescanned}
        />
      )}
    </div>
  )
}
