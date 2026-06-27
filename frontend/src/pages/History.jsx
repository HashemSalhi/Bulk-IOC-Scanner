import { useEffect, useState } from 'react'
import { getScanDetail, getHistory } from '../api/client'
import RiskBadge from '../components/RiskBadge'
import ResultDetailModal from '../components/ResultDetailModal'

export default function HistoryPage() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  useEffect(() => {
    getHistory()
      .then(setHistory)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

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

  if (loading) return <div className="p-6 text-slate-500 font-mono text-sm">Loading history…</div>
  if (error) return <div className="p-6 text-red-400 font-mono text-sm">✕ {error}</div>

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      <div>
        <h1 className="text-xl font-mono font-bold text-slate-200">Scan History</h1>
        <p className="text-xs text-slate-500 mt-1">{history.length} scans stored · click a row to view details</p>
      </div>

      {history.length === 0 ? (
        <div className="text-center py-20 text-slate-600 font-mono text-sm">
          No scans yet — run your first scan from the Scan page.
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
