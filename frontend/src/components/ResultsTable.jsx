import { useMemo, useState } from 'react'
import RiskBadge from './RiskBadge'
import ResultDetailModal from './ResultDetailModal'

const COLUMNS = [
  { key: 'ioc',             label: 'IOC',            sortable: true  },
  { key: 'ioc_type',        label: 'Type',           sortable: true  },
  { key: 'risk_band',       label: 'Risk',           sortable: true  },
  { key: 'detection_ratio', label: 'Detection',      sortable: false },
  { key: 'source',          label: 'Source',         sortable: false },
  { key: 'status',          label: 'Status',         sortable: false },
]

const RISK_ORDER = { High: 0, Medium: 1, Low: 2 }

function exportCSV(rows) {
  const headers = ['IOC', 'Type', 'Risk Band', 'Risk Score', 'Detection Ratio', 'Status', 'Tag', 'Source File', 'Scanned At']
  const lines = [
    headers.join(','),
    ...rows.map(r => [
      `"${r.ioc}"`,
      r.ioc_type,
      r.risk_band || '',
      r.risk_score ?? '',
      r.detection_ratio || '',
      r.status,
      r.tag || '',
      r.source_filename || '',
      r.created_at ? new Date(r.created_at).toISOString() : '',
    ].join(','))
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `bulk-ioc-scanner-export-${Date.now()}.csv`
  a.click()
}

export default function ResultsTable({ results, onTagUpdated, onResultReplaced }) {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [riskFilter, setRiskFilter] = useState('all')
  const [sortKey, setSortKey] = useState('risk_band')
  const [sortDir, setSortDir] = useState('asc')
  const [selected, setSelected] = useState(null)

  const types = useMemo(() => {
    const s = new Set(results.map(r => r.ioc_type).filter(Boolean))
    return ['all', ...s]
  }, [results])

  const filtered = useMemo(() => {
    let rows = [...results]
    if (search) {
      const q = search.toLowerCase()
      rows = rows.filter(r => r.ioc.toLowerCase().includes(q))
    }
    if (typeFilter !== 'all') rows = rows.filter(r => r.ioc_type === typeFilter)
    if (riskFilter !== 'all') rows = rows.filter(r => r.risk_band === riskFilter)

    rows.sort((a, b) => {
      let av = a[sortKey], bv = b[sortKey]
      if (sortKey === 'risk_band') {
        av = RISK_ORDER[av] ?? 99
        bv = RISK_ORDER[bv] ?? 99
      }
      if (av == null) return 1
      if (bv == null) return -1
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return rows
  }, [results, search, typeFilter, riskFilter, sortKey, sortDir])

  function toggleSort(key) {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  function handleTagUpdated(id, tag) {
    onTagUpdated?.(id, tag)
    // update selected in-place
    if (selected?.id === id) setSelected(prev => ({ ...prev, tag }))
  }

  function handleRescanned(old, updated) {
    setSelected(updated)
    onResultReplaced?.(old, updated)
  }

  if (!results.length) return null

  return (
    <>
      {/* Controls */}
      <div className="flex flex-wrap gap-3 items-center justify-between mb-3">
        <div className="flex flex-wrap gap-2">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search IOC..."
            className="bg-slate-900 border border-[#1e2d4a] rounded px-3 py-1.5 text-xs font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-700 w-52"
          />
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="bg-slate-900 border border-[#1e2d4a] rounded px-2 py-1.5 text-xs font-mono text-slate-400 focus:outline-none focus:border-cyan-700"
          >
            {types.map(t => <option key={t} value={t}>{t === 'all' ? 'All types' : t.toUpperCase()}</option>)}
          </select>
          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
            className="bg-slate-900 border border-[#1e2d4a] rounded px-2 py-1.5 text-xs font-mono text-slate-400 focus:outline-none focus:border-cyan-700"
          >
            <option value="all">All risk</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
          <span>{filtered.length}/{results.length} results</span>
          <button
            onClick={() => exportCSV(filtered)}
            className="px-3 py-1.5 border border-[#1e2d4a] text-slate-400 hover:text-cyan-400 hover:border-cyan-700 rounded transition-all"
          >
            ⬇ Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-[#1e2d4a]">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-[#1e2d4a] bg-slate-900/60">
              {COLUMNS.map(col => (
                <th
                  key={col.key}
                  onClick={() => col.sortable && toggleSort(col.key)}
                  className={`text-left px-4 py-3 text-[10px] uppercase tracking-widest text-slate-500
                    ${col.sortable ? 'cursor-pointer hover:text-slate-300 select-none' : ''}`}
                >
                  {col.label}
                  {col.sortable && sortKey === col.key && (
                    <span className="ml-1 text-cyan-600">{sortDir === 'asc' ? '↑' : '↓'}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr
                key={r.id ?? i}
                onClick={() => setSelected(r)}
                className="border-b border-[#1e2d4a]/50 hover:bg-cyan-950/10 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 text-slate-300 max-w-xs">
                  <span className="truncate block max-w-[260px]" title={r.ioc}>{r.ioc}</span>
                </td>
                <td className="px-4 py-3 text-slate-400">{r.ioc_type?.toUpperCase()}</td>
                <td className="px-4 py-3">
                  <RiskBadge band={r.risk_band} score={r.risk_score} />
                </td>
                <td className="px-4 py-3 text-slate-400">{r.detection_ratio || '—'}</td>
                <td className="px-4 py-3 text-slate-500 max-w-[120px] truncate">
                  {r.source_filename || '—'}
                </td>
                <td className="px-4 py-3">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                    r.status === 'error'
                      ? 'text-red-400 bg-red-950/30'
                      : 'text-emerald-400 bg-emerald-950/30'
                  }`}>
                    {r.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <ResultDetailModal
          key={selected.id}
          result={selected}
          onClose={() => setSelected(null)}
          onTagged={handleTagUpdated}
          onRescanned={handleRescanned}
        />
      )}
    </>
  )
}
