import { useState } from 'react'
import { scanFiles, scanStream } from '../api/client'
import FileDropzone from '../components/FileDropzone'
import ResultsTable from '../components/ResultsTable'
import ScanProgress from '../components/ScanProgress'

export default function ScanPage() {
  const [mode, setMode] = useState('text')          // 'text' | 'files'
  const [input, setInput] = useState('')
  const [selectedFiles, setSelectedFiles] = useState([])
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(null)
  const [results, setResults] = useState([])
  const [error, setError] = useState(null)

  async function handleScan() {
    setError(null)
    setResults([])
    setScanning(true)

    try {
      if (mode === 'text') {
        const unique = [...new Set(input.split(/[\n,]+/).map(s => s.trim()).filter(Boolean))]
        setProgress({ total: unique.length, completed: 0, current: 'Starting…' })
        const collected = []
        await scanStream(unique, (r) => {
          collected.push(r)
          setResults([...collected])
          setProgress({ total: unique.length, completed: collected.length, current: r.ioc })
        })
        setProgress({ total: unique.length, completed: collected.length, current: null })
      } else {
        if (!selectedFiles.length) {
          setError('Please select at least one file')
          return
        }
        setProgress({ total: selectedFiles.length, completed: 0, current: selectedFiles[0]?.name })
        const data = await scanFiles(selectedFiles)
        // data is FileScanResult[] — flatten to ScanResult rows (errored files become error rows)
        const flat = data.map(d => {
          if (d.error || !d.scan_result) {
            return {
              ioc: d.filename,
              ioc_type: 'file',
              risk_band: null,
              status: 'error',
              source_filename: d.filename,
              provider_results: [{ provider: 'system', success: false, error: d.error }],
            }
          }
          return {
            ...d.scan_result,
            source_filename: d.file_info.filename,
            file_size: d.file_info.size,
            _hashes: { md5: d.file_info.md5, sha1: d.file_info.sha1, sha256: d.file_info.sha256 },
          }
        })
        setResults(flat)
        setProgress({ total: selectedFiles.length, completed: selectedFiles.length, current: null })
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setScanning(false)
    }
  }

  function handleTagUpdated(id, tag) {
    setResults(prev => prev.map(r => r.id === id ? { ...r, tag } : r))
  }

  function handleResultReplaced(old, updated) {
    setResults(prev => prev.map(r => r.id === old.id ? updated : r))
  }

  const canScan = mode === 'text' ? input.trim().length > 0 : selectedFiles.length > 0

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <div>
        <h1 className="text-xl font-mono font-bold text-slate-200">Bulk IOC Scanner</h1>
        <p className="text-xs text-slate-500 mt-1">
          Scan hashes (MD5/SHA1/SHA256), IP addresses, domains, and URLs against threat intelligence providers.
        </p>
      </div>

      {/* Mode tabs */}
      <div className="flex gap-1 border-b border-[#1e2d4a]">
        {[
          { id: 'text', label: '⌨ Paste IOCs' },
          { id: 'files', label: '📁 Upload Files' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setMode(tab.id)}
            className={`px-4 py-2 text-xs font-mono transition-all border-b-2 -mb-px
              ${mode === tab.id
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Input area */}
      {mode === 'text' ? (
        <div className="space-y-2">
          <label className="text-[10px] uppercase tracking-widest text-slate-500">
            Paste IOCs (newline or comma separated)
          </label>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={`44d88612fea8a8f36de82e1278abb02f\n8.8.8.8\nexample.com\nhttps://malicious.example.com`}
            rows={8}
            className="w-full bg-slate-900 border border-[#1e2d4a] rounded-lg px-4 py-3 text-xs font-mono text-slate-300 placeholder-slate-700 focus:outline-none focus:border-cyan-700 resize-y"
          />
          <div className="text-[10px] text-slate-600 font-mono">
            {input.split(/[\n,]+/).filter(l => l.trim()).length} IOCs detected
          </div>
        </div>
      ) : (
        <FileDropzone
          onFilesSelected={setSelectedFiles}
        />
      )}

      {/* Scan button */}
      <button
        onClick={handleScan}
        disabled={scanning || !canScan}
        className={`px-6 py-2.5 rounded-lg text-sm font-mono font-semibold transition-all
          ${scanning || !canScan
            ? 'bg-slate-800 text-slate-600 cursor-not-allowed'
            : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-900/30'
          }`}
      >
        {scanning ? '⌖ Scanning...' : '⌖ Start Scan'}
      </button>

      {/* Progress */}
      {scanning && progress && (
        <ScanProgress
          total={progress.total}
          completed={progress.completed}
          current={progress.current}
        />
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-950/20 border border-red-900/40 rounded-lg p-4 text-sm text-red-400 font-mono">
          ✕ {error}
        </div>
      )}

      {/* Results — render live as they stream in */}
      {results.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-mono font-semibold text-slate-300">
              Scan Results ({results.length})
            </h2>
            <div className="flex gap-2 text-xs font-mono">
              <span className="text-red-400">
                {results.filter(r => r.risk_band === 'High').length} high
              </span>
              <span className="text-amber-400">
                {results.filter(r => r.risk_band === 'Medium').length} medium
              </span>
              <span className="text-emerald-400">
                {results.filter(r => r.risk_band === 'Low').length} low
              </span>
            </div>
          </div>
          <ResultsTable results={results} onTagUpdated={handleTagUpdated} onResultReplaced={handleResultReplaced} />
        </div>
      )}
    </div>
  )
}
