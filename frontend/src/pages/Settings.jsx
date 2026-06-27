import { useEffect, useState } from 'react'
import { getSettings, updateApiKeys } from '../api/client'

function ProviderRow({ p }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[#1e2d4a] last:border-0">
      <div className="flex items-center gap-3">
        <span className={`w-2 h-2 rounded-full ${p.enabled ? 'bg-emerald-400' : 'bg-slate-600'}`} />
        <span className="text-sm font-mono text-slate-200">{p.name}</span>
      </div>
      <div className="text-xs font-mono text-slate-500">
        {p.enabled ? (
          <span className="text-emerald-400">✓ Active {p.key_hint && `· ${p.key_hint}`}</span>
        ) : (
          <span className="text-slate-600">✕ No key configured</span>
        )}
      </div>
    </div>
  )
}

function KeyInput({ label, value, onChange, placeholder }) {
  const [show, setShow] = useState(false)
  return (
    <div className="space-y-1">
      <label className="text-[10px] text-slate-500 uppercase tracking-widest">{label}</label>
      <div className="flex gap-2">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="off"
          spellCheck={false}
          className="flex-1 bg-slate-900 border border-[#1e2d4a] rounded px-3 py-2 text-xs font-mono text-slate-300
            placeholder-slate-700 focus:outline-none focus:border-cyan-700"
        />
        <button
          type="button"
          onClick={() => setShow(s => !s)}
          title={show ? 'Hide key' : 'Show key'}
          className="px-3 py-2 border border-[#1e2d4a] rounded text-slate-500 hover:text-slate-300 hover:border-slate-600
            text-xs font-mono transition-all"
        >
          {show ? '◉' : '◎'}
        </button>
      </div>
    </div>
  )
}

export default function Settings() {
  const [cfg, setCfg] = useState(null)
  const [loading, setLoading] = useState(true)
  const [pageError, setPageError] = useState(null)

  // Key form state: { providerId: typedValue }
  const [keyInputs, setKeyInputs] = useState({})
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState(null)   // { type: 'ok'|'error', text }

  useEffect(() => {
    getSettings()
      .then(setCfg)
      .catch(e => setPageError(e.message))
      .finally(() => setLoading(false))
  }, [])

  function setKey(id, value) {
    setKeyInputs(prev => ({ ...prev, [id]: value }))
  }

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setSaveMsg(null)

    // Only send fields that were typed into; leave blank = no change
    const payload = {}
    for (const [id, value] of Object.entries(keyInputs)) {
      if (value !== '' && value != null) payload[id] = value
    }

    if (!Object.keys(payload).length) {
      setSaveMsg({ type: 'error', text: 'Enter at least one key to save.' })
      setSaving(false)
      return
    }

    try {
      const updated = await updateApiKeys(payload)
      setCfg(prev => ({ ...prev, providers: updated.providers }))
      setKeyInputs({})
      setSaveMsg({ type: 'ok', text: 'API keys saved — providers active immediately.' })
    } catch (e) {
      setSaveMsg({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  if (loading)    return <div className="p-6 text-slate-500 font-mono text-sm">Loading…</div>
  if (pageError)  return <div className="p-6 text-red-400 font-mono text-sm">✕ {pageError}</div>

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-mono font-bold text-slate-200">Settings</h1>
        <p className="text-xs text-slate-500 mt-1">Provider configuration and scan limits</p>
      </div>

      {/* Provider status */}
      <div className="bg-[#0f172a] border border-[#1e2d4a] rounded-lg p-4">
        <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-3">Provider Status</div>
        {cfg?.providers.map(p => <ProviderRow key={p.name} p={p} />)}
      </div>

      {/* Key entry form */}
      <div className="bg-[#0f172a] border border-[#1e2d4a] rounded-lg p-4 space-y-4">
        <div className="text-[10px] text-slate-500 uppercase tracking-widest">Configure API Keys</div>

        <p className="text-xs text-slate-500">
          Keys are stored in the backend database and take effect immediately — no restart required.
          Leave a field blank to keep the existing key unchanged.
        </p>

        <form onSubmit={handleSave} className="space-y-4">
          {cfg?.providers.map(p => (
            <KeyInput
              key={p.id}
              label={`${p.name} API Key`}
              value={keyInputs[p.id] || ''}
              onChange={v => setKey(p.id, v)}
              placeholder={p.enabled ? `Configured (${p.key_hint}) — enter to replace…` : `Enter ${p.name} API key…`}
            />
          ))}

          <div className="flex items-center gap-4 pt-1">
            <button
              type="submit"
              disabled={saving}
              className={`px-5 py-2 rounded text-sm font-mono font-semibold transition-all
                ${saving
                  ? 'bg-slate-800 text-slate-600 cursor-not-allowed'
                  : 'bg-cyan-700 hover:bg-cyan-600 text-white'
                }`}
            >
              {saving ? 'Saving…' : '⚙ Save Keys'}
            </button>

            {saveMsg && (
              <span className={`text-xs font-mono ${saveMsg.type === 'ok' ? 'text-emerald-400' : 'text-red-400'}`}>
                {saveMsg.type === 'ok' ? '✓' : '✕'} {saveMsg.text}
              </span>
            )}
          </div>
        </form>

        <p className="text-[10px] text-slate-600 border-t border-[#1e2d4a] pt-3">
          Keys are never returned by the API. Only a masked hint (e.g. <code>ABCD...1234</code>) is shown above.
          You can also set keys via <code className="text-cyan-700">backend/.env</code> — DB keys take priority.
        </p>
      </div>

      {/* Limits */}
      {cfg && (
        <div className="bg-[#0f172a] border border-[#1e2d4a] rounded-lg p-4 space-y-3">
          <div className="text-[10px] text-slate-500 uppercase tracking-widest">Scan Limits</div>
          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Max file upload size</span>
              <span className="text-slate-200">{cfg.max_upload_mb} MB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Max IOCs per scan</span>
              <span className="text-slate-200">{cfg.max_iocs_per_scan}</span>
            </div>
          </div>
        </div>
      )}

      {/* Adding a provider */}
      <div className="bg-[#0f172a] border border-[#1e2d4a] rounded-lg p-4 space-y-3">
        <div className="text-[10px] text-slate-500 uppercase tracking-widest">Adding a New Provider</div>
        <p className="text-xs text-slate-400">
          Create <code className="text-cyan-400">backend/app/providers/yourprovider.py</code> implementing the
          <code className="text-cyan-400"> Provider</code> ABC (<code>supports()</code> + <code>lookup()</code>),
          then register it in <code className="text-cyan-400">backend/app/providers/registry.py</code>.
        </p>
      </div>
    </div>
  )
}
