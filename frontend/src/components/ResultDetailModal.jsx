import { useState } from 'react'
import { rescan, saveNotes } from '../api/client'
import CopyReportButton, { buildReport } from './CopyReportButton'
import RiskBadge from './RiskBadge'
import TagSelector from './TagSelector'

const PROVIDER_NAMES = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  greynoise: 'GreyNoise',
  threatfox: 'ThreatFox',
  urlscan: 'URLScan.io',
  ipify: 'IPify Geolocation',
  rdap: 'RDAP / WHOIS',
}

function Section({ title, children }) {
  return (
    <div className="space-y-2">
      <div className="text-[10px] text-slate-500 uppercase tracking-widest border-b border-[#1e2d4a] pb-1">{title}</div>
      {children}
    </div>
  )
}

function KV({ label, value }) {
  if (value == null || value === '' || value === false) return null
  return (
    <div className="flex gap-2 text-xs font-mono">
      <span className="text-slate-500 shrink-0 w-32">{label}</span>
      <span className="text-slate-200 break-all">{String(value)}</span>
    </div>
  )
}

function VendorDetections({ detections }) {
  const entries = Object.entries(detections || {})
  if (!entries.length) return <p className="text-xs text-slate-500 font-mono">No malicious detections</p>
  return (
    <div className="max-h-40 overflow-y-auto space-y-1">
      {entries.map(([engine, info]) => (
        <div key={engine} className="flex gap-2 text-xs font-mono">
          <span className={`shrink-0 ${info.category === 'malicious' ? 'text-red-400' : 'text-amber-400'}`}>
            {info.category === 'malicious' ? '✕' : '△'}
          </span>
          <span className="text-slate-300 w-40 shrink-0 truncate">{engine}</span>
          <span className="text-slate-500 truncate">{info.result || info.category}</span>
        </div>
      ))}
    </div>
  )
}

function ProviderPanel({ pr }) {
  const r = pr.raw || {}
  if (!pr.success) {
    return (
      <div className="bg-red-950/20 border border-red-900/40 rounded p-3 text-xs font-mono text-red-400">
        {pr.error || 'Unknown error'}
      </div>
    )
  }

  const isVT = pr.provider === 'virustotal'
  const isAbuse = pr.provider === 'abuseipdb'
  const isGrey = pr.provider === 'greynoise'
  const isTF = pr.provider === 'threatfox'
  const isURLScan = pr.provider === 'urlscan'
  const isIPify = pr.provider === 'ipify'
  const isRDAP = pr.provider === 'rdap'

  return (
    <div className="bg-slate-900/50 border border-[#1e2d4a] rounded p-3 space-y-3">
      {isVT && (
        <>
          <div className="flex flex-wrap gap-4 text-xs font-mono">
            <span className="text-red-400">✕ {r.malicious ?? 0} malicious</span>
            <span className="text-amber-400">△ {r.suspicious ?? 0} suspicious</span>
            <span className="text-emerald-400">✓ {r.harmless ?? 0} harmless</span>
            <span className="text-slate-500">? {r.undetected ?? 0} undetected</span>
          </div>
          <KV label="File Name" value={r.file_name} />
          <KV label="File Type" value={r.file_type} />
          <KV label="First Seen" value={r.first_seen} />
          <KV label="Last Analysis" value={r.last_analysis} />
          <KV label="Country" value={r.country} />
          <KV label="ASN" value={r.asn} />
          <KV label="AS Owner" value={r.as_owner} />
          <KV label="Reputation" value={r.reputation} />
          <KV label="Page Title" value={r.title} />
          <KV label="Final URL" value={r.final_url} />
          {r.last_dns_records?.length > 0 && (
            <div className="text-xs font-mono text-slate-400">
              DNS: {r.last_dns_records.slice(0, 5).map(d => `${d.type} ${d.value}`).join(', ')}
            </div>
          )}
          {r.categories && Object.keys(r.categories).length > 0 && (
            <div className="text-xs font-mono text-slate-400">
              Categories: {Object.values(r.categories).join(', ')}
            </div>
          )}
          {r.vendor_detections && (
            <div className="mt-2">
              <div className="text-[10px] text-slate-500 mb-1">Vendor Detections</div>
              <VendorDetections detections={r.vendor_detections} />
            </div>
          )}
        </>
      )}

      {isAbuse && (
        <>
          <KV label="Confidence" value={r.abuse_confidence_score != null ? `${r.abuse_confidence_score}%` : null} />
          <KV label="Country" value={r.country_code} />
          <KV label="ISP" value={r.isp} />
          <KV label="Usage Type" value={r.usage_type} />
          <KV label="Total Reports" value={r.total_reports} />
          <KV label="TOR Node" value={r.is_tor ? 'YES ⚠' : null} />
          <KV label="Whitelisted" value={r.is_whitelisted ? 'Yes' : null} />
          <KV label="Last Reported" value={r.last_reported} />
        </>
      )}

      {isGrey && (
        <>
          <KV label="Classification" value={r.classification} />
          <KV label="Internet Noise" value={r.noise ? 'Yes' : null} />
          <KV label="RIOT (known good)" value={r.riot ? 'Yes' : null} />
          <KV label="Actor" value={r.name} />
          <KV label="Last Seen" value={r.last_seen} />
        </>
      )}

      {isTF && (
        <>
          <KV label="Matches" value={r.matches} />
          <KV label="Threat Type" value={r.threat_type} />
          <KV label="Malware" value={r.malware} />
          <KV label="Tags" value={r.tags?.length ? r.tags.join(', ') : null} />
          <KV label="First Seen" value={r.first_seen} />
          <KV label="Confidence" value={r.threatfox_confidence != null ? `${r.threatfox_confidence}%` : null} />
        </>
      )}

      {isURLScan && (
        <>
          <KV label="Total Scans" value={r.total_scans} />
          <KV label="Malicious Scans" value={r.malicious_scans} />
          <KV label="Latest Result" value={r.latest_result} />
          <KV label="Latest Scan" value={r.latest_time} />
        </>
      )}

      {isIPify && (
        <>
          {r.found === false && <p className="text-xs font-mono text-slate-500">No geolocation data found.</p>}
          <KV label="City" value={r.city} />
          <KV label="Region" value={r.region} />
          <KV label="Country" value={r.country} />
          <KV label="Postal Code" value={r.postal_code} />
          <KV label="Coordinates" value={r.lat != null && r.lng != null ? `${r.lat}, ${r.lng}` : null} />
          <KV label="Timezone" value={r.timezone} />
          <KV label="ISP" value={r.isp} />
          <KV label="ASN" value={r.asn} />
          <KV label="AS Name" value={r.as_name} />
          <KV label="AS Route" value={r.as_route} />
        </>
      )}

      {isRDAP && (
        <>
          {r.found === false && <p className="text-xs font-mono text-slate-500">No RDAP record found.</p>}
          {r.rdap_newly_registered && (
            <p className="text-xs font-mono text-amber-400">⚠ Newly registered domain ({r.age_days}d old)</p>
          )}
          <KV label="Registrar" value={r.registrar} />
          <KV label="Registered" value={r.registered} />
          <KV label="Expires" value={r.expires} />
          <KV label="Age (days)" value={r.age_days} />
          <KV label="Nameservers" value={r.nameservers?.length ? r.nameservers.join(', ') : null} />
          <KV label="Network" value={r.network_name} />
          <KV label="Owner" value={r.owner} />
          <KV label="Country" value={r.country} />
          <KV label="CIDR" value={r.cidr} />
          <KV label="Range" value={r.range} />
          <KV label="Status" value={r.statuses?.length ? r.statuses.join(', ') : null} />
        </>
      )}
    </div>
  )
}

export default function ResultDetailModal({ result, onClose, onTagged, onRescanned }) {
  const [localTag, setLocalTag] = useState(result?.tag || null)
  const [notes, setNotes] = useState(result?.notes || '')
  const [notesSaved, setNotesSaved] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshError, setRefreshError] = useState(null)

  if (!result) return null

  function handleTagged(tag) {
    setLocalTag(tag)
    onTagged?.(result.id, tag)
  }

  async function handleNotesBlur() {
    if (!result.id || notes === (result.notes || '')) return
    try {
      await saveNotes(result.id, notes)
      setNotesSaved(true)
      setTimeout(() => setNotesSaved(false), 1500)
    } catch {
      // keep the typed text; surfacing inline is enough
    }
  }

  async function handleRefresh() {
    setRefreshing(true)
    setRefreshError(null)
    try {
      const updated = await rescan(result.ioc)
      onRescanned?.(result, updated)
    } catch (e) {
      setRefreshError(e.message)
    } finally {
      setRefreshing(false)
    }
  }

  const report = buildReport({ ...result, tag: localTag })

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-end bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-[#0f172a] border-l border-[#1e2d4a] w-full max-w-xl h-full overflow-y-auto flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d4a] sticky top-0 bg-[#0f172a]">
          <div>
            <div className="text-xs text-slate-500 uppercase tracking-widest">IOC Detail</div>
            <div className="text-cyan-400 font-mono text-sm truncate max-w-xs mt-0.5">{result.ioc}</div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              title="Re-scan now (bypass cache)"
              className="text-xs font-mono px-2 py-1 border border-[#1e2d4a] rounded text-slate-400 hover:text-cyan-400 hover:border-cyan-700 transition-all disabled:opacity-50"
            >
              {refreshing ? '⟳ …' : '⟳ Refresh'}
            </button>
            <button onClick={onClose} className="text-slate-500 hover:text-slate-200 text-xl leading-none">✕</button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 p-5 space-y-5">

          <Section title="Summary">
            <div className="flex flex-wrap gap-3 items-center">
              <RiskBadge band={result.risk_band} score={result.risk_score} />
              <span className="text-xs font-mono text-slate-400 bg-slate-800 border border-[#1e2d4a] px-2 py-0.5 rounded">
                {result.ioc_type?.toUpperCase()}
              </span>
              {result.detection_ratio && (
                <span className="text-xs font-mono text-slate-300">
                  Detection: {result.detection_ratio}
                </span>
              )}
              {result.from_cache && (
                <span className="text-[10px] font-mono text-cyan-500 bg-cyan-950/40 border border-cyan-800 px-2 py-0.5 rounded" title="Reused from a recent scan">
                  cached
                </span>
              )}
            </div>
            {refreshError && <p className="text-red-400 text-xs font-mono">✕ {refreshError}</p>}
            {result.source_filename && (
              <div className="text-xs font-mono text-slate-500">
                📄 {result.source_filename}
                {result.file_size != null && ` (${(result.file_size / 1024).toFixed(1)} KB)`}
              </div>
            )}
            {result.created_at && (
              <div className="text-xs font-mono text-slate-600">
                Scanned: {new Date(result.created_at).toLocaleString()}
              </div>
            )}
          </Section>

          {result.id && (
            <Section title="Tag">
              <TagSelector
                scanId={result.id}
                currentTag={localTag}
                onTagged={handleTagged}
              />
            </Section>
          )}

          {result.id && (
            <Section title="Notes">
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                onBlur={handleNotesBlur}
                placeholder="Add investigation notes… (saved when you click away)"
                rows={3}
                className="w-full bg-slate-900 border border-[#1e2d4a] rounded px-3 py-2 text-xs font-mono text-slate-300 placeholder-slate-700 focus:outline-none focus:border-cyan-700 resize-y"
              />
              {notesSaved && <span className="text-[10px] font-mono text-emerald-400">✓ saved</span>}
            </Section>
          )}

          {(result.provider_results || []).map((pr) => (
            <Section key={pr.provider} title={PROVIDER_NAMES[pr.provider] || pr.provider}>
              <ProviderPanel pr={pr} />
            </Section>
          ))}

          <Section title="Investigation Report">
            <pre className="bg-slate-900 border border-[#1e2d4a] rounded p-3 text-[11px] font-mono text-slate-300 whitespace-pre-wrap overflow-x-auto">
              {report}
            </pre>
          </Section>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-[#1e2d4a] flex justify-end">
          <CopyReportButton result={{ ...result, tag: localTag }} />
        </div>
      </div>
    </div>
  )
}
