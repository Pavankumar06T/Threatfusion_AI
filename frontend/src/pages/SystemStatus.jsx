import { useEffect, useState } from 'react'
import { fetchHealth, fetchStats } from '../services/api'
import { RefreshCw } from 'lucide-react'

function StatusRow({ label, value, ok }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-border last:border-0">
      <span className="text-sm text-text">{label}</span>
      <div className="flex items-center gap-2">
        <span className={ok ? 'dot-online' : 'dot-offline'} />
        <span className="text-xs font-mono text-dim">{value}</span>
      </div>
    </div>
  )
}

export default function SystemStatus() {
  const [health, setHealth] = useState(null)
  const [stats,  setStats]  = useState(null)
  const [loading,setLoading]= useState(true)

  const load = () => {
    setLoading(true)
    Promise.all([fetchHealth(), fetchStats()])
      .then(([h, s]) => { setHealth(h); setStats(s) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">System Status</h1>
          <p className="text-sm text-dim mt-0.5">External services and component health</p>
        </div>
        <button onClick={load} disabled={loading} className="btn-ghost flex items-center gap-2">
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="panel p-5">
        <p className="text-xs font-mono text-dim uppercase tracking-widest mb-4">External Services</p>
        {health ? (
          <>
            <StatusRow label="Google Gemini (LLM)"     value={health.gemini}     ok={!health.gemini.includes('unavailable')} />
            <StatusRow label="VirusTotal (Threat Intel)" value={health.virustotal} ok={!health.virustotal.includes('unavailable')} />
            <StatusRow label="ChromaDB (Vector Store)"  value={health.chromadb}   ok={!health.chromadb.includes('unavailable')} />
            <StatusRow label="SQLite Database"          value={health.database}   ok={health.database === 'healthy'} />
          </>
        ) : (
          <p className="text-dim text-sm">Loading…</p>
        )}
      </div>

      <div className="panel p-5">
        <p className="text-xs font-mono text-dim uppercase tracking-widest mb-4">Analysis Statistics</p>
        {stats ? (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {[
              { label: 'Total Analysed', value: stats.total_analyzed },
              { label: 'Critical',       value: stats.critical_count },
              { label: 'High Risk',      value: stats.high_risk_count },
              { label: 'Suspicious',     value: stats.suspicious_count },
              { label: 'Safe',           value: stats.safe_count },
              { label: 'Avg Risk Score', value: `${stats.avg_risk_score}/100` },
            ].map(({ label, value }) => (
              <div key={label} className="bg-surface border border-border rounded-lg p-3">
                <p className="text-[10px] font-mono text-dim uppercase tracking-wider">{label}</p>
                <p className="text-lg font-bold font-mono text-white mt-1">{value}</p>
              </div>
            ))}
          </div>
        ) : <p className="text-dim text-sm">Loading…</p>}
      </div>

      <div className="panel p-5">
        <p className="text-xs font-mono text-dim uppercase tracking-widest mb-4">Agent Configuration</p>
        <div className="space-y-2 font-mono text-xs">
          {[
            ['Agent 1 — Header/Metadata',    'Deterministic rules',       'Always on'],
            ['Agent 2 — Content/Linguistic', 'Gemini + heuristic fallback','Adaptive'],
            ['Agent 3 — URL/Threat Intel',   'VirusTotal + local heuristics','Adaptive'],
            ['Agent 4 — Memory/RAG',         'ChromaDB · all-MiniLM-L6-v2','Requires init'],
            ['Fusion Agent',                 'Weighted scoring 25/25/30/20','Always on'],
          ].map(([name, desc, status], i) => (
            <div key={i} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
              <div>
                <p className="text-text">{name}</p>
                <p className="text-dim text-[10px]">{desc}</p>
              </div>
              <span className="text-[10px] bg-muted border border-border rounded px-2 py-0.5 text-dim">{status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
