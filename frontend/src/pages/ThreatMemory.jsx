import { useEffect, useState } from 'react'
import { fetchMemoryStatus, initializeMemory } from '../services/api'
import { Database, Zap, CheckCircle2, AlertTriangle } from 'lucide-react'

export default function ThreatMemory() {
  const [status,    setStatus]    = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [initing,   setIniting]   = useState(false)
  const [initResult,setInitResult]= useState(null)
  const [error,     setError]     = useState(null)

  const load = () => fetchMemoryStatus().then(setStatus).catch(e => setError(e.message)).finally(() => setLoading(false))
  useEffect(() => { load() }, [])

  const handleInit = async () => {
    setIniting(true); setError(null); setInitResult(null)
    try {
      const r = await initializeMemory()
      setInitResult(r)
      load()
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setIniting(false)
    }
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div>
        <h1 className="text-xl font-bold text-white">Threat Memory</h1>
        <p className="text-sm text-dim mt-0.5">ChromaDB vector store — historical phishing campaign knowledge</p>
      </div>

      {/* Status card */}
      <div className="panel p-5">
        <div className="flex items-center gap-3 mb-5">
          <Database size={18} className="text-accent" />
          <h2 className="text-sm font-semibold text-white">Vector Database Status</h2>
        </div>

        {loading ? (
          <p className="text-dim text-sm">Loading…</p>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Status',       value: status?.available ? 'Online'    : 'Offline', ok: status?.available },
              { label: 'Records',      value: status?.record_count ?? '—',     ok: (status?.record_count ?? 0) > 0 },
              { label: 'Initialised',  value: status?.initialized ? 'Yes' : 'No', ok: status?.initialized },
              { label: 'Threshold',    value: `${Math.round((status?.similarity_threshold ?? 0) * 100)}%`, ok: true },
            ].map(({ label, value, ok }) => (
              <div key={label} className="bg-surface border border-border rounded-lg p-3">
                <p className="text-[10px] font-mono text-dim uppercase tracking-wider mb-1">{label}</p>
                <div className="flex items-center gap-2">
                  {ok
                    ? <CheckCircle2 size={13} className="text-safe" />
                    : <AlertTriangle size={13} className="text-suspicious" />}
                  <span className="text-sm font-mono font-semibold text-white">{value}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Init section */}
      <div className="panel p-5">
        <h2 className="text-sm font-semibold text-white mb-2">Initialise with Sample Data</h2>
        <p className="text-xs text-dim mb-4 leading-relaxed">
          Load 15 curated phishing and legitimate email samples into the vector database.
          This enables historical similarity detection for future analyses.
          Safe to run multiple times — duplicates are skipped.
        </p>

        {error && (
          <div className="mb-3 p-3 border border-critical/30 bg-critical/5 rounded-md text-critical text-xs">
            {error}
          </div>
        )}
        {initResult && (
          <div className="mb-3 p-3 border border-safe/30 bg-safe/5 rounded-md text-safe text-xs font-mono">
            ✓ {initResult.message}
          </div>
        )}

        <button onClick={handleInit} disabled={initing || !status?.available}
                className="btn-primary flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
          <Zap size={14} />
          {initing ? 'Initialising…' : 'Initialise Memory Database'}
        </button>
        {!status?.available && (
          <p className="text-xs text-critical mt-2">ChromaDB unavailable — check backend configuration</p>
        )}
      </div>

      {/* Sample data preview */}
      <div className="panel p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Included Sample Campaigns</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            { name: 'PayPal Credential Harvesting',   type: 'Credential Phishing',    risk: 'CRITICAL'  },
            { name: 'Microsoft Account Phishing',      type: 'Account Takeover',       risk: 'HIGH RISK' },
            { name: 'BEC Invoice Fraud',               type: 'Financial Fraud',        risk: 'HIGH RISK' },
            { name: 'Amazon Payment Scam',             type: 'Credential Phishing',    risk: 'CRITICAL'  },
            { name: 'LinkedIn Suspension Phishing',    type: 'Social Engineering',     risk: 'HIGH RISK' },
            { name: 'CEO Fraud / Wire Transfer',       type: 'BEC',                    risk: 'CRITICAL'  },
            { name: 'Apple ID Phishing',               type: 'Account Takeover',       risk: 'CRITICAL'  },
            { name: 'DHL Delivery Scam',               type: 'Impersonation',          risk: 'HIGH RISK' },
            { name: 'Netflix Billing Phishing',        type: 'Credential Phishing',    risk: 'HIGH RISK' },
            { name: 'IRS Tax Refund Scam',             type: 'Government Impersonation',risk:'CRITICAL'  },
            { name: 'University Newsletter',           type: 'Legitimate',             risk: 'SAFE'      },
            { name: 'GitHub Notification',             type: 'Legitimate',             risk: 'SAFE'      },
            { name: 'Chase Bank Statement',            type: 'Legitimate',             risk: 'SAFE'      },
            { name: 'Corporate Meeting Invite',        type: 'Legitimate',             risk: 'SAFE'      },
            { name: 'Amazon Shipping Notification',    type: 'Legitimate',             risk: 'SAFE'      },
          ].map((s, i) => {
            const cls = s.risk === 'CRITICAL' ? 'badge-critical' : s.risk === 'HIGH RISK' ? 'badge-high' : 'badge-safe'
            return (
              <div key={i} className="flex items-center justify-between gap-3 py-2 border-b border-border/50 last:border-0">
                <div>
                  <p className="text-xs text-text font-medium">{s.name}</p>
                  <p className="text-[10px] text-dim">{s.type}</p>
                </div>
                <span className={cls}>{s.risk}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
