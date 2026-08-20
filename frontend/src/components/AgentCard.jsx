import { scoreToColor, confidencePct } from '../utils/risk'
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react'

const AGENT_LABELS = {
  header_metadata:    'Header Agent',
  content_linguistic: 'Content Agent',
  url_threat:         'URL Agent',
  memory_rag:         'Memory Agent',
}

const AGENT_DESC = {
  header_metadata:    'Sender, domain, authentication',
  content_linguistic: 'Social engineering, linguistics',
  url_threat:         'URL reputation, threat intel',
  memory_rag:         'Historical campaign similarity',
}

function FindingIcon({ score }) {
  if (score >= 60) return <XCircle size={13} className="text-critical flex-shrink-0 mt-0.5" />
  if (score >= 30) return <AlertTriangle size={13} className="text-suspicious flex-shrink-0 mt-0.5" />
  return <CheckCircle2 size={13} className="text-safe flex-shrink-0 mt-0.5" />
}

export default function AgentCard({ agentKey, result }) {
  if (!result) return null
  const color  = scoreToColor(result.risk_score)
  const label  = AGENT_LABELS[agentKey] || agentKey
  const desc   = AGENT_DESC[agentKey] || ''
  const findings = result.findings || []

  return (
    <div className="panel p-4 flex flex-col gap-3 animate-slideUp">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-white">{label}</p>
          <p className="text-[11px] text-dim">{desc}</p>
        </div>
        <div className="text-right flex-shrink-0">
          <p className="text-xl font-bold font-mono" style={{ color }}>{result.risk_score}</p>
          <p className="text-[10px] text-dim font-mono">{confidencePct(result.confidence)} conf.</p>
        </div>
      </div>

      {/* Score bar */}
      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${result.risk_score}%`, background: color }}
        />
      </div>

      {/* Findings */}
      {findings.length > 0 ? (
        <ul className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
          {findings.slice(0, 6).map((f, i) => (
            <li key={i} className="flex items-start gap-2">
              <FindingIcon score={result.risk_score} />
              <span className="text-[11px] text-text leading-relaxed">{f}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[11px] text-dim italic">No findings</p>
      )}

      {/* Indicators */}
      {result.indicators?.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1 border-t border-border">
          {result.indicators.slice(0, 4).map((ind, i) => (
            <span key={i} className="text-[10px] font-mono bg-muted border border-border rounded px-1.5 py-0.5 text-dim">
              {ind}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
