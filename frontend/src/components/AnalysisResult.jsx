import { AlertTriangle, CheckCircle2, Link2, Brain, RotateCcw } from 'lucide-react'
import RiskGauge from './RiskGauge'
import AgentCard from './AgentCard'
import EvidenceTimeline from './EvidenceTimeline'
import { getRiskMeta, confidencePct } from '../utils/risk'

export default function AnalysisResult({ result, onReset }) {
  if (!result) return null
  const { fusion_result: fr, header_result, content_result, url_result, memory_result } = result

  const meta = getRiskMeta(fr.classification)

  return (
    <div className="space-y-5 animate-slideUp">

      {/* ── Top verdict bar ── */}
      <div
        className="panel-glow p-6 rounded-lg border"
        style={{ borderColor: meta.border, background: `${meta.bg}` }}
      >
        <div className="flex flex-col lg:flex-row items-center lg:items-start gap-6">
          {/* Gauge */}
          <div className="flex-shrink-0">
            <RiskGauge score={fr.risk_score} classification={fr.classification} size={150} />
          </div>

          {/* Verdict text */}
          <div className="flex-1 space-y-3">
            <div>
              <p className="text-xs font-mono text-dim uppercase tracking-widest mb-1">Final Verdict</p>
              <h2 className="text-2xl font-bold text-white">{fr.summary}</h2>
            </div>

            <div className="flex flex-wrap gap-4 text-sm">
              <div>
                <span className="text-dim">Confidence</span>
                <span className="ml-2 font-mono font-semibold text-white">{confidencePct(fr.confidence)}</span>
              </div>
              <div>
                <span className="text-dim">Processing</span>
                <span className="ml-2 font-mono font-semibold text-white">{result.processing_time_ms}ms</span>
              </div>
              {result.fallback_mode && (
                <div className="flex items-center gap-1.5 text-suspicious">
                  <AlertTriangle size={13} />
                  <span className="text-xs">Fallback mode — external services unavailable</span>
                </div>
              )}
            </div>

            {/* Recommended action */}
            <div className="p-3 bg-void/60 border border-border rounded-md">
              <p className="text-xs font-mono text-dim uppercase tracking-wider mb-1">Recommended Action</p>
              <p className="text-sm text-text">{fr.recommended_action}</p>
            </div>
          </div>

          {/* Reset */}
          <button onClick={onReset} className="btn-ghost flex items-center gap-2 self-start">
            <RotateCcw size={14} /> New Analysis
          </button>
        </div>
      </div>

      {/* ── Key reasons ── */}
      {fr.key_reasons?.length > 0 && (
        <div className="panel p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={14} className="text-accent" />
            <h3 className="text-sm font-semibold text-white">Why was this flagged?</h3>
          </div>
          <ol className="space-y-2">
            {fr.key_reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="font-mono text-xs text-accent flex-shrink-0 w-5 text-right">{i + 1}.</span>
                <span className="text-sm text-text">{r}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* ── Explanation ── */}
      {fr.explanation && (
        <div className="panel p-4 border-l-2 border-accent/40">
          <p className="text-xs font-mono text-dim uppercase tracking-wider mb-2">Plain-English Explanation</p>
          <p className="text-sm text-text leading-relaxed">{fr.explanation}</p>
        </div>
      )}

      {/* ── Agent breakdown ── */}
      <div>
        <p className="text-xs font-mono text-dim uppercase tracking-widest mb-3 flex items-center gap-2">
          <Brain size={12} className="text-accent" /> Agent Breakdown
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <AgentCard agentKey="header_metadata"    result={header_result} />
          <AgentCard agentKey="content_linguistic" result={content_result} />
          <AgentCard agentKey="url_threat"         result={url_result} />
          <AgentCard agentKey="memory_rag"         result={memory_result} />
        </div>
      </div>

      {/* ── Scoring breakdown ── */}
      {fr.agent_breakdown && (
        <div className="panel p-4">
          <p className="text-xs font-mono text-dim uppercase tracking-widest mb-4">Scoring Breakdown</p>
          <div className="space-y-2">
            {['header', 'content', 'url', 'memory'].map(k => {
              const ab = fr.agent_breakdown[k]
              if (!ab) return null
              return (
                <div key={k} className="flex items-center gap-3">
                  <span className="text-xs font-mono text-dim w-16 capitalize">{k}</span>
                  <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full bg-accent/60 transition-all duration-700"
                      style={{ width: `${ab.score}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-text w-10 text-right">{ab.score}/100</span>
                  <span className="text-[10px] font-mono text-dim w-16 text-right">×{ab.weight} → {ab.weighted_contribution}</span>
                </div>
              )
            })}
          </div>
          {fr.agent_breakdown.adjustments?.length > 0 && (
            <div className="mt-3 pt-3 border-t border-border">
              <p className="text-[10px] font-mono text-dim mb-1">Adjustments</p>
              {fr.agent_breakdown.adjustments.map((adj, i) => (
                <p key={i} className="text-[11px] font-mono text-text">{adj}</p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── URLs ── */}
      {url_result?.urls_found?.length > 0 && (
        <div className="panel p-4">
          <div className="flex items-center gap-2 mb-3">
            <Link2 size={14} className="text-accent" />
            <h3 className="text-sm font-semibold text-white">URLs Found ({url_result.urls_found.length})</h3>
          </div>
          <div className="space-y-1.5">
            {url_result.urls_found.slice(0, 10).map((url, i) => {
              const mal = url_result.malicious_urls?.find(u => u.url === url)
              const sus = url_result.suspicious_urls?.find(u => u.url === url)
              const status = mal ? 'malicious' : sus ? 'suspicious' : 'ok'
              return (
                <div key={i} className="flex items-center gap-2 py-1 border-b border-border/50 last:border-0">
                  {status === 'malicious' && <span className="w-2 h-2 rounded-full bg-critical flex-shrink-0" />}
                  {status === 'suspicious' && <span className="w-2 h-2 rounded-full bg-suspicious flex-shrink-0" />}
                  {status === 'ok' && <span className="w-2 h-2 rounded-full bg-safe flex-shrink-0" />}
                  <span className="font-mono text-[11px] text-text break-all">{url}</span>
                  {mal && <span className="badge-critical ml-auto flex-shrink-0">MALICIOUS</span>}
                  {sus && !mal && <span className="badge-suspicious ml-auto flex-shrink-0">SUSPICIOUS</span>}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── Memory matches ── */}
      {memory_result?.similar_emails?.length > 0 && (
        <div className="panel p-4">
          <p className="text-xs font-mono text-dim uppercase tracking-widest mb-3">Similar Known Campaigns</p>
          <div className="space-y-2">
            {memory_result.similar_emails.slice(0, 3).map((em, i) => (
              <div key={i} className="flex items-center gap-3 py-2 border-b border-border/50 last:border-0">
                <div className="w-10 text-right">
                  <span className="text-xs font-mono font-bold" style={{
                    color: em.similarity >= 0.8 ? '#ef4444' : em.similarity >= 0.6 ? '#f97316' : '#eab308'
                  }}>{Math.round(em.similarity * 100)}%</span>
                </div>
                <div className="flex-1">
                  <p className="text-xs text-white font-medium">{em.campaign}</p>
                  <p className="text-[11px] text-dim">{em.attack_type} · {em.risk_level}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Evidence timeline ── */}
      <EvidenceTimeline events={fr.evidence || []} />

      {/* ── Fallback notice ── */}
      {result.fallback_reasons?.length > 0 && (
        <div className="panel p-3 border-l-2 border-suspicious/50">
          <p className="text-xs font-mono text-suspicious mb-1">External Intelligence Unavailable — Local Analysis Used</p>
          {result.fallback_reasons.map((r, i) => (
            <p key={i} className="text-[11px] text-dim">· {r}</p>
          ))}
        </div>
      )}
    </div>
  )
}
