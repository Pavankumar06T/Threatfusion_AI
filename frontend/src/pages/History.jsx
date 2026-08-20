import { useEffect, useState } from 'react'
import { fetchHistory, fetchAnalysis, clearHistory, deleteAnalysis } from '../services/api'
import { getRiskMeta, formatTs, confidencePct } from '../utils/risk'
import { ChevronRight, X, Trash2 } from 'lucide-react'
import AnalysisResult from '../components/AnalysisResult'

export default function History() {
  const [history,  setHistory]  = useState([])
  const [selected, setSelected] = useState(null)
  const [detail,   setDetail]   = useState(null)
  const [loading,  setLoading]  = useState(true)

  const loadHistory = () => {
    setLoading(true)
    fetchHistory(100)
      .then(setHistory)
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadHistory()
  }, [])

  const handleClearAll = async () => {
    if (!window.confirm('Are you sure you want to clear all analysis history?')) return
    try {
      await clearHistory()
      setHistory([])
      setDetail(null)
      setSelected(null)
    } catch (err) {
      console.error('Failed to clear history:', err)
      alert('Failed to clear history')
    }
  }

  const handleDeleteItem = async (e, id) => {
    e.stopPropagation()
    if (!window.confirm('Delete this record?')) return
    try {
      await deleteAnalysis(id)
      setHistory(prev => prev.filter(item => item.id !== id))
      if (selected === id) {
        setDetail(null)
        setSelected(null)
      }
    } catch (err) {
      console.error('Failed to delete item:', err)
      alert('Failed to delete record')
    }
  }

  const loadDetail = async (id) => {
    if (selected === id) { setSelected(null); setDetail(null); return }
    setSelected(id)
    try {
      const d = await fetchAnalysis(id)
      setDetail(d)
    } catch { setDetail(null) }
  }

  if (detail) return (
    <div className="p-6 animate-fadeIn">
      <button onClick={() => { setDetail(null); setSelected(null) }}
              className="btn-ghost flex items-center gap-2 mb-5">
        <X size={13} /> Back to History
      </button>
      <AnalysisResult result={detail} onReset={() => { setDetail(null); setSelected(null) }} />
    </div>
  )

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Analysis History</h1>
          <p className="text-sm text-dim mt-0.5">{history.length} analyses stored</p>
        </div>
        {history.length > 0 && (
          <button
            onClick={handleClearAll}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-rose-400 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 rounded-md transition-colors"
          >
            <Trash2 size={14} /> Clear All History
          </button>
        )}
      </div>

      <div className="panel overflow-hidden">
        {loading ? (
          <p className="p-6 text-dim text-sm">Loading…</p>
        ) : history.length === 0 ? (
          <p className="p-6 text-dim text-sm">No analyses yet. <a href="/analyze" className="text-accent hover:underline">Analyse an email.</a></p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                {['Time', 'From', 'Subject', 'Score', 'Risk', 'Confidence', 'Actions'].map((h, i) => (
                  <th key={i} className="px-4 py-3 text-left text-[11px] font-mono text-dim uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.map(item => {
                const meta = getRiskMeta(item.classification)
                return (
                  <tr key={item.id}
                      onClick={() => loadDetail(item.id)}
                      className="border-b border-border/50 hover:bg-muted cursor-pointer transition-colors group">
                    <td className="px-4 py-3 font-mono text-[11px] text-dim whitespace-nowrap">
                      {formatTs(item.timestamp)}
                    </td>
                    <td className="px-4 py-3 text-xs text-text max-w-[140px] truncate">{item.email_from || '—'}</td>
                    <td className="px-4 py-3 text-xs text-text max-w-[200px] truncate">{item.email_subject || '(no subject)'}</td>
                    <td className="px-4 py-3 font-mono font-bold text-sm" style={{ color: meta.color }}>
                      {item.risk_score}
                    </td>
                    <td className="px-4 py-3">
                      <span style={{ color: meta.color, background: meta.bg, borderColor: meta.border }}
                            className="border rounded px-1.5 py-0.5 text-[10px] font-mono font-bold">
                        {item.classification}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-dim">{confidencePct(item.confidence)}</td>
                    <td className="px-4 py-3 flex items-center gap-2">
                      <button
                        onClick={(e) => handleDeleteItem(e, item.id)}
                        title="Delete this record"
                        className="p-1 text-dim hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                      >
                        <Trash2 size={14} />
                      </button>
                      <ChevronRight size={14} className="text-dim group-hover:text-accent transition-colors" />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

