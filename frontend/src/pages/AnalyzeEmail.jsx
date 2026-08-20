import { useState, useRef } from 'react'
import { Send, Upload, Zap, X, ChevronDown, ChevronUp } from 'lucide-react'
import { useAnalysis } from '../hooks/useAnalysis'
import { fetchDemoEmail } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import AnalysisResult from '../components/AnalysisResult'

const DEMO_SCENARIOS = [
  { id: 'demo_paypal_phishing',   label: 'PayPal Phishing',        badge: 'CRITICAL'  },
  { id: 'demo_microsoft_phishing',label: 'Microsoft Credential',    badge: 'HIGH RISK' },
  { id: 'demo_invoice_fraud',     label: 'Invoice Fraud / BEC',     badge: 'HIGH RISK' },
  { id: 'demo_campaign_match',    label: 'Apple Campaign Match',    badge: 'CRITICAL'  },
  { id: 'demo_legitimate',        label: 'University Newsletter',   badge: 'SAFE'      },
  { id: 'demo_prompt_injection',  label: 'Prompt Injection Attack', badge: 'HIGH RISK' },
]

const BADGE_CLS = {
  CRITICAL:  'badge-critical',
  'HIGH RISK': 'badge-high',
  SUSPICIOUS:'badge-suspicious',
  SAFE:      'badge-safe',
}

const EMPTY_FORM = { from: '', to: '', reply_to: '', subject: '', body: '' }

export default function AnalyzeEmail() {
  const { result, loading, error, analyze, analyzeEml, clear } = useAnalysis()
  const [form, setForm]         = useState(EMPTY_FORM)
  const [showDemos, setShowDemos] = useState(false)
  const [loadingDemo, setLoadingDemo] = useState(false)
  const fileRef = useRef()

  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const handleSubmit = () => {
    if (!form.from && !form.subject && !form.body) return
    analyze(form)
  }

  const handleFile = async e => {
    const file = e.target.files?.[0]
    if (!file) return
    analyzeEml(file)
    e.target.value = ''
  }

  const handleDemo = async (id) => {
    setLoadingDemo(true)
    try {
      const scenario = await fetchDemoEmail(id)
      const email = scenario.email
      setForm({
        from:     email.from || '',
        to:       email.to || '',
        reply_to: email.reply_to || '',
        subject:  email.subject || '',
        body:     email.body || '',
      })
      setShowDemos(false)
    } catch (e) {
      console.error(e)
    } finally {
      setLoadingDemo(false)
    }
  }

  const handleClear = () => {
    setForm(EMPTY_FORM)
    clear()
  }

  if (result) return (
    <div className="p-6">
      <AnalysisResult result={result} onReset={handleClear} />
    </div>
  )

  if (loading) return (
    <div className="p-6">
      <LoadingSpinner message="Running multi-agent analysis…" />
    </div>
  )

  return (
    <div className="p-6 max-w-3xl space-y-5 animate-fadeIn">
      <div>
        <h1 className="text-xl font-bold text-white">Analyse Email</h1>
        <p className="text-sm text-dim mt-0.5">Paste email headers and body, or upload an .eml file</p>
      </div>

      {error && (
        <div className="panel p-3 border-l-2 border-critical text-critical text-sm flex items-start gap-2">
          <X size={14} className="mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Demo dropdown */}
      <div className="panel p-3">
        <button
          onClick={() => setShowDemos(s => !s)}
          className="w-full flex items-center justify-between text-sm text-text hover:text-accent transition-colors"
        >
          <div className="flex items-center gap-2">
            <Zap size={14} className="text-accent" />
            <span className="font-medium">Load Demo Scenario</span>
          </div>
          {showDemos ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showDemos && (
          <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
            {DEMO_SCENARIOS.map(d => (
              <button
                key={d.id}
                onClick={() => handleDemo(d.id)}
                disabled={loadingDemo}
                className="flex items-center justify-between gap-2 px-3 py-2.5 bg-surface border border-border rounded-md hover:border-accent/40 hover:bg-muted transition-all text-left group"
              >
                <span className="text-xs text-text group-hover:text-white transition-colors">{d.label}</span>
                <span className={BADGE_CLS[d.badge] || 'badge-suspicious'}>{d.badge}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Form */}
      <div className="panel p-5 space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-mono text-dim mb-1.5 block">FROM</label>
            <input name="from" value={form.from} onChange={handleChange}
                   placeholder='"Display Name" <sender@domain.com>'
                   className="input-field" />
          </div>
          <div>
            <label className="text-xs font-mono text-dim mb-1.5 block">TO</label>
            <input name="to" value={form.to} onChange={handleChange}
                   placeholder="recipient@example.com"
                   className="input-field" />
          </div>
          <div>
            <label className="text-xs font-mono text-dim mb-1.5 block">REPLY-TO</label>
            <input name="reply_to" value={form.reply_to} onChange={handleChange}
                   placeholder="reply@domain.com"
                   className="input-field" />
          </div>
          <div>
            <label className="text-xs font-mono text-dim mb-1.5 block">SUBJECT</label>
            <input name="subject" value={form.subject} onChange={handleChange}
                   placeholder="Email subject line"
                   className="input-field" />
          </div>
        </div>

        <div>
          <label className="text-xs font-mono text-dim mb-1.5 block">BODY</label>
          <textarea
            name="body" value={form.body} onChange={handleChange}
            rows={12}
            placeholder="Paste the full email body here…"
            className="input-field resize-y min-h-[200px]"
          />
        </div>

        {/* Action row */}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button onClick={handleSubmit} className="btn-primary flex items-center gap-2">
            <Send size={14} /> Analyse Email
          </button>

          <button onClick={() => fileRef.current?.click()} className="btn-ghost flex items-center gap-2">
            <Upload size={14} /> Upload .eml
          </button>
          <input ref={fileRef} type="file" accept=".eml" onChange={handleFile} className="hidden" />

          {(form.from || form.body) && (
            <button onClick={handleClear} className="btn-danger flex items-center gap-2">
              <X size={14} /> Clear
            </button>
          )}

          <span className="ml-auto text-[11px] font-mono text-dim">
            {form.body.length.toLocaleString()} chars
          </span>
        </div>
      </div>

      {/* Tip */}
      <p className="text-[11px] text-dim leading-relaxed">
        💡 All email content is treated as untrusted data. Prompt injection defences are active.
        API keys are never exposed to the frontend.
      </p>
    </div>
  )
}
