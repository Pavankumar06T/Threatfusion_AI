import { Shield, Brain, Database, Link2, Cpu, Lock } from 'lucide-react'

const AGENTS = [
  {
    icon: Shield, label: 'Header / Metadata Agent',
    color: '#00d4ff',
    desc: 'Deterministic analysis of email headers. Detects display-name spoofing, reply-to hijacking, domain typosquatting, SPF/DKIM/DMARC failures. No LLM dependency — fully rules-based.',
  },
  {
    icon: Brain, label: 'Content / Linguistic Agent',
    color: '#a78bfa',
    desc: 'Google Gemini analyses the email body for social engineering tactics: urgency, fear, credential harvesting, authority impersonation, BEC indicators. Falls back to regex heuristics without API key. Prompt injection defended.',
  },
  {
    icon: Link2, label: 'URL / Threat Intelligence Agent',
    color: '#f97316',
    desc: 'Extracts all URLs from plain text, HTML, and anchor tags. Detects typosquatting, suspicious TLDs, IP-based URLs, URL shorteners, encoded characters. Integrates VirusTotal with graceful fallback.',
  },
  {
    icon: Database, label: 'Memory / RAG Agent',
    color: '#22c55e',
    desc: 'ChromaDB vector similarity search over 15 curated historical phishing campaigns. Uses all-MiniLM-L6-v2 embeddings locally. High similarity to known campaigns boosts risk score with campaign attribution.',
  },
  {
    icon: Cpu, label: 'Fusion Agent',
    color: '#eab308',
    desc: 'Transparent weighted scoring: Header 25%, Content 25%, URL 30%, Memory 20%. Applies deterministic adjustments for confirmed malicious URLs, campaign matches, and corroborating signals. No black-box LLM decision.',
  },
]

const STACK = [
  ['Backend',         'Python 3.11, FastAPI, Pydantic, SQLAlchemy, SQLite'],
  ['AI / LLM',        'Google Gemini 1.5 Flash via LangChain'],
  ['Vector Memory',   'ChromaDB, sentence-transformers (all-MiniLM-L6-v2)'],
  ['Threat Intel',    'VirusTotal API v3 (optional, graceful fallback)'],
  ['Orchestration',   'Concurrent asyncio + ThreadPoolExecutor'],
  ['Frontend',        'React 18, Vite, Tailwind CSS, Recharts'],
  ['Testing',         'pytest, pytest-asyncio, httpx'],
  ['Deployment',      'Docker Compose / local Python + Node'],
]

export default function About() {
  return (
    <div className="p-6 space-y-6 animate-fadeIn max-w-4xl">
      {/* Hero */}
      <div className="panel-glow p-6 text-center space-y-2">
        <div className="flex justify-center mb-3">
          <div className="w-14 h-14 rounded-xl bg-accent/10 border border-accent/30 flex items-center justify-center">
            <Shield size={28} className="text-accent" />
          </div>
        </div>
        <h1 className="text-2xl font-bold text-white">ThreatFusion AI</h1>
        <p className="text-dim text-sm">Multi-Agent System for Explainable Phishing &amp; Social Engineering Detection</p>
        <div className="flex justify-center flex-wrap gap-2 pt-2">
          {['Explainable AI', 'Multi-Agent', 'RAG', 'Threat Intelligence', 'FastAPI + React'].map(t => (
            <span key={t} className="text-[10px] font-mono bg-muted border border-border rounded px-2 py-0.5 text-dim">{t}</span>
          ))}
        </div>
      </div>

      {/* Agents */}
      <div>
        <p className="text-xs font-mono text-dim uppercase tracking-widest mb-3">The Four Analysis Agents</p>
        <div className="space-y-3">
          {AGENTS.map(({ icon: Icon, label, color, desc }) => (
            <div key={label} className="panel p-4 flex items-start gap-4">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                   style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
                <Icon size={16} style={{ color }} />
              </div>
              <div>
                <p className="text-sm font-semibold text-white mb-1">{label}</p>
                <p className="text-xs text-dim leading-relaxed">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tech stack */}
      <div className="panel p-5">
        <p className="text-xs font-mono text-dim uppercase tracking-widest mb-4">Technology Stack</p>
        <div className="space-y-2">
          {STACK.map(([area, tech]) => (
            <div key={area} className="flex gap-4 py-2 border-b border-border/50 last:border-0">
              <span className="text-xs font-mono text-dim w-32 flex-shrink-0">{area}</span>
              <span className="text-xs text-text">{tech}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Security note */}
      <div className="panel p-4 border-l-2 border-accent/40">
        <div className="flex items-center gap-2 mb-2">
          <Lock size={13} className="text-accent" />
          <p className="text-xs font-mono text-accent uppercase tracking-wider">Security Design</p>
        </div>
        <ul className="text-xs text-dim space-y-1 leading-relaxed">
          <li>· All email content treated as untrusted hostile input</li>
          <li>· Prompt injection defence active in Content Agent</li>
          <li>· API keys never exposed to the frontend</li>
          <li>· File size limits and input validation on all endpoints</li>
          <li>· Graceful degradation when external services are unavailable</li>
          <li>· No arbitrary command execution from email content</li>
          <li>· Displayed HTML sanitised before rendering</li>
        </ul>
      </div>
    </div>
  )
}
