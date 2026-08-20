import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer,
         PieChart, Pie, Cell, Tooltip } from 'recharts'
import { AlertTriangle, Shield, Eye, CheckCircle2, ChevronRight, Mail } from 'lucide-react'
import { fetchStats, fetchHistory } from '../services/api'
import { getRiskMeta, formatTs } from '../utils/risk'

const RISK_COLORS = {
  CRITICAL: '#ef4444',
  'HIGH RISK': '#f97316',
  SUSPICIOUS: '#eab308',
  SAFE: '#22c55e',
}

function StatCard({ label, value, icon: Icon, color }) {
  return (
    <div className="panel p-4 flex items-center gap-4">
      <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
           style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
        <Icon size={18} style={{ color }} />
      </div>
      <div>
        <p className="text-2xl font-bold font-mono text-white">{value ?? '—'}</p>
        <p className="text-xs text-dim">{label}</p>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats,   setStats]   = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([fetchStats(), fetchHistory(10)])
      .then(([s, h]) => { setStats(s); setHistory(h) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const pieData = stats ? [
    { name: 'Critical',    value: stats.critical_count,    color: '#ef4444' },
    { name: 'High Risk',   value: stats.high_risk_count,   color: '#f97316' },
    { name: 'Suspicious',  value: stats.suspicious_count,  color: '#eab308' },
    { name: 'Safe',        value: stats.safe_count,        color: '#22c55e' },
  ].filter(d => d.value > 0) : []

  return (
    <div className="p-6 space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-dim mt-0.5">ThreatFusion AI · Phishing Intelligence Overview</p>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <StatCard label="Total Analysed"   value={stats?.total_analyzed}    icon={Mail}          color="#00d4ff" />
        <StatCard label="Critical Threats"  value={stats?.critical_count}    icon={AlertTriangle} color="#ef4444" />
        <StatCard label="High Risk"         value={stats?.high_risk_count}   icon={Eye}           color="#f97316" />
        <StatCard label="Safe Emails"       value={stats?.safe_count}        icon={CheckCircle2}  color="#22c55e" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Pie chart */}
        <div className="panel p-4 xl:col-span-1">
          <p className="text-sm font-semibold text-white mb-4">Risk Distribution</p>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                       dataKey="value" stroke="none">
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#151820', border: '1px solid #1e2230', borderRadius: 6, fontSize: 12 }}
                           labelStyle={{ color: '#c8cdd8' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-x-4 gap-y-1 justify-center mt-2">
                {pieData.map((d, i) => (
                  <span key={i} className="flex items-center gap-1.5 text-[11px] text-dim">
                    <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                    {d.name} ({d.value})
                  </span>
                ))}
              </div>
            </>
          ) : (
            <div className="h-[180px] flex items-center justify-center text-dim text-sm">
              No analyses yet
            </div>
          )}
        </div>

        {/* Recent history */}
        <div className="panel p-4 xl:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm font-semibold text-white">Recent Analyses</p>
            <Link to="/history" className="text-xs text-accent hover:underline flex items-center gap-1">
              View all <ChevronRight size={12} />
            </Link>
          </div>
          {loading ? (
            <p className="text-dim text-sm">Loading…</p>
          ) : history.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 gap-3">
              <Shield size={32} className="text-dim" />
              <p className="text-sm text-dim">No analyses yet</p>
              <Link to="/analyze" className="btn-primary text-xs">Analyse First Email</Link>
            </div>
          ) : (
            <div className="space-y-1">
              {history.map(item => {
                const meta = getRiskMeta(item.classification)
                return (
                  <Link key={item.id} to={`/history`}
                        className="flex items-center gap-3 py-2.5 px-3 rounded-md hover:bg-muted transition-colors group">
                    <div className="w-2 h-2 rounded-full flex-shrink-0"
                         style={{ background: meta.color }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-text font-medium truncate">
                        {item.email_subject || '(no subject)'}
                      </p>
                      <p className="text-[10px] text-dim">{item.email_from || '—'}</p>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-xs font-mono font-bold" style={{ color: meta.color }}>
                        {item.risk_score}
                      </p>
                      <p className="text-[10px] text-dim">{formatTs(item.timestamp)}</p>
                    </div>
                  </Link>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Quick actions */}
      <div className="panel p-4">
        <p className="text-sm font-semibold text-white mb-3">Quick Actions</p>
        <div className="flex flex-wrap gap-3">
          <Link to="/analyze" className="btn-primary flex items-center gap-2">
            <Mail size={14} /> Analyse Email
          </Link>
          <Link to="/memory" className="btn-ghost flex items-center gap-2">
            <Shield size={14} /> Threat Memory
          </Link>
          <Link to="/status" className="btn-ghost flex items-center gap-2">
            <Eye size={14} /> System Status
          </Link>
        </div>
      </div>
    </div>
  )
}
