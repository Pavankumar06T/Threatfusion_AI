import { scoreToColor, getRiskMeta } from '../utils/risk'

export default function RiskGauge({ score = 0, classification = 'SAFE', size = 160 }) {
  const meta   = getRiskMeta(classification)
  const radius = 56
  const circ   = 2 * Math.PI * radius
  const pct    = Math.min(Math.max(score, 0), 100) / 100
  const stroke = circ * pct
  const color  = scoreToColor(score)

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox="0 0 128 128" className="-rotate-90">
          {/* Track */}
          <circle
            cx="64" cy="64" r={radius}
            fill="none" stroke="#1e2230" strokeWidth="10"
          />
          {/* Progress */}
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${stroke} ${circ}`}
            style={{ transition: 'stroke-dasharray 0.8s cubic-bezier(.4,0,.2,1), stroke 0.5s' }}
          />
        </svg>
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold font-mono" style={{ color }}>{score}</span>
          <span className="text-[10px] text-dim font-mono">/100</span>
        </div>
      </div>

      {/* Badge */}
      <div
        className="px-4 py-1.5 rounded-md border font-mono font-bold text-sm tracking-widest"
        style={{ color: meta.color, background: meta.bg, borderColor: meta.border }}
      >
        {meta.icon} {meta.label}
      </div>
    </div>
  )
}
