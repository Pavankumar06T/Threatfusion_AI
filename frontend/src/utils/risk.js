export const RISK_META = {
  SAFE:        { color: '#22c55e', bg: '#22c55e15', border: '#22c55e40', label: 'SAFE',     icon: '✓' },
  SUSPICIOUS:  { color: '#eab308', bg: '#eab30815', border: '#eab30840', label: 'SUSPICIOUS', icon: '⚠' },
  'HIGH RISK': { color: '#f97316', bg: '#f9731615', border: '#f9731640', label: 'HIGH RISK', icon: '⛔' },
  CRITICAL:    { color: '#ef4444', bg: '#ef444415', border: '#ef444440', label: 'CRITICAL',  icon: '☠' },
}

export function getRiskMeta(classification) {
  return RISK_META[classification] || RISK_META['SUSPICIOUS']
}

export function scoreToColor(score) {
  if (score < 25) return '#22c55e'
  if (score < 50) return '#eab308'
  if (score < 75) return '#f97316'
  return '#ef4444'
}

export function confidencePct(conf) {
  return `${Math.round((conf || 0) * 100)}%`
}

export function formatTs(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}
