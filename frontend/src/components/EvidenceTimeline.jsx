import { Clock } from 'lucide-react'

export default function EvidenceTimeline({ events = [] }) {
  if (!events.length) return null
  return (
    <div className="panel p-4">
      <div className="flex items-center gap-2 mb-4">
        <Clock size={14} className="text-accent" />
        <h3 className="text-sm font-semibold text-white">Evidence Timeline</h3>
      </div>
      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-[7px] top-0 bottom-0 w-px bg-border" />
        <ul className="space-y-3 pl-5">
          {events.map((ev, i) => (
            <li key={i} className="relative flex items-start gap-3">
              {/* Dot */}
              <div className="absolute -left-5 top-1.5 w-2 h-2 rounded-full bg-accent/60 border border-accent/30" />
              <span className="text-[10px] font-mono text-accent flex-shrink-0 pt-0.5 w-16">{ev.timestamp}</span>
              <div>
                <p className="text-xs text-text font-medium">{ev.event}</p>
                {ev.detail && <p className="text-[11px] text-dim">{ev.detail}</p>}
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
