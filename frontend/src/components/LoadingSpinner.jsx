export default function LoadingSpinner({ message = 'Analysing…' }) {
  return (
    <div className="flex flex-col items-center justify-center gap-6 py-20 animate-fadeIn">
      {/* Spinning rings */}
      <div className="relative w-20 h-20">
        <div className="absolute inset-0 rounded-full border-2 border-accent/20" />
        <div className="absolute inset-0 rounded-full border-t-2 border-accent animate-spin" />
        <div className="absolute inset-2 rounded-full border-2 border-accent/10" />
        <div className="absolute inset-2 rounded-full border-b-2 border-accent/60 animate-spin"
             style={{ animationDuration: '1.5s', animationDirection: 'reverse' }} />
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-3 h-3 rounded-full bg-accent animate-pulse" />
        </div>
      </div>
      <div className="text-center">
        <p className="text-accent font-mono text-sm font-semibold tracking-wider">{message}</p>
        <p className="text-dim text-xs mt-1">Running 4 agents concurrently</p>
      </div>
      {/* Fake progress steps */}
      <div className="flex flex-col gap-1.5 w-64">
        {['Header analysis', 'Content analysis', 'URL threat check', 'Memory similarity'].map((step, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-accent/60 animate-pulse"
                 style={{ animationDelay: `${i * 0.3}s` }} />
            <span className="text-[11px] text-dim font-mono">{step}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
