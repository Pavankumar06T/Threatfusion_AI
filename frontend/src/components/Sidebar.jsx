import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Mail, History, Database,
  Activity, Info, Shield,
} from 'lucide-react'

const NAV = [
  { to: '/',        icon: LayoutDashboard, label: 'Dashboard'     },
  { to: '/analyze', icon: Mail,            label: 'Analyze Email' },
  { to: '/history', icon: History,         label: 'History'       },
  { to: '/memory',  icon: Database,        label: 'Threat Memory' },
  { to: '/status',  icon: Activity,        label: 'System Status' },
  { to: '/about',   icon: Info,            label: 'About'         },
]

export default function Sidebar() {
  return (
    <aside className="w-56 flex-shrink-0 flex flex-col bg-panel border-r border-border h-screen sticky top-0">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-md bg-accent/10 border border-accent/30 flex items-center justify-center">
            <Shield size={16} className="text-accent" />
          </div>
          <div>
            <p className="text-sm font-semibold text-white leading-none">ThreatFusion</p>
            <p className="text-[10px] text-dim leading-none mt-0.5 font-mono">AI · v1.0</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm transition-all duration-150 ${
                isActive
                  ? 'bg-accent/10 text-accent border border-accent/20'
                  : 'text-dim hover:text-text hover:bg-muted'
              }`
            }
          >
            <Icon size={15} />
            <span className="font-medium">{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-border">
        <p className="text-[10px] text-dim font-mono leading-relaxed">
          Multi-Agent Phishing<br />Detection System
        </p>
      </div>
    </aside>
  )
}
