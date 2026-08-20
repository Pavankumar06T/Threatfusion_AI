import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar     from './components/Sidebar'
import Dashboard   from './pages/Dashboard'
import AnalyzeEmail from './pages/AnalyzeEmail'
import History     from './pages/History'
import ThreatMemory from './pages/ThreatMemory'
import SystemStatus from './pages/SystemStatus'
import About       from './pages/About'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-void">
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/"        element={<Dashboard />} />
            <Route path="/analyze" element={<AnalyzeEmail />} />
            <Route path="/history" element={<History />} />
            <Route path="/memory"  element={<ThreatMemory />} />
            <Route path="/status"  element={<SystemStatus />} />
            <Route path="/about"   element={<About />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
