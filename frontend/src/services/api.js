import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: `${BASE}/api`,
  timeout: 90_000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Health ───────────────────────────────────────────────────────────────────
export const fetchHealth   = ()           => api.get('/health').then(r => r.data)
export const fetchStats    = ()           => api.get('/stats').then(r => r.data)
export const fetchHistory  = (limit = 50) => api.get('/history', { params: { limit } }).then(r => r.data)
export const clearHistory  = ()           => api.delete('/history').then(r => r.data)
export const fetchAnalysis = (id)         => api.get(`/analysis/${id}`).then(r => r.data)
export const deleteAnalysis = (id)         => api.delete(`/analysis/${id}`).then(r => r.data)
export const fetchMemoryStatus   = ()     => api.get('/memory/status').then(r => r.data)
export const initializeMemory    = ()     => api.post('/memory/initialize').then(r => r.data)
export const fetchDemoEmails     = ()     => api.get('/demo/emails').then(r => r.data)
export const fetchDemoEmail      = (id)   => api.get(`/demo/emails/${id}`).then(r => r.data)

// ── Analyse ──────────────────────────────────────────────────────────────────
export const analyzeEmail = (emailObj) =>
  api.post('/analyze', { email: emailObj }).then(r => r.data)

export const analyzeFile = (file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/analyze/file', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(r => r.data)
}

export default api
