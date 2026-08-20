import { useState, useCallback } from 'react'
import { analyzeEmail, analyzeFile } from '../services/api'

export function useAnalysis() {
  const [result,   setResult]   = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)

  const analyze = useCallback(async (emailObj) => {
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeEmail(emailObj)
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }, [])

  const analyzeEml = useCallback(async (file) => {
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeFile(file)
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'File analysis failed')
    } finally {
      setLoading(false)
    }
  }, [])

  const clear = useCallback(() => {
    setResult(null); setError(null)
  }, [])

  return { result, loading, error, analyze, analyzeEml, clear }
}
