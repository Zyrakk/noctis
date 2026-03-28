import { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '../context/AuthContext.jsx'

export function useApi(url, options = {}) {
  const { apiKey, logout } = useAuth()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const abortRef = useRef(null)

  const fetchData = useCallback(async () => {
    if (!apiKey) return
    if (!url) { setLoading(false); return }

    if (abortRef.current) abortRef.current.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setLoading(true)
    setError(null)

    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { 'X-API-Key': apiKey },
        ...options,
      })

      if (res.status === 401) {
        logout()
        return
      }

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `HTTP ${res.status}`)
      }

      const json = await res.json()
      setData(json)
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err.message)
      }
    } finally {
      setLoading(false)
    }
  }, [url, apiKey])

  useEffect(() => {
    fetchData()
    return () => { if (abortRef.current) abortRef.current.abort() }
  }, [fetchData])

  return { data, loading, error, refetch: fetchData }
}

export async function apiFetch(apiKey, url, options = {}) {
  const { headers: extraHeaders, ...restOptions } = options
  const res = await fetch(url, {
    ...restOptions,
    headers: {
      'X-API-Key': apiKey,
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `HTTP ${res.status}`)
  }

  return res.json()
}
