import React, { createContext, useContext, useState, useCallback } from 'react'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [apiKey, setApiKey] = useState(() => sessionStorage.getItem('noctis_key') || '')
  const [error, setError] = useState('')

  const isAuthenticated = apiKey !== ''

  const login = useCallback(async (key) => {
    setError('')
    try {
      const res = await fetch('/api/auth/check', {
        method: 'POST',
        headers: { 'X-API-Key': key },
      })
      if (!res.ok) {
        setError('Invalid API key')
        return false
      }
      setApiKey(key)
      sessionStorage.setItem('noctis_key', key)
      return true
    } catch {
      setError('Connection failed')
      return false
    }
  }, [])

  const logout = useCallback(() => {
    setApiKey('')
    sessionStorage.removeItem('noctis_key')
  }, [])

  return React.createElement(AuthContext.Provider, {
    value: { apiKey, isAuthenticated, login, logout, error }
  }, children)
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be inside AuthProvider')
  return ctx
}
