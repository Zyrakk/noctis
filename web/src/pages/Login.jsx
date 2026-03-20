import React, { useState } from 'react'
import { Activity, Key, ArrowRight, AlertCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'

export default function Login({ navigate }) {
  const { login, error: authError } = useAuth()
  const [key, setKey] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!key.trim()) return
    setLoading(true)
    const ok = await login(key.trim())
    setLoading(false)
    if (ok) navigate('/dashboard')
  }

  return React.createElement('div', {
    className: 'min-h-screen bg-noctis-bg grid-bg flex items-center justify-center px-6'
  },
    React.createElement('div', { className: 'w-full max-w-sm' },
      // Logo
      React.createElement('div', { className: 'text-center mb-8' },
        React.createElement('div', {
          className: 'inline-flex items-center justify-center w-14 h-14 bg-noctis-purple/10 border border-noctis-purple/30 rounded-2xl mb-4'
        },
          React.createElement(Activity, { className: 'w-7 h-7 text-noctis-purple-light' }),
        ),
        React.createElement('h1', {
          className: 'font-heading font-bold text-2xl tracking-tight text-noctis-text'
        }, 'NOCTIS'),
        React.createElement('p', {
          className: 'text-sm text-noctis-muted mt-1'
        }, 'Threat Intelligence Dashboard'),
      ),

      // Card
      React.createElement('form', {
        onSubmit: handleSubmit,
        className: 'bg-noctis-surface border border-noctis-border rounded-xl p-6'
      },
        React.createElement('label', {
          htmlFor: 'apikey',
          className: 'block text-sm font-medium text-noctis-muted mb-2'
        }, 'API Key'),

        React.createElement('div', { className: 'relative' },
          React.createElement(Key, {
            className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim'
          }),
          React.createElement('input', {
            id: 'apikey',
            type: 'password',
            value: key,
            onChange: (e) => setKey(e.target.value),
            placeholder: 'Enter your API key',
            autoFocus: true,
            className: 'w-full pl-10 pr-4 py-3 bg-noctis-bg border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple focus:ring-1 focus:ring-noctis-purple/50 transition-colors duration-200 font-mono'
          }),
        ),

        // Error
        authError && React.createElement('div', {
          className: 'flex items-center gap-2 mt-3 text-sm text-red-400'
        },
          React.createElement(AlertCircle, { className: 'w-4 h-4 flex-shrink-0' }),
          authError,
        ),

        React.createElement('button', {
          type: 'submit',
          disabled: loading || !key.trim(),
          className: 'w-full mt-4 flex items-center justify-center gap-2 py-3 bg-noctis-purple hover:bg-noctis-purple-light disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg cursor-pointer transition-colors duration-200'
        },
          loading ? 'Authenticating...' : 'Access Dashboard',
          !loading && React.createElement(ArrowRight, { className: 'w-4 h-4' }),
        ),
      ),

      React.createElement('p', {
        className: 'text-center text-xs text-noctis-dim mt-4'
      }, 'Your API key is stored in session memory only.'),
    ),
  )
}
