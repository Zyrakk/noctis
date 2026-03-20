import React, { useState } from 'react'
import { Activity, Key, ArrowRight, ArrowLeft, AlertCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'

export default function Login({ navigate }) {
  const { login, error: authError } = useAuth()
  const [key, setKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [shaking, setShaking] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!key.trim()) return
    setLoading(true)
    const ok = await login(key.trim())
    setLoading(false)
    if (ok) {
      navigate('/dashboard')
    } else {
      setShaking(true)
      setTimeout(() => setShaking(false), 500)
    }
  }

  return React.createElement('div', {
    className: 'min-h-screen bg-noctis-bg flex items-center justify-center px-6'
  },
    React.createElement('div', { className: 'w-full max-w-sm' },
      // Back link
      React.createElement('button', {
        onClick: () => navigate('/'),
        className: 'flex items-center gap-1.5 text-xs text-noctis-dim hover:text-noctis-muted cursor-pointer transition-colors duration-200 mb-8'
      },
        React.createElement(ArrowLeft, { className: 'w-3 h-3' }),
        'Back to home',
      ),

      // Logo
      React.createElement('div', { className: 'mb-8' },
        React.createElement('div', { className: 'flex items-center gap-2 mb-1' },
          React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple' }),
          React.createElement('span', {
            className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text'
          }, 'Noctis'),
        ),
        React.createElement('p', {
          className: 'text-xs text-noctis-dim mt-1'
        }, 'Threat Intelligence Dashboard'),
      ),

      // Card
      React.createElement('form', {
        onSubmit: handleSubmit,
        className: `border border-noctis-border/50 rounded p-5 ${shaking ? 'shake' : ''}`
      },
        React.createElement('label', {
          htmlFor: 'apikey',
          className: 'block text-xs font-medium text-noctis-dim mb-2'
        }, 'API Key'),

        React.createElement('div', { className: 'relative' },
          React.createElement(Key, {
            className: 'absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-noctis-dim'
          }),
          React.createElement('input', {
            id: 'apikey',
            type: 'password',
            value: key,
            onChange: (e) => setKey(e.target.value),
            placeholder: 'Enter your API key',
            autoFocus: true,
            className: 'w-full pl-9 pr-4 py-2.5 bg-noctis-bg border border-noctis-border/50 rounded text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-muted/50 transition-colors duration-200 font-mono'
          }),
        ),

        // Error
        authError && React.createElement('div', {
          className: 'flex items-center gap-2 mt-3 text-xs text-red-400'
        },
          React.createElement(AlertCircle, { className: 'w-3.5 h-3.5 flex-shrink-0' }),
          authError,
        ),

        React.createElement('button', {
          type: 'submit',
          disabled: loading || !key.trim(),
          className: 'w-full mt-4 flex items-center justify-center gap-2 py-2.5 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 disabled:opacity-40 disabled:cursor-not-allowed rounded cursor-pointer transition-all duration-200'
        },
          loading ? 'Authenticating...' : 'Access Dashboard',
          !loading && React.createElement(ArrowRight, { className: 'w-3.5 h-3.5' }),
        ),
      ),

      React.createElement('p', {
        className: 'text-xs text-noctis-dim mt-4'
      }, 'Your API key is stored in session memory only.'),
    ),
  )
}
