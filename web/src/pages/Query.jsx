import React, { useState, useCallback } from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import { Search, Loader, ChevronDown, ChevronUp, Zap } from 'lucide-react'

const EXAMPLES = [
  'Show me all critical findings from the last 7 days',
  'Which threat actors are most active?',
  'What CVEs have dark web mentions?',
  'Find all credential leaks mentioning banking',
  'Show IOCs with the highest threat scores',
  'What correlations were confirmed by the analyst?',
]

export default function QueryPage() {
  const { apiKey } = useAuth()
  const [question, setQuestion] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [showSQL, setShowSQL] = useState(false)
  const [history, setHistory] = useState([])

  const runQuery = useCallback(async (q) => {
    const query = q || question
    if (!query.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const resp = await fetch('/api/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey,
        },
        body: JSON.stringify({ question: query }),
      })

      const data = await resp.json()

      if (!resp.ok) {
        setError(data.error || 'Query failed')
        return
      }

      setResult(data)
      setHistory(prev => [{ question: query, rowCount: data.row_count, time: new Date() }, ...prev.slice(0, 19)])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [question, apiKey])

  const handleSubmit = (e) => {
    e.preventDefault()
    runQuery()
  }

  const formatCell = (val) => {
    if (val === null || val === undefined) return '-'
    if (typeof val === 'boolean') return val ? 'true' : 'false'
    if (val instanceof Date || (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(val))) {
      return new Date(val).toLocaleString()
    }
    if (typeof val === 'object') return JSON.stringify(val)
    return String(val)
  }

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Ask Noctis'),

    // Query input
    React.createElement('form', { onSubmit: handleSubmit },
      React.createElement('div', { className: 'relative' },
        React.createElement(Search, { className: 'absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: question,
          onChange: e => setQuestion(e.target.value),
          placeholder: 'Ask a question about your threat intelligence...',
          className: 'w-full pl-12 pr-24 py-4 bg-noctis-surface border border-noctis-border rounded-xl text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple transition-colors duration-200',
          disabled: loading,
        }),
        React.createElement('button', {
          type: 'submit',
          disabled: loading || !question.trim(),
          className: 'absolute right-2 top-1/2 -translate-y-1/2 px-4 py-2 bg-noctis-purple/20 text-noctis-purple-light rounded-lg text-sm font-medium cursor-pointer disabled:opacity-30 hover:bg-noctis-purple/30 transition-colors duration-200'
        }, loading
          ? React.createElement(Loader, { className: 'w-4 h-4 animate-spin' })
          : 'Query'
        ),
      ),
    ),

    // Example queries
    !result && !loading && React.createElement('div', { className: 'space-y-2' },
      React.createElement('p', { className: 'text-xs text-noctis-dim uppercase tracking-wider' }, 'Try asking'),
      React.createElement('div', { className: 'grid grid-cols-1 sm:grid-cols-2 gap-2' },
        EXAMPLES.map((ex, i) =>
          React.createElement('button', {
            key: i,
            onClick: () => { setQuestion(ex); runQuery(ex) },
            className: 'text-left p-3 border border-noctis-border/30 rounded-lg text-sm text-noctis-muted hover:text-noctis-text hover:border-noctis-purple/30 hover:bg-noctis-surface/50 cursor-pointer transition-all duration-150'
          },
            React.createElement(Zap, { className: 'w-3.5 h-3.5 inline mr-2 text-noctis-purple-light' }),
            ex,
          )
        ),
      ),
    ),

    // Error
    error && React.createElement('div', {
      className: 'p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400'
    }, error),

    // Results
    result && React.createElement('div', { className: 'space-y-4' },
      // Meta bar
      React.createElement('div', { className: 'flex items-center justify-between text-xs text-noctis-dim' },
        React.createElement('span', null, `${result.row_count} rows in ${result.duration}`),
        React.createElement('button', {
          onClick: () => setShowSQL(v => !v),
          className: 'flex items-center gap-1 text-noctis-muted hover:text-noctis-text cursor-pointer transition-colors duration-150'
        },
          showSQL ? React.createElement(ChevronUp, { className: 'w-3.5 h-3.5' }) : React.createElement(ChevronDown, { className: 'w-3.5 h-3.5' }),
          'SQL',
        ),
      ),

      // SQL (collapsible)
      showSQL && React.createElement('pre', {
        className: 'p-3 bg-noctis-surface border border-noctis-border rounded-lg text-xs font-mono text-noctis-muted overflow-x-auto whitespace-pre-wrap'
      }, result.sql),

      // Data table
      result.columns && result.columns.length > 0 && React.createElement('div', {
        className: 'border border-noctis-border/50 rounded overflow-x-auto'
      },
        React.createElement('table', { className: 'w-full text-sm' },
          React.createElement('thead', null,
            React.createElement('tr', { className: 'border-b border-noctis-border bg-noctis-surface/30' },
              result.columns.map(col =>
                React.createElement('th', {
                  key: col,
                  className: 'px-3 py-2 text-left text-xs font-medium text-noctis-dim uppercase tracking-wider whitespace-nowrap'
                }, col)
              ),
            ),
          ),
          React.createElement('tbody', null,
            result.rows.map((row, i) =>
              React.createElement('tr', {
                key: i,
                className: `border-b border-noctis-border/50 ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`
              },
                row.map((cell, j) =>
                  React.createElement('td', {
                    key: j,
                    className: 'px-3 py-2 text-xs font-mono text-noctis-muted whitespace-nowrap max-w-xs truncate'
                  }, formatCell(cell))
                ),
              )
            ),
          ),
        ),
      ),

      result.row_count === 0 && React.createElement('div', {
        className: 'py-8 text-center text-sm text-noctis-dim'
      }, 'No results found.'),
    ),

    // Query history
    history.length > 0 && !loading && React.createElement('div', { className: 'space-y-2' },
      React.createElement('p', { className: 'text-xs text-noctis-dim uppercase tracking-wider' }, 'Recent queries'),
      React.createElement('div', { className: 'space-y-1' },
        history.map((h, i) =>
          React.createElement('button', {
            key: i,
            onClick: () => { setQuestion(h.question); runQuery(h.question) },
            className: 'w-full text-left p-2 rounded text-xs text-noctis-muted hover:text-noctis-text hover:bg-noctis-surface/50 cursor-pointer transition-colors duration-150 flex items-center justify-between'
          },
            React.createElement('span', { className: 'truncate' }, h.question),
            React.createElement('span', { className: 'text-noctis-dim ml-2 flex-shrink-0' }, `${h.rowCount} rows`),
          )
        ),
      ),
    ),
  )
}
