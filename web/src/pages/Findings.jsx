import React, { useState, useEffect, useCallback } from 'react'
import { useApi, apiFetch } from '../hooks/useApi.js'
import { useAuth } from '../context/AuthContext.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { Search, X, ChevronLeft, ChevronRight, Filter, Shield, ExternalLink } from 'lucide-react'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const PAGE_SIZE = 30

export default function Findings() {
  const { apiKey } = useAuth()
  const [filters, setFilters] = useState({ category: '', severity: '', source: '', q: '' })
  const [page, setPage] = useState(0)
  const [selectedId, setSelectedId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [copiedIOC, setCopiedIOC] = useState(null)

  const params = new URLSearchParams()
  if (filters.category) params.set('category', filters.category)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.source) params.set('source', filters.source)
  if (filters.q) params.set('q', filters.q)
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)

  const { data, loading, error } = useApi(`/api/findings?${params.toString()}`)
  const { data: categories } = useApi('/api/categories')

  const findings = data?.findings || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const loadDetail = useCallback(async (id) => {
    setSelectedId(id)
    setDetailLoading(true)
    try {
      const d = await apiFetch(apiKey, `/api/findings/${id}`)
      setDetail(d)
    } catch {
      setDetail(null)
    }
    setDetailLoading(false)
  }, [apiKey])

  const updateFilter = (key, value) => {
    setFilters(f => ({ ...f, [key]: value }))
    setPage(0)
  }

  return React.createElement('div', { className: 'flex gap-6 min-h-[calc(100vh-3rem)]' },
    // Filters sidebar
    React.createElement('div', {
      className: 'w-56 flex-shrink-0 space-y-5'
    },
      React.createElement('div', { className: 'flex items-center gap-2 text-sm font-medium text-noctis-muted' },
        React.createElement(Filter, { className: 'w-4 h-4' }),
        'Filters',
      ),

      // Search
      React.createElement('div', { className: 'relative' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: filters.q,
          onChange: e => updateFilter('q', e.target.value),
          placeholder: 'Search content...',
          className: 'w-full pl-9 pr-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple transition-colors duration-200'
        }),
      ),

      // Category
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Category'),
        React.createElement('select', {
          value: filters.category,
          onChange: e => updateFilter('category', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Categories'),
          (categories || []).map(c =>
            React.createElement('option', { key: c.category, value: c.category },
              c.category?.replace(/_/g, ' '),
            )
          ),
        ),
      ),

      // Severity
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Severity'),
        React.createElement('select', {
          value: filters.severity,
          onChange: e => updateFilter('severity', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Severities'),
          SEVERITIES.map(s =>
            React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
          ),
        ),
      ),

      // Source type
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Source'),
        React.createElement('select', {
          value: filters.source,
          onChange: e => updateFilter('source', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Sources'),
          ['telegram', 'paste', 'forum', 'web', 'rss'].map(s =>
            React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
          ),
        ),
      ),

      // Clear
      (filters.category || filters.severity || filters.source || filters.q) &&
        React.createElement('button', {
          onClick: () => { setFilters({ category: '', severity: '', source: '', q: '' }); setPage(0) },
          className: 'text-xs text-noctis-purple-light hover:text-noctis-purple cursor-pointer'
        }, 'Clear all filters'),
    ),

    // Main content
    React.createElement('div', { className: 'flex-1 min-w-0' },
      // Header
      React.createElement('div', { className: 'flex items-center justify-between mb-4' },
        React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Findings'),
        React.createElement('span', { className: 'text-sm text-noctis-muted' },
          `${total.toLocaleString()} results`,
        ),
      ),

      // Table
      React.createElement('div', {
        className: 'border border-noctis-border/50 rounded overflow-hidden'
      },
        React.createElement('table', { className: 'w-full text-sm' },
          React.createElement('thead', null,
            React.createElement('tr', { className: 'border-b border-noctis-border bg-noctis-surface/30' },
              ['Time', 'Source', 'Category', 'Severity', 'Summary'].map(h =>
                React.createElement('th', {
                  key: h,
                  className: 'px-4 py-3 text-left text-xs font-medium text-noctis-dim uppercase tracking-wider'
                }, h)
              ),
            ),
          ),
          React.createElement('tbody', null,
            loading
              ? Array.from({ length: 10 }).map((_, i) =>
                  React.createElement('tr', { key: i, className: 'border-b border-noctis-border/50' },
                    Array.from({ length: 5 }).map((_, j) =>
                      React.createElement('td', { key: j, className: 'px-4 py-3' },
                        React.createElement('div', { className: 'skeleton h-4 w-full' }),
                      )
                    ),
                  )
                )
              : findings.map((f, i) =>
                  React.createElement('tr', {
                    key: f.id,
                    onClick: () => loadDetail(f.id),
                    className: `border-b border-noctis-border/50 cursor-pointer transition-colors duration-150 hover:bg-white/[0.04] ${selectedId === f.id ? 'bg-noctis-purple/5' : i % 2 === 0 ? '' : 'bg-white/[0.02]'}`
                  },
                    React.createElement('td', { className: 'px-4 py-3 text-xs font-mono text-noctis-dim whitespace-nowrap' },
                      new Date(f.collectedAt).toLocaleString(),
                    ),
                    React.createElement('td', { className: 'px-4 py-3' },
                      React.createElement('span', { className: 'text-xs px-2 py-0.5 bg-noctis-bg rounded text-noctis-muted' }, f.sourceType),
                    ),
                    React.createElement('td', { className: 'px-4 py-3 text-xs text-noctis-muted' },
                      f.category?.replace(/_/g, ' ') || '-',
                    ),
                    React.createElement('td', { className: 'px-4 py-3' },
                      f.severity ? React.createElement(SeverityBadge, { severity: f.severity }) : '-',
                    ),
                    React.createElement('td', { className: 'px-4 py-3 text-sm text-noctis-text truncate max-w-md' },
                      f.summary || 'No summary',
                    ),
                  )
                ),
          ),
        ),

        // Empty state
        !loading && findings.length === 0 &&
          React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
            'No findings match your filters.',
          ),
      ),

      // Pagination
      totalPages > 1 && React.createElement('div', {
        className: 'flex items-center justify-between mt-4'
      },
        React.createElement('span', { className: 'text-sm text-noctis-dim' },
          `Page ${page + 1} of ${totalPages}`,
        ),
        React.createElement('div', { className: 'flex gap-2' },
          React.createElement('button', {
            onClick: () => setPage(p => Math.max(0, p - 1)),
            disabled: page === 0,
            className: 'p-2 bg-noctis-surface border border-noctis-border rounded-lg disabled:opacity-30 cursor-pointer hover:bg-noctis-surface2 transition-colors duration-150'
          },
            React.createElement(ChevronLeft, { className: 'w-4 h-4' }),
          ),
          React.createElement('button', {
            onClick: () => setPage(p => Math.min(totalPages - 1, p + 1)),
            disabled: page >= totalPages - 1,
            className: 'p-2 bg-noctis-surface border border-noctis-border rounded-lg disabled:opacity-30 cursor-pointer hover:bg-noctis-surface2 transition-colors duration-150'
          },
            React.createElement(ChevronRight, { className: 'w-4 h-4' }),
          ),
        ),
      ),
    ),

    // Detail panel
    selectedId && React.createElement('div', {
      className: 'w-96 flex-shrink-0 border border-noctis-border/50 rounded p-5 overflow-y-auto max-h-[calc(100vh-3rem)] sticky top-0 animate-slide-in'
    },
      React.createElement('div', { className: 'flex items-center justify-between mb-4' },
        React.createElement('h3', { className: 'text-sm font-medium text-noctis-muted' }, 'Finding Detail'),
        React.createElement('button', {
          onClick: () => { setSelectedId(null); setDetail(null) },
          className: 'p-1 hover:bg-noctis-surface2 rounded cursor-pointer transition-colors duration-150'
        },
          React.createElement(X, { className: 'w-4 h-4 text-noctis-dim' }),
        ),
      ),

      detailLoading
        ? React.createElement('div', { className: 'space-y-3' },
            Array.from({ length: 6 }).map((_, i) =>
              React.createElement('div', { key: i, className: 'skeleton h-4 w-full' })
            ),
          )
        : detail && React.createElement('div', { className: 'space-y-4' },
            // Metadata
            React.createElement('div', { className: 'flex items-center gap-2 flex-wrap' },
              detail.severity && React.createElement(SeverityBadge, { severity: detail.severity }),
              detail.category && React.createElement('span', {
                className: 'text-xs px-2 py-0.5 bg-noctis-bg rounded text-noctis-muted'
              }, detail.category.replace(/_/g, ' ')),
              React.createElement('span', {
                className: 'text-xs text-noctis-dim font-mono'
              }, new Date(detail.collectedAt).toLocaleString()),
            ),

            // Summary
            detail.summary && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'AI Summary'),
              React.createElement('p', { className: 'text-sm text-noctis-text leading-relaxed' }, detail.summary),
            ),

            // Tags
            detail.tags?.length > 0 && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'Tags'),
              React.createElement('div', { className: 'flex flex-wrap gap-1.5' },
                detail.tags.map(t =>
                  React.createElement('span', {
                    key: t,
                    className: 'text-xs px-2 py-0.5 bg-noctis-purple/10 border border-noctis-purple/30 rounded text-noctis-purple-light'
                  }, t)
                ),
              ),
            ),

            // IOCs
            detail.iocs?.length > 0 && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-2' },
                `IOCs (${detail.iocs.length})`,
              ),
              React.createElement('div', { className: 'space-y-1.5' },
                detail.iocs.map((ioc, i) =>
                  React.createElement('div', {
                    key: i,
                    onClick: () => {
                      navigator.clipboard.writeText(ioc.value).then(() => {
                        setCopiedIOC(ioc.value)
                        setTimeout(() => setCopiedIOC(null), 2000)
                      })
                    },
                    className: 'flex items-center gap-2 p-2 bg-noctis-bg rounded-lg cursor-pointer hover:bg-noctis-surface transition-colors duration-150',
                    title: 'Click to copy',
                  },
                    React.createElement(Shield, { className: 'w-3.5 h-3.5 text-noctis-cyan flex-shrink-0' }),
                    React.createElement('span', { className: 'text-xs px-1.5 py-0.5 bg-noctis-surface2 rounded text-noctis-dim' }, ioc.type),
                    React.createElement('span', { className: 'text-xs font-mono text-noctis-text truncate' }, ioc.value),
                    copiedIOC === ioc.value && React.createElement('span', { className: 'text-[10px] text-green-400 flex-shrink-0' }, 'copied'),
                  )
                ),
              ),
            ),

            // Content
            React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'Raw Content'),
              React.createElement('pre', {
                className: 'text-xs font-mono text-noctis-muted bg-noctis-bg p-3 rounded-lg overflow-auto max-h-60 whitespace-pre-wrap break-words border border-noctis-border'
              }, detail.content),
            ),

            // URL
            detail.url && React.createElement('a', {
              href: detail.url,
              target: '_blank',
              rel: 'noopener noreferrer',
              className: 'inline-flex items-center gap-1 text-xs text-noctis-blue hover:text-noctis-blue-light cursor-pointer'
            },
              React.createElement(ExternalLink, { className: 'w-3 h-3' }),
              'Original URL',
            ),
          ),
    ),
  )
}
