import React, { useState } from 'react'
import { useApi } from '../hooks/useApi.js'
import { ChevronLeft, ChevronRight, GitBranch } from 'lucide-react'

const PAGE_SIZE = 20

const decisionColors = {
  promote: 'bg-green-500/15 text-green-400 border-green-500/30',
  reject: 'bg-red-500/15 text-red-400 border-red-500/30',
  defer: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
}

export default function Correlations() {
  const [tab, setTab] = useState('correlations')
  const [page, setPage] = useState(0)
  const [decisionFilter, setDecisionFilter] = useState('')

  const corrParams = new URLSearchParams()
  corrParams.set('limit', PAGE_SIZE)
  corrParams.set('offset', page * PAGE_SIZE)
  const { data: corrData, loading: corrLoading } = useApi(`/api/correlations?${corrParams.toString()}`)

  const decParams = new URLSearchParams()
  if (decisionFilter) decParams.set('decision', decisionFilter)
  decParams.set('limit', PAGE_SIZE)
  decParams.set('offset', page * PAGE_SIZE)
  const { data: decData, loading: decLoading } = useApi(`/api/correlation-decisions?${decParams.toString()}`)

  const data = tab === 'correlations' ? corrData : decData
  const loading = tab === 'correlations' ? corrLoading : decLoading
  const items = tab === 'correlations' ? (data?.correlations || []) : (data?.decisions || [])
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  return React.createElement('div', { className: 'animate-page-enter' },
    // Header
    React.createElement('div', { className: 'flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-5' },
      React.createElement('div', { className: 'flex items-center gap-2' },
        React.createElement(GitBranch, { className: 'w-5 h-5 text-noctis-purple' }),
        React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Correlations'),
      ),
      React.createElement('span', { className: 'text-sm text-noctis-muted' },
        `${total.toLocaleString()} ${tab}`,
      ),
    ),

    // Tab bar
    React.createElement('div', { className: 'flex gap-2 mb-5' },
      ['correlations', 'decisions'].map(t =>
        React.createElement('button', {
          key: t,
          onClick: () => { setTab(t); setPage(0) },
          className: `px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors duration-200 ${
            tab === t
              ? 'bg-noctis-purple/15 text-noctis-purple-light border border-noctis-purple/30'
              : 'text-noctis-muted hover:text-noctis-text bg-noctis-surface border border-noctis-border'
          }`
        }, t.charAt(0).toUpperCase() + t.slice(1)),
      ),
      tab === 'decisions' && React.createElement('select', {
        value: decisionFilter,
        onChange: e => { setDecisionFilter(e.target.value); setPage(0) },
        className: 'px-3 py-1.5 bg-noctis-surface border border-noctis-border rounded-lg text-xs text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
      },
        React.createElement('option', { value: '' }, 'All Decisions'),
        ['promote', 'reject', 'defer'].map(d =>
          React.createElement('option', { key: d, value: d }, d.charAt(0).toUpperCase() + d.slice(1))
        ),
      ),
    ),

    // Content
    loading
      ? React.createElement('div', { className: 'space-y-3' },
          Array.from({ length: 6 }).map((_, i) =>
            React.createElement('div', { key: i, className: 'skeleton h-24 w-full rounded-lg' })
          ),
        )
      : items.length === 0
        ? React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
            `No ${tab} found.`,
          )
        : React.createElement('div', { className: 'space-y-3' },
            tab === 'correlations'
              ? items.map(c =>
                  React.createElement('div', {
                    key: c.id,
                    className: 'p-4 rounded-lg border border-white/[0.06] bg-noctis-surface/20'
                  },
                    React.createElement('div', { className: 'flex items-center gap-2 mb-2 flex-wrap' },
                      React.createElement('span', {
                        className: 'text-xs px-2 py-0.5 bg-noctis-purple/10 border border-noctis-purple/30 rounded text-noctis-purple-light'
                      }, c.correlationType?.replace(/_/g, ' ')),
                      React.createElement('span', {
                        className: 'text-xs px-2 py-0.5 bg-noctis-bg rounded text-noctis-dim'
                      }, c.method),
                      React.createElement('span', {
                        className: 'text-xs font-mono text-noctis-dim'
                      }, `${Math.round(c.confidence * 100)}% confidence`),
                    ),
                    React.createElement('div', { className: 'flex flex-wrap gap-1 mb-2' },
                      (c.entityIds || []).slice(0, 5).map(e =>
                        React.createElement('span', {
                          key: e,
                          className: 'text-[10px] px-1.5 py-0.5 bg-noctis-cyan/10 border border-noctis-cyan/20 rounded text-cyan-400 truncate max-w-[200px]'
                        }, e)
                      ),
                    ),
                    React.createElement('div', { className: 'text-[10px] text-noctis-dim font-mono' },
                      new Date(c.createdAt).toLocaleString(),
                    ),
                  )
                )
              : items.map(d => {
                  const cls = decisionColors[d.decision] || decisionColors.defer
                  return React.createElement('div', {
                    key: d.id,
                    className: 'p-4 rounded-lg border border-white/[0.06] bg-noctis-surface/20'
                  },
                    React.createElement('div', { className: 'flex items-center gap-2 mb-2 flex-wrap' },
                      React.createElement('span', {
                        className: `text-xs px-2 py-0.5 rounded border ${cls}`
                      }, d.decision.toUpperCase()),
                      React.createElement('span', {
                        className: 'text-xs font-mono text-noctis-dim'
                      }, `${Math.round(d.confidence * 100)}% confidence`),
                      d.modelUsed && React.createElement('span', {
                        className: 'text-xs px-1.5 py-0.5 bg-noctis-bg rounded text-noctis-dim'
                      }, d.modelUsed),
                    ),
                    React.createElement('p', { className: 'text-xs text-noctis-muted leading-relaxed mb-2 line-clamp-2' },
                      d.reasoning,
                    ),
                    React.createElement('div', { className: 'flex items-center gap-2 text-[10px] text-noctis-dim' },
                      React.createElement('span', { className: 'font-mono truncate max-w-[200px]' }, d.clusterId),
                      React.createElement('span', { className: 'font-mono ml-auto' }, new Date(d.createdAt).toLocaleString()),
                    ),
                  )
                }),
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
  )
}
