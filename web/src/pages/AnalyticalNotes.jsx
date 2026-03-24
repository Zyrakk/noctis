import React, { useState } from 'react'
import { useApi } from '../hooks/useApi.js'
import { ChevronLeft, ChevronRight, FileText } from 'lucide-react'

const NOTE_TYPES = [
  'correlation_judgment', 'attribution', 'pattern', 'prediction', 'warning', 'context'
]
const STATUSES = ['active', 'superseded', 'retracted']
const PAGE_SIZE = 20

const typeColors = {
  correlation_judgment: 'bg-noctis-purple/15 text-noctis-purple-light border-noctis-purple/30',
  attribution: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  pattern: 'bg-noctis-blue/15 text-noctis-blue-light border-noctis-blue/30',
  prediction: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  warning: 'bg-red-500/15 text-red-400 border-red-500/30',
  context: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

const creatorColors = {
  analyst: 'bg-noctis-purple/10 text-noctis-purple-light',
  correlator: 'bg-noctis-blue/10 text-noctis-blue-light',
  human: 'bg-noctis-green/10 text-noctis-green',
}

function confidenceColor(c) {
  if (c < 0.3) return 'bg-red-500'
  if (c < 0.7) return 'bg-yellow-500'
  return 'bg-green-500'
}

export default function AnalyticalNotes() {
  const [filters, setFilters] = useState({ type: '', status: 'active', entityId: '' })
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState(null)

  const params = new URLSearchParams()
  if (filters.type) params.set('type', filters.type)
  if (filters.status) params.set('status', filters.status)
  if (filters.entityId) params.set('entity_id', filters.entityId)
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)

  const { data, loading } = useApi(`/api/notes?${params.toString()}`)
  const notes = data?.notes || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const updateFilter = (key, value) => {
    setFilters(f => ({ ...f, [key]: value }))
    setPage(0)
  }

  return React.createElement('div', { className: 'animate-page-enter' },
    // Header
    React.createElement('div', { className: 'flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-5' },
      React.createElement('div', { className: 'flex items-center gap-2' },
        React.createElement(FileText, { className: 'w-5 h-5 text-noctis-purple' }),
        React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Analytical Notes'),
      ),
      React.createElement('span', { className: 'text-sm text-noctis-muted' },
        `${total.toLocaleString()} notes`,
      ),
    ),

    // Filters
    React.createElement('div', { className: 'flex flex-wrap gap-3 mb-5' },
      // Type filter
      React.createElement('select', {
        value: filters.type,
        onChange: e => updateFilter('type', e.target.value),
        className: 'px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
      },
        React.createElement('option', { value: '' }, 'All Types'),
        NOTE_TYPES.map(t =>
          React.createElement('option', { key: t, value: t }, t.replace(/_/g, ' '))
        ),
      ),

      // Status filter
      React.createElement('select', {
        value: filters.status,
        onChange: e => updateFilter('status', e.target.value),
        className: 'px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
      },
        React.createElement('option', { value: '' }, 'All Statuses'),
        STATUSES.map(s =>
          React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
        ),
      ),
    ),

    // Notes list
    loading
      ? React.createElement('div', { className: 'space-y-3' },
          Array.from({ length: 6 }).map((_, i) =>
            React.createElement('div', { key: i, className: 'skeleton h-28 w-full rounded-lg' })
          ),
        )
      : notes.length === 0
        ? React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
            'No analytical notes match your filters.',
          )
        : React.createElement('div', { className: 'space-y-3' },
            notes.map(n => {
              const isExpanded = expanded === n.id
              const typeCls = typeColors[n.noteType] || typeColors.context

              return React.createElement('div', {
                key: n.id,
                className: 'p-4 rounded-lg border border-noctis-border/30 bg-noctis-surface/20 transition-all duration-150'
              },
                // Top row: title + type badge
                React.createElement('div', { className: 'flex items-start justify-between gap-2 mb-2' },
                  React.createElement('h3', { className: 'text-sm font-medium text-noctis-text' }, n.title),
                  React.createElement('span', {
                    className: `text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0 ${typeCls}`
                  }, n.noteType.replace(/_/g, ' ')),
                ),

                // Content (truncated or expanded)
                React.createElement('p', {
                  onClick: () => setExpanded(isExpanded ? null : n.id),
                  className: `text-xs text-noctis-muted leading-relaxed mb-3 cursor-pointer ${isExpanded ? '' : 'line-clamp-3'}`
                }, n.content),

                // Confidence bar
                React.createElement('div', { className: 'flex items-center gap-2 mb-2' },
                  React.createElement('span', { className: 'text-[10px] text-noctis-dim w-16' }, 'Confidence'),
                  React.createElement('div', { className: 'flex-1 h-1.5 bg-noctis-bg rounded-full overflow-hidden' },
                    React.createElement('div', {
                      className: `h-full rounded-full ${confidenceColor(n.confidence)}`,
                      style: { width: `${Math.round(n.confidence * 100)}%` },
                    }),
                  ),
                  React.createElement('span', { className: 'text-[10px] text-noctis-dim w-8 text-right' },
                    `${Math.round(n.confidence * 100)}%`,
                  ),
                ),

                // Bottom row: creator, model, entity, time
                React.createElement('div', { className: 'flex items-center flex-wrap gap-2 text-[10px]' },
                  React.createElement('span', {
                    className: `px-1.5 py-0.5 rounded ${creatorColors[n.createdBy] || creatorColors.human}`
                  }, n.createdBy),
                  n.modelUsed && React.createElement('span', {
                    className: 'px-1.5 py-0.5 bg-noctis-bg rounded text-noctis-dim'
                  }, n.modelUsed),
                  n.entityId && React.createElement('span', {
                    className: 'px-1.5 py-0.5 bg-noctis-cyan/10 border border-noctis-cyan/20 rounded text-cyan-400 truncate max-w-[200px]'
                  }, n.entityId),
                  React.createElement('span', { className: 'text-noctis-dim font-mono ml-auto' },
                    new Date(n.createdAt).toLocaleString(),
                  ),
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
