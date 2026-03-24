import React, { useState } from 'react'
import { useApi } from '../hooks/useApi.js'
import { FileText, ChevronLeft, ChevronRight, Clock, AlertTriangle, TrendingUp, Shield, Target } from 'lucide-react'

const PAGE_SIZE = 10

const SECTION_ICONS = {
  key_threats: AlertTriangle,
  correlation_insights: Target,
  emerging_trends: TrendingUp,
  collection_gaps: Shield,
  recommended_actions: FileText,
}

const SECTION_TITLES = {
  key_threats: 'Key Threats',
  correlation_insights: 'Correlation Insights',
  emerging_trends: 'Emerging Trends',
  collection_gaps: 'Collection Gaps',
  recommended_actions: 'Recommended Actions',
}

export default function Briefs() {
  const [view, setView] = useState('latest')
  const [page, setPage] = useState(0)

  const { data: latestData, loading: latestLoading } = useApi('/api/briefs/latest?type=daily')
  const params = new URLSearchParams()
  params.set('type', 'daily')
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)
  const { data: listData, loading: listLoading } = useApi(`/api/briefs?${params.toString()}`)

  const brief = latestData
  const briefs = listData?.briefs || []
  const total = listData?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const renderSection = (key, content) => {
    const Icon = SECTION_ICONS[key] || FileText
    const title = SECTION_TITLES[key] || key
    return React.createElement('div', {
      key,
      className: 'border border-noctis-border/30 rounded-lg p-4'
    },
      React.createElement('div', { className: 'flex items-center gap-2 mb-3' },
        React.createElement(Icon, { className: 'w-4 h-4 text-noctis-purple-light' }),
        React.createElement('h3', { className: 'text-sm font-medium text-noctis-text' }, title),
      ),
      React.createElement('div', {
        className: 'text-sm text-noctis-muted leading-relaxed whitespace-pre-wrap'
      }, String(content)),
    )
  }

  const renderMetric = (label, value) =>
    React.createElement('div', { className: 'text-center' },
      React.createElement('div', { className: 'text-lg font-mono text-noctis-text' }, value),
      React.createElement('div', { className: 'text-xs text-noctis-dim mt-0.5' }, label),
    )

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Intelligence Briefs'),
      React.createElement('div', { className: 'flex gap-2' },
        ['latest', 'history'].map(v =>
          React.createElement('button', {
            key: v,
            onClick: () => setView(v),
            className: `px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors duration-200 ${
              view === v
                ? 'bg-noctis-purple/15 text-noctis-purple-light border border-noctis-purple/30'
                : 'text-noctis-muted bg-noctis-surface border border-noctis-border'
            }`
          }, v === 'latest' ? 'Latest' : 'History')
        ),
      ),
    ),

    // Latest view
    view === 'latest' && (
      latestLoading
        ? React.createElement('div', { className: 'space-y-4' },
            React.createElement('div', { className: 'skeleton h-8 w-2/3' }),
            React.createElement('div', { className: 'skeleton h-20 w-full' }),
            React.createElement('div', { className: 'skeleton h-40 w-full' }),
          )
        : brief
          ? React.createElement('div', { className: 'space-y-4' },
              // Title + meta
              React.createElement('div', null,
                React.createElement('h2', { className: 'text-lg font-medium text-noctis-text' }, brief.title),
                React.createElement('div', { className: 'flex items-center gap-2 mt-1 text-xs text-noctis-dim' },
                  React.createElement(Clock, { className: 'w-3.5 h-3.5' }),
                  `${new Date(brief.periodStart).toLocaleDateString()} — ${new Date(brief.periodEnd).toLocaleDateString()}`,
                  brief.modelUsed && React.createElement('span', { className: 'text-noctis-dim' }, `• ${brief.modelUsed}`),
                ),
              ),

              // Metrics bar
              brief.metrics && React.createElement('div', {
                className: 'grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 bg-noctis-surface/50 border border-noctis-border/30 rounded-lg'
              },
                renderMetric('Findings', brief.metrics.total_findings || 0),
                renderMetric('IOCs', brief.metrics.total_iocs || 0),
                renderMetric('Correlations', brief.metrics.new_correlations || 0),
                renderMetric('Notes', brief.metrics.new_notes || 0),
              ),

              // Executive summary
              React.createElement('div', {
                className: 'p-4 bg-noctis-purple/5 border border-noctis-purple/20 rounded-lg'
              },
                React.createElement('h3', { className: 'text-xs font-medium text-noctis-purple-light mb-2' }, 'EXECUTIVE SUMMARY'),
                React.createElement('p', { className: 'text-sm text-noctis-text leading-relaxed' }, brief.executiveSummary),
              ),

              // Sections
              brief.sections && React.createElement('div', { className: 'space-y-3' },
                ...Object.entries(brief.sections).map(([key, content]) => renderSection(key, content)),
              ),
            )
          : React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
              'No briefs generated yet.',
            )
    ),

    // History view
    view === 'history' && React.createElement('div', { className: 'space-y-3' },
      listLoading
        ? Array.from({ length: 5 }).map((_, i) =>
            React.createElement('div', { key: i, className: 'skeleton h-20 rounded' })
          )
        : briefs.length > 0
          ? briefs.map(b =>
              React.createElement('div', {
                key: b.id,
                onClick: () => setView('latest'),
                className: 'p-4 border border-noctis-border/30 rounded-lg cursor-pointer hover:bg-noctis-surface/50 transition-colors duration-150'
              },
                React.createElement('div', { className: 'flex items-center justify-between mb-1' },
                  React.createElement('h3', { className: 'text-sm font-medium text-noctis-text' }, b.title),
                  React.createElement('span', { className: 'text-xs text-noctis-dim' },
                    new Date(b.generatedAt).toLocaleDateString(),
                  ),
                ),
                React.createElement('p', { className: 'text-xs text-noctis-muted line-clamp-2' }, b.executiveSummary),
              )
            )
          : React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
              'No briefs generated yet.',
            ),

      totalPages > 1 && React.createElement('div', {
        className: 'flex items-center justify-between'
      },
        React.createElement('span', { className: 'text-sm text-noctis-dim' }, `Page ${page + 1} of ${totalPages}`),
        React.createElement('div', { className: 'flex gap-2' },
          React.createElement('button', {
            onClick: () => setPage(p => Math.max(0, p - 1)),
            disabled: page === 0,
            className: 'p-2 bg-noctis-surface border border-noctis-border rounded-lg disabled:opacity-30 cursor-pointer hover:bg-noctis-surface2 transition-colors duration-150'
          }, React.createElement(ChevronLeft, { className: 'w-4 h-4' })),
          React.createElement('button', {
            onClick: () => setPage(p => Math.min(totalPages - 1, p + 1)),
            disabled: page >= totalPages - 1,
            className: 'p-2 bg-noctis-surface border border-noctis-border rounded-lg disabled:opacity-30 cursor-pointer hover:bg-noctis-surface2 transition-colors duration-150'
          }, React.createElement(ChevronRight, { className: 'w-4 h-4' })),
        ),
      ),
    ),
  )
}
