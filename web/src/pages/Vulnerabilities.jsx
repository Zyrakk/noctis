import React, { useState } from 'react'
import { useApi } from '../hooks/useApi.js'
import {
  Search, ChevronLeft, ChevronRight, AlertTriangle, Shield, Bug, ExternalLink, X
} from 'lucide-react'

const PAGE_SIZE = 50

const PRIORITY_COLORS = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-noctis-bg text-noctis-dim border-noctis-border',
}

export default function Vulnerabilities() {
  const [searchQ, setSearchQ] = useState('')
  const [kevOnly, setKevOnly] = useState(false)
  const [hasExploit, setHasExploit] = useState(false)
  const [hasMentions, setHasMentions] = useState(false)
  const [page, setPage] = useState(0)
  const [selectedCVE, setSelectedCVE] = useState(null)

  const params = new URLSearchParams()
  if (searchQ) params.set('q', searchQ)
  if (kevOnly) params.set('kev', 'true')
  if (hasExploit) params.set('exploit', 'true')
  if (hasMentions) params.set('mentions', 'true')
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)

  const { data, loading } = useApi(`/api/vulnerabilities?${params.toString()}`)
  const vulns = data?.vulnerabilities || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const { data: detail } = useApi(selectedCVE ? `/api/vulnerabilities/${selectedCVE}` : null)

  const toggleBtn = (label, active, onClick) =>
    React.createElement('button', {
      onClick: () => { onClick(); setPage(0) },
      className: `px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors duration-200 whitespace-nowrap ${
        active
          ? 'bg-noctis-purple/15 text-noctis-purple-light border border-noctis-purple/30'
          : 'text-noctis-muted bg-noctis-surface border border-noctis-border'
      }`
    }, label)

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Vulnerability Intelligence'),
      React.createElement('span', { className: 'text-sm text-noctis-muted' },
        `${total.toLocaleString()} vulnerabilities`,
      ),
    ),

    // Filters
    React.createElement('div', { className: 'flex items-center gap-3 flex-wrap' },
      React.createElement('div', { className: 'relative flex-1 min-w-[200px]' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: searchQ,
          onChange: e => { setSearchQ(e.target.value); setPage(0) },
          placeholder: 'Search CVE ID...',
          className: 'w-full pl-9 pr-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple transition-colors duration-200 font-mono'
        }),
      ),
      toggleBtn('KEV Only', kevOnly, () => setKevOnly(v => !v)),
      toggleBtn('Has Exploit', hasExploit, () => setHasExploit(v => !v)),
      toggleBtn('Dark Web', hasMentions, () => setHasMentions(v => !v)),
    ),

    // Table
    React.createElement('div', { className: 'border border-white/[0.08] rounded-lg overflow-x-auto' },
      React.createElement('table', { className: 'w-full text-sm' },
        React.createElement('thead', null,
          React.createElement('tr', { className: 'border-b border-white/[0.08] bg-noctis-surface/30' },
            ['CVE ID', 'CVSS', 'EPSS', 'KEV', 'Mentions', 'Priority'].map(h =>
              React.createElement('th', {
                key: h,
                className: 'px-3 py-2.5 text-left text-[11px] font-medium text-noctis-dim uppercase tracking-wider'
              }, h)
            ),
          ),
        ),
        React.createElement('tbody', null,
          loading
            ? Array.from({ length: 10 }).map((_, i) =>
                React.createElement('tr', { key: i, className: 'border-b border-white/[0.05]' },
                  Array.from({ length: 6 }).map((_, j) =>
                    React.createElement('td', { key: j, className: 'px-3 py-2.5' },
                      React.createElement('div', { className: 'skeleton h-4 w-full' }),
                    )
                  ),
                )
              )
            : vulns.map((v, i) =>
                React.createElement('tr', {
                  key: v.id,
                  onClick: () => setSelectedCVE(v.cveId),
                  className: `border-b border-white/[0.05] hover:bg-white/[0.04] cursor-pointer transition-colors duration-150 `
                },
                  React.createElement('td', { className: 'px-3 py-2.5 font-mono text-sm text-noctis-text' }, v.cveId),
                  React.createElement('td', { className: 'px-3 py-2.5' },
                    v.cvssScore != null
                      ? React.createElement('span', {
                          className: `text-xs font-mono px-2 py-0.5 rounded ${
                            v.cvssScore >= 9 ? 'bg-red-500/15 text-red-400' :
                            v.cvssScore >= 7 ? 'bg-orange-500/15 text-orange-400' :
                            v.cvssScore >= 4 ? 'bg-yellow-500/15 text-yellow-400' :
                            'bg-noctis-bg text-noctis-dim'
                          }`
                        }, v.cvssScore.toFixed(1))
                      : React.createElement('span', { className: 'text-xs text-noctis-dim' }, '-'),
                  ),
                  React.createElement('td', { className: 'px-3 py-2.5' },
                    v.epssScore != null
                      ? React.createElement('span', { className: 'text-xs font-mono text-noctis-muted' },
                          (v.epssScore * 100).toFixed(1) + '%')
                      : React.createElement('span', { className: 'text-xs text-noctis-dim' }, '-'),
                  ),
                  React.createElement('td', { className: 'px-3 py-2.5' },
                    v.kevListed
                      ? React.createElement(AlertTriangle, { className: 'w-4 h-4 text-red-400' })
                      : null,
                  ),
                  React.createElement('td', { className: 'px-3 py-2.5' },
                    v.darkWebMentions > 0
                      ? React.createElement('span', { className: 'text-xs font-mono px-2 py-0.5 bg-noctis-purple/10 text-noctis-purple-light rounded' }, v.darkWebMentions)
                      : null,
                  ),
                  React.createElement('td', { className: 'px-3 py-2.5' },
                    v.priorityLabel
                      ? React.createElement('span', {
                          className: `text-xs px-2 py-0.5 rounded border ${PRIORITY_COLORS[v.priorityLabel] || PRIORITY_COLORS.info}`
                        }, v.priorityLabel)
                      : null,
                  ),
                )
              ),
        ),
      ),

      !loading && vulns.length === 0 &&
        React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
          'No vulnerabilities found.',
        ),
    ),

    // Pagination
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

    // Detail panel
    selectedCVE && detail && React.createElement('div', {
      className: 'fixed inset-0 z-50 flex items-center justify-center bg-black/50',
      onClick: () => setSelectedCVE(null),
    },
      React.createElement('div', {
        className: 'bg-noctis-bg border border-noctis-border rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto',
        onClick: e => e.stopPropagation(),
      },
        React.createElement('div', { className: 'flex items-center justify-between mb-4' },
          React.createElement('h2', { className: 'text-lg font-mono text-noctis-text' }, detail.cveId),
          React.createElement('button', {
            onClick: () => setSelectedCVE(null),
            className: 'p-1 hover:bg-noctis-surface rounded cursor-pointer'
          }, React.createElement(X, { className: 'w-5 h-5' })),
        ),

        detail.description && React.createElement('p', {
          className: 'text-sm text-noctis-muted mb-4 leading-relaxed'
        }, detail.description),

        // Scores row
        React.createElement('div', { className: 'grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4' },
          React.createElement('div', { className: 'text-center p-2 bg-noctis-surface/50 rounded' },
            React.createElement('div', { className: 'text-lg font-mono text-noctis-text' }, detail.cvssScore?.toFixed(1) || '-'),
            React.createElement('div', { className: 'text-xs text-noctis-dim' }, 'CVSS'),
          ),
          React.createElement('div', { className: 'text-center p-2 bg-noctis-surface/50 rounded' },
            React.createElement('div', { className: 'text-lg font-mono text-noctis-text' }, detail.epssScore ? (detail.epssScore * 100).toFixed(1) + '%' : '-'),
            React.createElement('div', { className: 'text-xs text-noctis-dim' }, 'EPSS'),
          ),
          React.createElement('div', { className: 'text-center p-2 bg-noctis-surface/50 rounded' },
            React.createElement('div', { className: 'text-lg font-mono text-noctis-text' }, detail.darkWebMentions || 0),
            React.createElement('div', { className: 'text-xs text-noctis-dim' }, 'Mentions'),
          ),
          React.createElement('div', { className: 'text-center p-2 bg-noctis-surface/50 rounded' },
            detail.priorityLabel && React.createElement('span', {
              className: `text-xs px-2 py-0.5 rounded border ${PRIORITY_COLORS[detail.priorityLabel] || PRIORITY_COLORS.info}`
            }, detail.priorityLabel),
            React.createElement('div', { className: 'text-xs text-noctis-dim mt-1' }, 'Priority'),
          ),
        ),

        // Badges
        React.createElement('div', { className: 'flex flex-wrap gap-2 mb-4' },
          detail.kevListed && React.createElement('span', {
            className: 'text-xs px-2 py-1 bg-red-500/15 text-red-400 rounded border border-red-500/30'
          }, 'CISA KEV Listed'),
          detail.exploitAvailable && React.createElement('span', {
            className: 'text-xs px-2 py-1 bg-orange-500/15 text-orange-400 rounded border border-orange-500/30'
          }, 'Exploit Available'),
          detail.kevRansomwareUse && React.createElement('span', {
            className: 'text-xs px-2 py-1 bg-red-500/15 text-red-400 rounded border border-red-500/30'
          }, 'Ransomware Use'),
        ),

        // CWE IDs
        detail.cweIds?.length > 0 && React.createElement('div', { className: 'mb-4' },
          React.createElement('h3', { className: 'text-xs font-medium text-noctis-dim uppercase mb-1' }, 'Weaknesses'),
          React.createElement('div', { className: 'flex flex-wrap gap-1' },
            detail.cweIds.map(cwe =>
              React.createElement('span', { key: cwe, className: 'text-xs font-mono px-2 py-0.5 bg-noctis-surface rounded text-noctis-muted' }, cwe)
            ),
          ),
        ),

        // References
        detail.referenceUrls?.length > 0 && React.createElement('div', null,
          React.createElement('h3', { className: 'text-xs font-medium text-noctis-dim uppercase mb-1' }, 'References'),
          React.createElement('div', { className: 'space-y-1' },
            detail.referenceUrls.slice(0, 5).map((url, i) =>
              React.createElement('a', {
                key: i,
                href: url,
                target: '_blank',
                rel: 'noopener noreferrer',
                className: 'flex items-center gap-1 text-xs text-noctis-purple-light hover:underline truncate'
              },
                React.createElement(ExternalLink, { className: 'w-3 h-3 flex-shrink-0' }),
                String(url),
              )
            ),
          ),
        ),
      ),
    ),
  )
}
