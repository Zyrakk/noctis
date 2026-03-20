import React, { useState, useCallback } from 'react'
import { useApi } from '../hooks/useApi.js'
import {
  Search, Download, Copy, Check, Globe, Hash, Mail, Bug, Link, Server, ChevronLeft, ChevronRight
} from 'lucide-react'

const IOC_TYPES = [
  { value: '', label: 'All', icon: null },
  { value: 'ip', label: 'IPs', icon: Server },
  { value: 'domain', label: 'Domains', icon: Globe },
  { value: 'hash_md5', label: 'MD5', icon: Hash },
  { value: 'hash_sha256', label: 'SHA256', icon: Hash },
  { value: 'email', label: 'Emails', icon: Mail },
  { value: 'cve', label: 'CVEs', icon: Bug },
  { value: 'url', label: 'URLs', icon: Link },
]

const PAGE_SIZE = 50

export default function IOCs() {
  const [typeFilter, setTypeFilter] = useState('')
  const [searchQ, setSearchQ] = useState('')
  const [page, setPage] = useState(0)
  const [copiedId, setCopiedId] = useState(null)

  const params = new URLSearchParams()
  if (typeFilter) params.set('type', typeFilter)
  if (searchQ) params.set('q', searchQ)
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)

  const { data, loading } = useApi(`/api/iocs?${params.toString()}`)
  const iocs = data?.iocs || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const copyValue = useCallback(async (id, value) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch { /* clipboard not available */ }
  }, [])

  const exportCSV = useCallback(() => {
    if (!iocs.length) return
    const header = 'type,value,context,first_seen,last_seen,sighting_count'
    const rows = iocs.map(i =>
      `"${i.type}","${i.value}","${(i.context || '').replace(/"/g, '""')}","${i.firstSeen}","${i.lastSeen}",${i.sightingCount}`
    )
    const csv = [header, ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `noctis-iocs-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [iocs])

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'IOC Explorer'),
      React.createElement('div', { className: 'flex items-center gap-3' },
        React.createElement('span', { className: 'text-sm text-noctis-muted' },
          `${total.toLocaleString()} indicators`,
        ),
        React.createElement('button', {
          onClick: exportCSV,
          disabled: !iocs.length,
          className: 'flex items-center gap-2 px-3 py-1.5 border border-noctis-muted/30 rounded text-sm text-noctis-muted hover:text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/50 cursor-pointer disabled:opacity-30 transition-all duration-200'
        },
          React.createElement(Download, { className: 'w-4 h-4' }),
          'Export CSV',
        ),
      ),
    ),

    // Type tabs + search
    React.createElement('div', {
      className: 'flex items-center gap-4 flex-wrap'
    },
      // Type pills
      React.createElement('div', { className: 'flex items-center gap-1.5' },
        IOC_TYPES.map(t =>
          React.createElement('button', {
            key: t.value,
            onClick: () => { setTypeFilter(t.value); setPage(0) },
            className: `px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors duration-200 ${
              typeFilter === t.value
                ? 'bg-noctis-purple/15 text-noctis-purple-light border border-noctis-purple/30'
                : 'text-noctis-muted hover:text-noctis-text bg-noctis-surface border border-noctis-border hover:border-noctis-border'
            }`
          }, t.label)
        ),
      ),

      // Search
      React.createElement('div', { className: 'relative flex-1 max-w-xs' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: searchQ,
          onChange: e => { setSearchQ(e.target.value); setPage(0) },
          placeholder: 'Search by value...',
          className: 'w-full pl-9 pr-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple transition-colors duration-200 font-mono'
        }),
      ),
    ),

    // Table
    React.createElement('div', {
      className: 'border border-noctis-border/50 rounded overflow-x-auto'
    },
      React.createElement('table', { className: 'w-full text-sm' },
        React.createElement('thead', null,
          React.createElement('tr', { className: 'border-b border-noctis-border bg-noctis-surface/30' },
            ['Type', 'Value', 'Context', 'First Seen', 'Sightings'].map(h =>
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
            : iocs.map((ioc, i) =>
                React.createElement('tr', {
                  key: ioc.id,
                  className: `border-b border-noctis-border/50 hover:bg-white/[0.04] transition-colors duration-150 ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`
                },
                  React.createElement('td', { className: 'px-4 py-3' },
                    React.createElement('span', {
                      className: 'text-xs px-2 py-0.5 bg-noctis-cyan/10 border border-noctis-cyan/30 rounded text-cyan-400 font-mono'
                    }, ioc.type),
                  ),
                  React.createElement('td', { className: 'px-4 py-3' },
                    React.createElement('div', { className: 'flex items-center gap-2' },
                      React.createElement('span', {
                        className: 'font-mono text-sm text-noctis-text truncate max-w-xs'
                      }, ioc.value),
                      React.createElement('button', {
                        onClick: (e) => { e.stopPropagation(); copyValue(ioc.id, ioc.value) },
                        className: 'p-1 hover:bg-noctis-surface2 rounded cursor-pointer transition-colors duration-150 flex-shrink-0',
                        title: 'Copy to clipboard',
                      },
                        copiedId === ioc.id
                          ? React.createElement(Check, { className: 'w-3.5 h-3.5 text-noctis-green' })
                          : React.createElement(Copy, { className: 'w-3.5 h-3.5 text-noctis-dim' }),
                      ),
                    ),
                  ),
                  React.createElement('td', { className: 'px-4 py-3 text-xs text-noctis-muted truncate max-w-xs' },
                    ioc.context || '-',
                  ),
                  React.createElement('td', { className: 'px-4 py-3 text-xs font-mono text-noctis-dim whitespace-nowrap' },
                    new Date(ioc.firstSeen).toLocaleDateString(),
                  ),
                  React.createElement('td', { className: 'px-4 py-3' },
                    React.createElement('span', {
                      className: 'text-xs font-mono px-2 py-0.5 bg-noctis-bg rounded text-noctis-muted'
                    }, ioc.sightingCount),
                  ),
                )
              ),
        ),
      ),

      !loading && iocs.length === 0 &&
        React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
          'No IOCs found.',
        ),
    ),

    // Pagination
    totalPages > 1 && React.createElement('div', {
      className: 'flex items-center justify-between'
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
