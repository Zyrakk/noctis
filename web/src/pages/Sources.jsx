import React, { useState, useCallback } from 'react'
import { useApi, apiFetch } from '../hooks/useApi.js'
import { useAuth } from '../context/AuthContext.jsx'
import {
  Globe, Radio, MessageSquare, Rss, FileText, Plus, Check, X,
  Clock, AlertTriangle, Wifi, ChevronLeft, ChevronRight, Inbox
} from 'lucide-react'

const TABS = [
  { value: 'active', label: 'Active', shortLabel: 'Active', dotColor: 'bg-green-400' },
  { value: 'discovered', label: 'Discovered', shortLabel: 'New', dotColor: 'bg-yellow-400' },
  { value: 'paused', label: 'Paused', shortLabel: 'Paused', dotColor: 'bg-gray-400' },
  { value: 'rejected', label: 'Rejected', shortLabel: 'Rejected', dotColor: 'bg-red-400' },
]

const TYPE_ICONS = {
  telegram_channel: Radio,
  telegram_group: MessageSquare,
  forum: Globe,
  paste_site: FileText,
  web: Globe,
  rss: Rss,
}

const SOURCE_TYPES = [
  { value: 'telegram_channel', label: 'Telegram Channel' },
  { value: 'telegram_group', label: 'Telegram Group' },
  { value: 'forum', label: 'Forum' },
  { value: 'paste_site', label: 'Paste Site' },
  { value: 'web', label: 'Web' },
  { value: 'rss', label: 'RSS Feed' },
]

const TYPE_PILLS = [
  { value: '', label: 'All' },
  { value: 'rss', label: 'RSS' },
  { value: 'telegram', label: 'Telegram' },
  { value: 'web', label: 'Web' },
  { value: 'other', label: 'Other' },
]

function typeCategory(type) {
  if (type === 'rss') return 'rss'
  if (type === 'telegram_channel' || type === 'telegram_group') return 'telegram'
  if (type === 'web') return 'web'
  return 'other'
}

const PAGE_SIZE = 50

export default function Sources() {
  const { apiKey } = useAuth()
  const [tab, setTab] = useState('active')
  const [typeFilter, setTypeFilter] = useState('')
  const [page, setPage] = useState(0)
  const [showModal, setShowModal] = useState(false)
  const [newType, setNewType] = useState('telegram_channel')
  const [newIdentifier, setNewIdentifier] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [toast, setToast] = useState(null)
  const [fadingIds, setFadingIds] = useState(new Set())

  const isActive = tab === 'active'
  const apiUrl = isActive
    ? `/api/sources?status=${tab}&limit=500`
    : `/api/sources?status=${tab}&limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}${typeFilter ? `&type=${typeFilter}` : ''}`
  const { data, loading, refetch } = useApi(apiUrl)

  const typeCounts = data?.typeCounts || { rss: 0, telegram: 0, web: 0, other: 0 }
  const allSources = data?.sources || []

  const list = isActive && typeFilter ? allSources.filter(s => typeCategory(s.type) === typeFilter) : allSources
  const total = isActive ? list.length : (data?.total || 0)
  const totalPages = isActive ? 1 : Math.ceil(total / PAGE_SIZE)

  const handleApprove = useCallback(async (id) => {
    try {
      await apiFetch(apiKey, `/api/sources/${id}/approve`, { method: 'POST' })
      setFadingIds(prev => new Set(prev).add(id))
      setToast('Source approved — will be collected within 5 minutes')
      setTimeout(() => {
        setFadingIds(prev => { const next = new Set(prev); next.delete(id); return next })
        refetch()
      }, 500)
      setTimeout(() => setToast(null), 3000)
    } catch (err) {
      console.error('Failed to approve:', err)
      setToast('Failed to approve source')
      setTimeout(() => setToast(null), 3000)
    }
  }, [apiKey, refetch])

  const handleReject = useCallback(async (id) => {
    try {
      await apiFetch(apiKey, `/api/sources/${id}/reject`, { method: 'POST' })
      setFadingIds(prev => new Set(prev).add(id))
      setToast('Source rejected')
      setTimeout(() => {
        setFadingIds(prev => { const next = new Set(prev); next.delete(id); return next })
        refetch()
      }, 500)
      setTimeout(() => setToast(null), 3000)
    } catch (err) {
      console.error('Failed to reject:', err)
      setToast('Failed to reject source')
      setTimeout(() => setToast(null), 3000)
    }
  }, [apiKey, refetch])

  const handleAdd = useCallback(async (e) => {
    e.preventDefault()
    if (!newIdentifier.trim()) return
    setSubmitting(true)
    try {
      await apiFetch(apiKey, '/api/sources', {
        method: 'POST',
        body: JSON.stringify({ type: newType, identifier: newIdentifier.trim() }),
      })
      setShowModal(false)
      setNewIdentifier('')
      refetch()
    } catch (err) {
      console.error('Failed to add:', err)
    }
    setSubmitting(false)
  }, [apiKey, newType, newIdentifier, refetch])

  const changeTab = (t) => { setTab(t); setPage(0); setTypeFilter('') }

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Sources'),
      React.createElement('div', { className: 'flex items-center gap-3' },
        total > 0 && React.createElement('span', { className: 'text-xs text-noctis-dim' }, `${total} total`),
        React.createElement('button', {
          onClick: () => setShowModal(true),
          className: 'flex items-center gap-2 px-4 py-2 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 rounded cursor-pointer transition-all duration-200'
        },
          React.createElement(Plus, { className: 'w-4 h-4' }),
          'Add Source',
        ),
      ),
    ),

    // Tabs + type filter
    React.createElement('div', { className: 'flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3' },
      React.createElement('div', { className: 'flex w-full lg:w-auto items-center gap-1 border border-white/[0.08] rounded p-1 overflow-x-auto flex-nowrap' },
        TABS.map(t =>
          React.createElement('button', {
            key: t.value,
            onClick: () => changeTab(t.value),
            className: `flex-1 lg:flex-initial flex items-center justify-center gap-2 px-4 py-2 rounded text-sm font-medium cursor-pointer transition-colors duration-200 whitespace-nowrap ${
              tab === t.value
                ? 'bg-noctis-surface text-noctis-text'
                : 'text-noctis-muted hover:text-noctis-text'
            }`
          },
            React.createElement('div', { className: `w-2 h-2 rounded-full ${t.dotColor}` }),
            React.createElement('span', { className: 'lg:hidden' }, t.shortLabel),
            React.createElement('span', { className: 'hidden lg:inline' }, t.label),
          )
        ),
      ),
      React.createElement('div', { className: 'flex items-center gap-2 flex-wrap' },
        TYPE_PILLS.map(p =>
          React.createElement('button', {
            key: p.value,
            onClick: () => { setTypeFilter(p.value); setPage(0) },
            className: `px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors duration-200 ${
              typeFilter === p.value
                ? 'bg-noctis-purple/15 text-noctis-purple-light border border-noctis-purple/30'
                : 'text-noctis-muted hover:text-noctis-text bg-noctis-surface border border-noctis-border hover:border-noctis-border'
            }`
          },
            p.value ? `${p.label} (${typeCounts[p.value]})` : `All (${typeCounts.rss + typeCounts.telegram + typeCounts.web + typeCounts.other})`
          )
        ),
      ),
    ),

    // Content
    tab === 'active'
      // Card grid for active
      ? React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4' },
          loading
            ? Array.from({ length: 6 }).map((_, i) =>
                React.createElement('div', { key: i, className: 'skeleton h-24 rounded' })
              )
            : list.length > 0
              ? list.map(s => {
                  const Icon = TYPE_ICONS[s.type] || Globe
                  return React.createElement('div', {
                    key: s.id,
                    className: 'border-l-2 border-noctis-border hover:border-noctis-purple/40 pl-5 py-4 transition-colors duration-200'
                  },
                    React.createElement('div', { className: 'flex items-start justify-between mb-3' },
                      React.createElement('div', { className: 'flex items-center gap-3' },
                        React.createElement(Icon, { className: 'w-4 h-4 text-noctis-dim' }),
                        React.createElement('div', null,
                          React.createElement('div', { className: 'text-sm font-medium text-noctis-text truncate max-w-[180px]' },
                            s.name || s.identifier,
                          ),
                          React.createElement('div', { className: 'text-xs text-noctis-dim' }, s.type.replace(/_/g, ' ')),
                        ),
                      ),
                      React.createElement('div', { className: 'flex items-center gap-2' },
                        React.createElement(Wifi, { className: 'w-3.5 h-3.5 text-green-400' }),
                        React.createElement('button', {
                          onClick: () => handleReject(s.id),
                          title: 'Reject source',
                          className: 'p-1 rounded text-noctis-dim hover:text-red-400 hover:bg-red-500/10 cursor-pointer transition-colors duration-200'
                        },
                          React.createElement(X, { className: 'w-3.5 h-3.5' }),
                        ),
                      ),
                    ),
                    React.createElement('div', { className: 'flex items-center gap-4 text-xs text-noctis-muted' },
                      React.createElement('div', { className: 'flex items-center gap-1' },
                        React.createElement(FileText, { className: 'w-3 h-3' }),
                        `${s.contentCount} items`,
                      ),
                      s.lastCollected && React.createElement('div', { className: 'flex items-center gap-1' },
                        React.createElement(Clock, { className: 'w-3 h-3' }),
                        new Date(s.lastCollected).toLocaleDateString(),
                      ),
                      s.errorCount > 0 && React.createElement('div', { className: 'flex items-center gap-1 text-yellow-400' },
                        React.createElement(AlertTriangle, { className: 'w-3 h-3' }),
                        `${s.errorCount} errors`,
                      ),
                    ),
                  )
                })
              : React.createElement('div', { className: 'col-span-full flex flex-col items-center justify-center py-16 text-noctis-dim' },
                  React.createElement(Inbox, { className: 'w-8 h-8 mb-2 opacity-40' }),
                  React.createElement('span', { className: 'text-sm' }, 'No active sources.'),
                ),
        )
      // Table for discovered/paused
      : React.createElement('div', null,
          // Desktop table
          React.createElement('div', { className: 'hidden lg:block' },
            React.createElement('div', {
              className: 'border border-white/[0.08] rounded-lg overflow-x-auto'
            },
              React.createElement('table', { className: 'w-full text-sm' },
                React.createElement('thead', null,
                  React.createElement('tr', { className: 'border-b border-white/[0.08] bg-noctis-surface/30' },
                    ['Type', 'Identifier', 'Discovered', tab === 'discovered' ? 'Actions' : 'Status'].map(h =>
                      React.createElement('th', {
                        key: h,
                        className: 'px-3 py-2.5 text-left text-[11px] font-medium text-noctis-dim uppercase tracking-wider'
                      }, h)
                    ),
                  ),
                ),
                React.createElement('tbody', null,
                  loading
                    ? Array.from({ length: 5 }).map((_, i) =>
                        React.createElement('tr', { key: i, className: 'border-b border-white/[0.05]' },
                          Array.from({ length: 4 }).map((_, j) =>
                            React.createElement('td', { key: j, className: 'px-3 py-2.5' },
                              React.createElement('div', { className: 'skeleton h-4 w-full' }),
                            )
                          ),
                        )
                      )
                    : list.map((s, i) => {
                        const Icon = TYPE_ICONS[s.type] || Globe
                        return React.createElement('tr', {
                          key: s.id,
                          className: `border-b border-white/[0.05] hover:bg-white/[0.04] transition-all duration-500 ${
                            fadingIds.has(s.id) ? 'opacity-0' : 'opacity-100'
                          }`
                        },
                          React.createElement('td', { className: 'px-3 py-2.5' },
                            React.createElement('div', { className: 'flex items-center gap-2' },
                              React.createElement(Icon, { className: 'w-4 h-4 text-noctis-muted' }),
                              React.createElement('span', { className: 'text-xs text-noctis-muted' }, s.type.replace(/_/g, ' ')),
                            ),
                          ),
                          React.createElement('td', { className: 'px-3 py-2.5 font-mono text-xs text-noctis-text truncate max-w-sm' },
                            s.identifier,
                          ),
                          React.createElement('td', { className: 'px-3 py-2.5 text-xs text-noctis-dim font-mono' },
                            new Date(s.createdAt).toLocaleDateString(),
                          ),
                          React.createElement('td', { className: 'px-3 py-2.5' },
                            tab === 'discovered'
                              ? React.createElement('div', { className: 'flex items-center gap-2' },
                                  React.createElement('button', {
                                    onClick: () => handleApprove(s.id),
                                    className: 'flex items-center gap-1.5 px-3 py-2.5 min-h-[44px] bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400 hover:bg-green-500/20 cursor-pointer transition-colors duration-200'
                                  },
                                    React.createElement(Check, { className: 'w-3 h-3' }),
                                    'Approve',
                                  ),
                                  React.createElement('button', {
                                    onClick: () => handleReject(s.id),
                                    className: 'flex items-center gap-1.5 px-3 py-2.5 min-h-[44px] bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 hover:bg-red-500/20 cursor-pointer transition-colors duration-200'
                                  },
                                    React.createElement(X, { className: 'w-3 h-3' }),
                                    'Reject',
                                  ),
                                )
                              : React.createElement('span', {
                                  className: 'text-xs text-noctis-dim'
                                }, s.status),
                          ),
                        )
                      }),
                ),
              ),

              !loading && list.length === 0 &&
                React.createElement('div', { className: 'py-16 flex flex-col items-center text-noctis-dim' },
                  React.createElement(Inbox, { className: 'w-8 h-8 mb-2 opacity-40' }),
                  React.createElement('span', { className: 'text-sm' }, `No ${tab} sources.`),
                ),
            ),
          ),

          // Mobile card list for discovered/paused/rejected
          React.createElement('div', { className: 'lg:hidden space-y-3' },
            loading
              ? Array.from({ length: 5 }).map((_, i) =>
                  React.createElement('div', { key: i, className: 'skeleton h-24 rounded-lg' })
                )
              : list.length > 0
                ? list.map((s) => {
                    const Icon = TYPE_ICONS[s.type] || Globe
                    return React.createElement('div', {
                      key: s.id,
                      className: `rounded-lg border border-noctis-border/30 transition-all duration-200 active:scale-[0.98] ${
                        fadingIds.has(s.id) ? 'opacity-0' : 'opacity-100'
                      }`,
                    },
                      // Swipe-ready content wrapper
                      React.createElement('div', { className: 'p-4' },
                        // Top row: type + date
                        React.createElement('div', { className: 'flex items-center justify-between mb-2' },
                          React.createElement('div', { className: 'flex items-center gap-2' },
                            React.createElement(Icon, { className: 'w-4 h-4 text-noctis-muted' }),
                            React.createElement('span', { className: 'text-xs text-noctis-muted' }, s.type.replace(/_/g, ' ')),
                          ),
                          React.createElement('span', { className: 'text-xs text-noctis-dim font-mono' },
                            new Date(s.createdAt).toLocaleDateString(),
                          ),
                        ),
                        // Identifier
                        React.createElement('p', {
                          className: 'font-mono text-sm text-noctis-text break-all mb-3'
                        }, s.identifier),
                        // Actions (Discovered) or Status (Paused/Rejected)
                        tab === 'discovered'
                          ? React.createElement('div', { className: 'flex gap-2' },
                              React.createElement('button', {
                                onClick: () => handleApprove(s.id),
                                className: 'flex-1 flex items-center justify-center gap-1.5 px-3 py-2.5 min-h-[44px] bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400 hover:bg-green-500/20 cursor-pointer transition-colors duration-200'
                              },
                                React.createElement(Check, { className: 'w-3 h-3' }),
                                'Approve',
                              ),
                              React.createElement('button', {
                                onClick: () => handleReject(s.id),
                                className: 'flex-1 flex items-center justify-center gap-1.5 px-3 py-2.5 min-h-[44px] bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 hover:bg-red-500/20 cursor-pointer transition-colors duration-200'
                              },
                                React.createElement(X, { className: 'w-3 h-3' }),
                                'Reject',
                              ),
                            )
                          : React.createElement('span', {
                              className: 'text-xs text-noctis-dim'
                            }, s.status),
                      ),
                    )
                  })
                : React.createElement('div', { className: 'py-16 flex flex-col items-center text-noctis-dim' },
                    React.createElement(Inbox, { className: 'w-8 h-8 mb-2 opacity-40' }),
                    React.createElement('span', { className: 'text-sm' }, `No ${tab} sources.`),
                  ),
          ),

          // Pagination
          totalPages > 1 && React.createElement('div', {
            className: 'flex items-center justify-between mt-4'
          },
            React.createElement('span', { className: 'text-xs text-noctis-dim' },
              `Page ${page + 1} of ${totalPages}`,
            ),
            React.createElement('div', { className: 'flex gap-2' },
              React.createElement('button', {
                onClick: () => setPage(p => Math.max(0, p - 1)),
                disabled: page === 0,
                className: 'p-2 border border-white/[0.08] rounded disabled:opacity-30 cursor-pointer hover:bg-noctis-surface/50 transition-colors duration-150'
              },
                React.createElement(ChevronLeft, { className: 'w-4 h-4' }),
              ),
              React.createElement('button', {
                onClick: () => setPage(p => Math.min(totalPages - 1, p + 1)),
                disabled: page >= totalPages - 1,
                className: 'p-2 border border-white/[0.08] rounded disabled:opacity-30 cursor-pointer hover:bg-noctis-surface/50 transition-colors duration-150'
              },
                React.createElement(ChevronRight, { className: 'w-4 h-4' }),
              ),
            ),
          ),
        ),

    // Add modal
    showModal && React.createElement('div', {
      className: 'fixed inset-0 z-50 flex items-center justify-center',
      onClick: (e) => { if (e.target === e.currentTarget) setShowModal(false) },
    },
      React.createElement('div', { className: 'fixed inset-0 bg-black/60 backdrop-blur-sm' }),
      React.createElement('form', {
        onSubmit: handleAdd,
        className: 'relative bg-noctis-bg border border-white/[0.08] rounded p-6 w-full max-w-md z-10'
      },
        React.createElement('div', { className: 'flex items-center justify-between mb-5' },
          React.createElement('h2', { className: 'font-heading font-normal text-lg' }, 'Add Source'),
          React.createElement('button', {
            type: 'button',
            onClick: () => setShowModal(false),
            className: 'p-1 hover:bg-noctis-surface rounded cursor-pointer transition-colors duration-150'
          },
            React.createElement(X, { className: 'w-4 h-4 text-noctis-dim' }),
          ),
        ),

        React.createElement('div', { className: 'space-y-4' },
          React.createElement('div', null,
            React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Type'),
            React.createElement('select', {
              value: newType,
              onChange: e => setNewType(e.target.value),
              className: 'w-full px-3 py-3 bg-noctis-bg border border-white/[0.08] rounded text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-muted/50'
            },
              SOURCE_TYPES.map(t =>
                React.createElement('option', { key: t.value, value: t.value }, t.label)
              ),
            ),
          ),
          React.createElement('div', null,
            React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Identifier'),
            React.createElement('input', {
              type: 'text',
              value: newIdentifier,
              onChange: e => setNewIdentifier(e.target.value),
              placeholder: 'e.g., t.me/channel_name or https://...',
              className: 'w-full px-3 py-3 bg-noctis-bg border border-white/[0.08] rounded text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-muted/50 font-mono transition-colors duration-200'
            }),
          ),
        ),

        React.createElement('div', { className: 'flex justify-end gap-3 mt-6' },
          React.createElement('button', {
            type: 'button',
            onClick: () => setShowModal(false),
            className: 'px-4 py-2 text-sm text-noctis-muted hover:text-noctis-text cursor-pointer transition-colors duration-200'
          }, 'Cancel'),
          React.createElement('button', {
            type: 'submit',
            disabled: submitting || !newIdentifier.trim(),
            className: 'px-4 py-2 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 rounded cursor-pointer disabled:opacity-40 transition-all duration-200'
          }, submitting ? 'Adding...' : 'Add Source'),
        ),
      ),
    ),

    toast && React.createElement('div', {
      className: 'fixed bottom-24 left-4 right-4 lg:bottom-6 lg:right-6 lg:left-auto z-50 px-4 py-3 bg-noctis-surface border border-white/[0.08] rounded-lg text-sm text-noctis-text shadow-lg'
    },
      toast,
    ),
  )
}
