import React, { useState, useCallback } from 'react'
import { useApi, apiFetch } from '../hooks/useApi.js'
import { useAuth } from '../context/AuthContext.jsx'
import {
  Globe, Radio, MessageSquare, Rss, FileText, Plus, Check, X,
  Clock, AlertTriangle, Wifi
} from 'lucide-react'

const TABS = [
  { value: 'active', label: 'Active', dotColor: 'bg-green-400' },
  { value: 'discovered', label: 'Discovered', dotColor: 'bg-yellow-400' },
  { value: 'paused', label: 'Paused', dotColor: 'bg-gray-400' },
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

export default function Sources() {
  const { apiKey } = useAuth()
  const [tab, setTab] = useState('active')
  const [showModal, setShowModal] = useState(false)
  const [newType, setNewType] = useState('telegram_channel')
  const [newIdentifier, setNewIdentifier] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const { data: sources, loading, refetch } = useApi(`/api/sources?status=${tab}`)

  const handleApprove = useCallback(async (id) => {
    try {
      await apiFetch(apiKey, `/api/sources/${id}/approve`, { method: 'POST' })
      refetch()
    } catch (err) {
      console.error('Failed to approve:', err)
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

  const list = sources || []

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Sources'),
      React.createElement('button', {
        onClick: () => setShowModal(true),
        className: 'flex items-center gap-2 px-4 py-2 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 rounded cursor-pointer transition-all duration-200'
      },
        React.createElement(Plus, { className: 'w-4 h-4' }),
        'Add Source',
      ),
    ),

    // Tabs
    React.createElement('div', { className: 'flex items-center gap-1 border border-noctis-border/50 rounded p-1' },
      TABS.map(t =>
        React.createElement('button', {
          key: t.value,
          onClick: () => setTab(t.value),
          className: `flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer transition-colors duration-200 ${
            tab === t.value
              ? 'bg-noctis-surface2 text-noctis-text'
              : 'text-noctis-muted hover:text-noctis-text'
          }`
        },
          React.createElement('div', { className: `w-2 h-2 rounded-full ${t.dotColor}` }),
          t.label,
        )
      ),
    ),

    // Content
    tab === 'active'
      // Card grid for active
      ? React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4' },
          loading
            ? Array.from({ length: 6 }).map((_, i) =>
                React.createElement('div', { key: i, className: 'skeleton h-32 rounded-xl' })
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
                        React.createElement('div', {
                          className: 'w-9 h-9 flex items-center justify-center bg-noctis-purple/10 rounded-lg'
                        },
                          React.createElement(Icon, { className: 'w-4 h-4 text-noctis-purple-light' }),
                        ),
                        React.createElement('div', null,
                          React.createElement('div', { className: 'text-sm font-medium text-noctis-text truncate max-w-[180px]' },
                            s.name || s.identifier,
                          ),
                          React.createElement('div', { className: 'text-xs text-noctis-dim' }, s.type.replace(/_/g, ' ')),
                        ),
                      ),
                      React.createElement(Wifi, { className: 'w-4 h-4 text-green-400' }),
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
              : React.createElement('div', { className: 'col-span-full text-center py-12 text-sm text-noctis-dim' },
                  'No active sources.',
                ),
        )
      // Table for discovered/paused
      : React.createElement('div', {
          className: 'border border-noctis-border/50 rounded overflow-hidden'
        },
          React.createElement('table', { className: 'w-full text-sm' },
            React.createElement('thead', null,
              React.createElement('tr', { className: 'border-b border-noctis-border' },
                ['Type', 'Identifier', 'Discovered', tab === 'discovered' ? 'Actions' : 'Status'].map(h =>
                  React.createElement('th', {
                    key: h,
                    className: 'px-4 py-3 text-left text-xs font-medium text-noctis-dim uppercase tracking-wider'
                  }, h)
                ),
              ),
            ),
            React.createElement('tbody', null,
              loading
                ? Array.from({ length: 5 }).map((_, i) =>
                    React.createElement('tr', { key: i, className: 'border-b border-noctis-border/50' },
                      Array.from({ length: 4 }).map((_, j) =>
                        React.createElement('td', { key: j, className: 'px-4 py-3' },
                          React.createElement('div', { className: 'skeleton h-4 w-full' }),
                        )
                      ),
                    )
                  )
                : list.map(s => {
                    const Icon = TYPE_ICONS[s.type] || Globe
                    return React.createElement('tr', {
                      key: s.id,
                      className: 'border-b border-noctis-border/50 hover:bg-noctis-surface2 transition-colors duration-150'
                    },
                      React.createElement('td', { className: 'px-4 py-3' },
                        React.createElement('div', { className: 'flex items-center gap-2' },
                          React.createElement(Icon, { className: 'w-4 h-4 text-noctis-muted' }),
                          React.createElement('span', { className: 'text-xs text-noctis-muted' }, s.type.replace(/_/g, ' ')),
                        ),
                      ),
                      React.createElement('td', { className: 'px-4 py-3 font-mono text-sm text-noctis-text truncate max-w-sm' },
                        s.identifier,
                      ),
                      React.createElement('td', { className: 'px-4 py-3 text-xs text-noctis-dim font-mono' },
                        new Date(s.createdAt).toLocaleDateString(),
                      ),
                      React.createElement('td', { className: 'px-4 py-3' },
                        tab === 'discovered'
                          ? React.createElement('button', {
                              onClick: () => handleApprove(s.id),
                              className: 'flex items-center gap-1.5 px-3 py-1 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400 hover:bg-green-500/20 cursor-pointer transition-colors duration-200'
                            },
                              React.createElement(Check, { className: 'w-3 h-3' }),
                              'Approve',
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
            React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
              `No ${tab} sources.`,
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
        className: 'relative border border-noctis-border/50 rounded p-6 w-full max-w-md z-10'
      },
        React.createElement('div', { className: 'flex items-center justify-between mb-5' },
          React.createElement('h2', { className: 'font-heading font-semibold text-lg' }, 'Add Source'),
          React.createElement('button', {
            type: 'button',
            onClick: () => setShowModal(false),
            className: 'p-1 hover:bg-noctis-surface2 rounded cursor-pointer transition-colors duration-150'
          },
            React.createElement(X, { className: 'w-4 h-4 text-noctis-dim' }),
          ),
        ),

        React.createElement('div', { className: 'space-y-4' },
          React.createElement('div', null,
            React.createElement('label', { className: 'block text-sm text-noctis-muted mb-1.5' }, 'Type'),
            React.createElement('select', {
              value: newType,
              onChange: e => setNewType(e.target.value),
              className: 'w-full px-3 py-2.5 bg-noctis-bg border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
            },
              SOURCE_TYPES.map(t =>
                React.createElement('option', { key: t.value, value: t.value }, t.label)
              ),
            ),
          ),
          React.createElement('div', null,
            React.createElement('label', { className: 'block text-sm text-noctis-muted mb-1.5' }, 'Identifier'),
            React.createElement('input', {
              type: 'text',
              value: newIdentifier,
              onChange: e => setNewIdentifier(e.target.value),
              placeholder: 'e.g., t.me/channel_name or https://...',
              className: 'w-full px-3 py-2.5 bg-noctis-bg border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple font-mono transition-colors duration-200'
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
  )
}
