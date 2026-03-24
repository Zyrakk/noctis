import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import {
  Activity, Radio, FileText, Globe, Rss,
  Cpu, Brain, GitBranch, AlertTriangle, Loader
} from 'lucide-react'

const CATEGORY_META = {
  collector: { title: 'Collectors', icon: Radio },
  processor: { title: 'Processing Engine', icon: Cpu },
  brain: { title: 'Intelligence Brain', icon: Brain },
  infra: { title: 'Infrastructure', icon: GitBranch },
}

const CATEGORY_ORDER = ['collector', 'processor', 'brain', 'infra']

function timeAgo(isoString) {
  if (!isoString) return 'Never'
  const t = new Date(isoString)
  if (isNaN(t.getTime()) || t.getFullYear() < 2000) return 'Never'
  const secs = Math.floor((Date.now() - t.getTime()) / 1000)
  if (secs < 0) return 'Just now'
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

function statusDot(running, enabled) {
  if (!enabled) return React.createElement('span', { className: 'inline-block w-2 h-2 rounded-full bg-gray-500' })
  if (running) return React.createElement('span', { className: 'inline-block w-2 h-2 rounded-full bg-green-400' })
  return React.createElement('span', { className: 'inline-block w-2 h-2 rounded-full bg-red-400' })
}

function aiBadge(provider, model) {
  if (!provider) return null
  return React.createElement('span', {
    className: 'inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono rounded bg-noctis-purple/10 border border-noctis-purple/30 text-noctis-purple-light'
  }, `${provider} / ${model}`)
}

function formatNumber(n) {
  if (n == null) return '0'
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return String(n)
}

function moduleCard(mod) {
  const extraEntries = mod.extra ? Object.entries(mod.extra) : []

  return React.createElement('div', {
    key: mod.id,
    className: 'border border-noctis-border/50 rounded p-4 hover:border-noctis-border transition-colors duration-200'
  },
    // Top row: status + name
    React.createElement('div', { className: 'flex items-center gap-2.5 mb-3' },
      statusDot(mod.running, mod.enabled),
      React.createElement('span', { className: 'text-sm font-medium text-noctis-text' }, mod.name),
      !mod.enabled && React.createElement('span', { className: 'text-[10px] text-noctis-dim' }, '(disabled)'),
    ),

    // AI badge
    aiBadge(mod.ai_provider, mod.ai_model),

    // Stats row
    React.createElement('div', { className: 'flex items-center gap-4 mt-3 text-xs' },
      React.createElement('div', { className: 'text-noctis-muted' },
        React.createElement('span', { className: 'text-noctis-text font-mono' }, formatNumber(mod.total_processed)),
        ' processed',
      ),
      mod.total_errors > 0 && React.createElement('div', { className: 'text-red-400' },
        React.createElement('span', { className: 'font-mono' }, formatNumber(mod.total_errors)),
        ' errors',
      ),
    ),

    // Activity
    React.createElement('div', { className: 'mt-2 text-[11px] text-noctis-dim' },
      'Last active: ', timeAgo(mod.last_activity_at),
    ),

    // Queue depth
    mod.queue_depth > 0 && React.createElement('div', { className: 'mt-1 text-[11px] text-noctis-dim' },
      'Queue: ', React.createElement('span', { className: 'font-mono text-noctis-muted' }, mod.queue_depth), ' items',
    ),

    // Worker count
    mod.worker_count > 0 && React.createElement('div', { className: 'mt-1 text-[11px] text-noctis-dim' },
      'Workers: ', React.createElement('span', { className: 'font-mono text-noctis-muted' }, mod.worker_count),
    ),

    // Last error
    mod.last_error && React.createElement('div', { className: 'mt-2 text-[11px] text-red-400/80 truncate', title: mod.last_error },
      React.createElement(AlertTriangle, { className: 'w-3 h-3 inline mr-1 align-text-bottom' }),
      mod.last_error.length > 80 ? mod.last_error.slice(0, 80) + '...' : mod.last_error,
    ),

    // Extra data
    extraEntries.length > 0 && React.createElement('div', { className: 'mt-2 pt-2 border-t border-noctis-border/30 space-y-0.5' },
      extraEntries.map(([k, v]) =>
        React.createElement('div', { key: k, className: 'text-[11px] text-noctis-dim flex justify-between' },
          React.createElement('span', null, k.replace(/_/g, ' ')),
          React.createElement('span', { className: 'font-mono text-noctis-muted' }, String(v)),
        )
      ),
    ),
  )
}

export default function SystemStatus() {
  const { apiKey, logout } = useAuth()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const abortRef = useRef(null)

  const fetchData = useCallback(async () => {
    if (!apiKey) return
    if (abortRef.current) abortRef.current.abort()
    const controller = new AbortController()
    abortRef.current = controller

    try {
      const res = await fetch('/api/system/status', {
        signal: controller.signal,
        headers: { 'Authorization': `Bearer ${apiKey}` },
      })
      if (res.status === 401) { logout(); return }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setData(json)
      setError(null)
    } catch (err) {
      if (err.name !== 'AbortError') setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [apiKey, logout])

  // Initial fetch + 10s polling
  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000)
    return () => {
      clearInterval(interval)
      if (abortRef.current) abortRef.current.abort()
    }
  }, [fetchData])

  const mods = data?.modules || {}

  // Count totals for header
  let totalRunning = 0
  let totalModules = 0
  for (const cat of Object.values(mods)) {
    for (const m of cat) {
      totalModules++
      if (m.running) totalRunning++
    }
  }

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'System Status'),
      !loading && data?.available && React.createElement('span', { className: 'text-xs text-noctis-dim' },
        `${totalRunning}/${totalModules} modules running`,
      ),
    ),

    // Loading
    loading && React.createElement('div', { className: 'flex items-center justify-center py-20 text-noctis-dim' },
      React.createElement(Loader, { className: 'w-5 h-5 animate-spin mr-2' }),
      'Loading system status...',
    ),

    // Error
    error && React.createElement('div', { className: 'border border-red-500/30 rounded p-4 text-sm text-red-400' },
      'Failed to load system status: ', error,
    ),

    // Not available
    !loading && data && !data.available && React.createElement('div', {
      className: 'border border-noctis-border/50 rounded p-8 text-center text-noctis-dim text-sm'
    }, 'Module status tracking is not available.'),

    // Module sections by category
    !loading && data?.available && CATEGORY_ORDER.filter(cat => mods[cat]?.length > 0).map(cat => {
      const meta = CATEGORY_META[cat] || { title: cat, icon: Activity }
      const Icon = meta.icon
      const items = mods[cat]
      return React.createElement('div', { key: cat },
        // Section header
        React.createElement('div', { className: 'flex items-center gap-2 mb-3' },
          React.createElement(Icon, { className: 'w-4 h-4 text-noctis-purple' }),
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-text' }, meta.title),
          React.createElement('span', { className: 'text-xs text-noctis-dim' }, `(${items.length})`),
        ),
        // Card grid
        React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4' },
          items.map(mod => moduleCard(mod)),
        ),
      )
    }),
  )
}
