import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import {
  Activity, Radio, Cpu, Brain, GitBranch,
  AlertTriangle, Loader, ChevronDown, ChevronRight, RefreshCw
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

function formatNumber(n) {
  if (n == null) return '0'
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return String(n)
}

// Determine module health: 'healthy', 'degraded', 'down', 'disabled'
function moduleHealth(mod) {
  if (!mod.enabled) return 'disabled'
  if (!mod.running) return 'down'
  if (mod.last_error) return 'degraded'
  return 'healthy'
}

const DOT_COLORS = {
  healthy: 'bg-green-400',
  degraded: 'bg-yellow-400',
  down: 'bg-red-400',
  disabled: 'bg-gray-500',
}

const STATUS_COLORS = {
  healthy: 'text-noctis-muted',
  degraded: 'text-yellow-400/80',
  down: 'text-red-400/80',
  disabled: 'text-noctis-dim',
}

const BORDER_ACCENT = {
  down: 'border-l-2 border-l-red-400',
  degraded: 'border-l-2 border-l-yellow-400',
}

function statusText(mod, health) {
  switch (health) {
    case 'disabled': return 'Disabled'
    case 'down': return 'Down'
    case 'degraded': {
      const err = mod.last_error || 'unknown error'
      return err.length > 60 ? 'Error: ' + err.slice(0, 57) + '\u2026' : 'Error: ' + err
    }
    case 'healthy':
      return mod.total_processed > 0
        ? `Running \u2014 ${formatNumber(mod.total_processed)} processed`
        : 'Running'
    default: return 'Unknown'
  }
}

// Small component that re-renders independently for the "Updated Xs ago" text
function UpdatedAgo({ timestamp }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => tick(n => n + 1), 5000)
    return () => clearInterval(t)
  }, [])
  if (!timestamp) return null
  return React.createElement('div', {
    className: 'flex items-center gap-1.5 text-[11px] text-noctis-dim'
  },
    React.createElement(RefreshCw, { className: 'w-3 h-3' }),
    `Updated ${timeAgo(new Date(timestamp).toISOString())}`,
  )
}

function healthBanner(modules) {
  const allMods = Object.values(modules).flat()
  const enabled = allMods.filter(m => m.enabled)
  const down = enabled.filter(m => !m.running)
  const degraded = enabled.filter(m => m.running && m.last_error)

  let dotColor, text
  if (down.length > 0) {
    dotColor = 'bg-red-400'
    text = down.length === 1
      ? `${down[0].name} is down`
      : `${down.length} modules are down`
  } else if (degraded.length > 0) {
    dotColor = 'bg-yellow-400'
    text = `${degraded.length} of ${enabled.length} modules have issues`
  } else {
    dotColor = 'bg-green-400'
    text = 'All systems operational'
  }

  return React.createElement('div', {
    className: 'flex items-center gap-3 px-4 py-3 rounded border border-noctis-border/50 bg-noctis-surface'
  },
    React.createElement('span', { className: `inline-block w-2.5 h-2.5 rounded-full ${dotColor}` }),
    React.createElement('span', { className: 'text-sm text-noctis-text' }, text),
  )
}

function ModuleCard({ mod, expanded, onToggle }) {
  const health = moduleHealth(mod)
  const extraEntries = mod.extra ? Object.entries(mod.extra) : []
  const hasDetails = mod.worker_count > 0 || mod.queue_depth > 0 || mod.last_error || extraEntries.length > 0

  const borderClass = BORDER_ACCENT[health] || ''

  return React.createElement('div', {
    className: `border border-noctis-border/50 rounded p-4 hover:border-noctis-border transition-colors duration-200 ${borderClass}`,
  },
    // Row 1: dot + name + chevron
    React.createElement('div', {
      className: `flex items-center gap-2.5 ${hasDetails ? 'cursor-pointer select-none' : ''}`,
      onClick: hasDetails ? onToggle : undefined,
    },
      React.createElement('span', { className: `inline-block w-2 h-2 rounded-full ${DOT_COLORS[health]}` }),
      React.createElement('span', { className: 'text-sm font-medium text-noctis-text flex-1' }, mod.name),
      hasDetails && React.createElement(
        expanded ? ChevronDown : ChevronRight,
        { className: 'w-3.5 h-3.5 text-noctis-dim' }
      ),
    ),

    // Row 2: status one-liner
    React.createElement('div', {
      className: `text-xs mt-1.5 ml-[18px] ${STATUS_COLORS[health]}`,
      title: health === 'degraded' ? mod.last_error : undefined,
    }, statusText(mod, health)),

    // Row 3: AI badge + last active
    React.createElement('div', { className: 'flex items-center gap-3 mt-2 ml-[18px]' },
      mod.ai_provider && React.createElement('span', {
        className: 'inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono rounded bg-noctis-purple/10 border border-noctis-purple/30 text-noctis-purple-light'
      }, mod.ai_provider),
      React.createElement('span', { className: 'text-[11px] text-noctis-dim' },
        timeAgo(mod.last_activity_at),
      ),
    ),

    // Expanded details (slide-down)
    expanded && React.createElement('div', {
      className: 'mt-3 ml-[18px] pt-3 border-t border-noctis-border/30 space-y-1.5 animate-expand-down'
    },
      mod.total_processed > 0 && React.createElement('div', {
        className: 'text-[11px] text-noctis-dim flex justify-between'
      },
        React.createElement('span', null, 'Processed'),
        React.createElement('span', { className: 'font-mono text-noctis-muted' }, formatNumber(mod.total_processed)),
      ),
      mod.total_errors > 0 && React.createElement('div', {
        className: 'text-[11px] text-noctis-dim flex justify-between'
      },
        React.createElement('span', null, 'Errors'),
        React.createElement('span', { className: 'font-mono text-red-400' }, formatNumber(mod.total_errors)),
      ),
      mod.worker_count > 0 && React.createElement('div', {
        className: 'text-[11px] text-noctis-dim flex justify-between'
      },
        React.createElement('span', null, 'Workers'),
        React.createElement('span', { className: 'font-mono text-noctis-muted' }, mod.worker_count),
      ),
      mod.queue_depth > 0 && React.createElement('div', {
        className: 'text-[11px] text-noctis-dim flex justify-between'
      },
        React.createElement('span', null, 'Queue'),
        React.createElement('span', { className: 'font-mono text-noctis-muted' }, `${mod.queue_depth} items`),
      ),
      mod.last_error && React.createElement('div', {
        className: 'mt-1.5 text-[11px] text-red-400/80 break-words'
      },
        React.createElement(AlertTriangle, { className: 'w-3 h-3 inline mr-1 align-text-bottom' }),
        mod.last_error,
      ),
      extraEntries.length > 0 && extraEntries.map(([k, v]) =>
        React.createElement('div', {
          key: k, className: 'text-[11px] text-noctis-dim flex justify-between'
        },
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
  const [expanded, setExpanded] = useState(new Set())
  const [lastUpdated, setLastUpdated] = useState(null)
  const abortRef = useRef(null)

  const toggleExpand = useCallback((id) => {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }, [])

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
      setLastUpdated(Date.now())
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

  return React.createElement('div', { className: 'space-y-6' },
    // Header row with refresh indicator
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'System Status'),
      React.createElement(UpdatedAgo, { timestamp: lastUpdated }),
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

    // Health banner
    !loading && data?.available && healthBanner(mods),

    // Sections grouped by category
    !loading && data?.available && CATEGORY_ORDER.filter(cat => mods[cat]?.length > 0).map(cat => {
      const meta = CATEGORY_META[cat] || { title: cat, icon: Activity }
      const Icon = meta.icon
      const items = mods[cat]
      const enabledItems = items.filter(m => m.enabled)
      const healthyCt = enabledItems.filter(m => moduleHealth(m) === 'healthy').length
      const sectionDot = enabledItems.length === 0 ? 'bg-gray-500'
        : healthyCt === enabledItems.length ? 'bg-green-400'
        : healthyCt > 0 ? 'bg-yellow-400'
        : 'bg-red-400'

      return React.createElement('div', { key: cat },
        // Section header with aggregate health
        React.createElement('div', { className: 'flex items-center gap-2 mb-3' },
          React.createElement(Icon, { className: 'w-4 h-4 text-noctis-purple' }),
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-text' }, meta.title),
          React.createElement('span', { className: 'text-xs text-noctis-dim' },
            `\u2014 ${healthyCt}/${enabledItems.length} healthy`,
          ),
          React.createElement('span', {
            className: `inline-block w-1.5 h-1.5 rounded-full ${sectionDot}`
          }),
        ),
        // Card grid
        React.createElement('div', {
          className: 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3'
        },
          items.map(mod => React.createElement(ModuleCard, {
            key: mod.id,
            mod,
            expanded: expanded.has(mod.id),
            onToggle: () => toggleExpand(mod.id),
          })),
        ),
      )
    }),
  )
}
