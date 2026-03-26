import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import { AlertTriangle, Loader } from 'lucide-react'

// ── Pipeline stage mapping (module IDs from internal/modules/status.go) ──

const PIPELINE_STAGES = [
  {
    key: 'collect',
    label: 'Collect',
    ids: new Set([
      'collector.telegram', 'collector.rss', 'collector.paste',
      'collector.forum', 'collector.leaksite', 'collector.specter',
    ]),
  },
  {
    key: 'classify',
    label: 'Classify',
    ids: new Set(['processor.classifier']),
  },
  {
    key: 'process',
    label: 'Process',
    ids: new Set([
      'processor.summarizer', 'processor.ioc_extractor',
      'processor.entity_extractor', 'processor.graph_bridge',
      'processor.librarian', 'processor.ioc_lifecycle',
    ]),
  },
  {
    key: 'analyze',
    label: 'Analyze',
    ids: new Set([
      'brain.correlator', 'brain.analyst', 'brain.brief_generator',
      'brain.query_engine', 'brain.attributor',
    ]),
  },
  {
    key: 'enrich',
    label: 'Enrich',
    ids: new Set([
      'processor.enrichment', 'infra.vuln_ingestor', 'infra.source_analyzer',
    ]),
  },
]

const ON_DEMAND = new Set(['brain.query_engine'])
const SCHEDULED = { 'brain.brief_generator': '06:00 UTC' }
const HIDDEN = new Set(['infra.dashboard', 'infra.discovery'])

const DISPLAY_NAMES = {
  'collector.telegram': 'Telegram', 'collector.rss': 'RSS', 'collector.paste': 'Paste',
  'collector.forum': 'Forum', 'collector.leaksite': 'Leak Site', 'collector.specter': 'Specter',
  'processor.classifier': 'Classifier', 'processor.summarizer': 'Summarizer',
  'processor.ioc_extractor': 'IOC Extractor', 'processor.entity_extractor': 'Entity Extractor',
  'processor.graph_bridge': 'Graph Bridge', 'processor.librarian': 'Librarian',
  'processor.ioc_lifecycle': 'IOC Lifecycle', 'brain.correlator': 'Correlator',
  'brain.analyst': 'Analyst', 'brain.brief_generator': 'Brief Generator',
  'brain.query_engine': 'Query Engine', 'brain.attributor': 'Attributor',
  'processor.enrichment': 'Enrichment', 'infra.vuln_ingestor': 'Vuln Ingestor',
  'infra.source_analyzer': 'Source Analyzer',
}

const PROVIDER_BADGE = {
  groq: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
  glm: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  gemini: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
}

const STATUS_DOT = {
  running: 'bg-green-400',
  degraded: 'bg-yellow-400',
  down: 'bg-red-400',
  idle: 'bg-noctis-dim',
  disabled: 'bg-gray-600',
}

// ── Helpers ──────────────────────────────────────────────────────────────

function timeAgo(ts) {
  if (!ts) return 'Never'
  const d = new Date(ts)
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return 'Never'
  const s = Math.floor((Date.now() - d.getTime()) / 1000)
  if (s < 0) return 'Just now'
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function fmtNum(n) {
  if (n == null) return '0'
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K'
  return String(n)
}

function modStatus(mod) {
  if (!mod.enabled) return { s: 'disabled', label: 'Disabled' }

  if (ON_DEMAND.has(mod.id)) {
    if (mod.last_error) return { s: 'degraded', label: 'Error' }
    if (!mod.total_processed && !mod.total_errors) return { s: 'idle', label: 'Ready' }
    return { s: 'running', label: fmtNum(mod.total_processed) }
  }

  if (SCHEDULED[mod.id]) {
    if (mod.last_error) return { s: 'degraded', label: 'Error' }
    if (mod.running || !mod.total_errors) {
      const label = mod.total_processed > 0
        ? `${fmtNum(mod.total_processed)} \u00b7 next ${SCHEDULED[mod.id]}`
        : `Next ${SCHEDULED[mod.id]}`
      return { s: 'running', label }
    }
  }

  if (!mod.running) return { s: 'down', label: 'Down' }
  if (mod.last_error) return { s: 'degraded', label: 'Error' }
  return { s: 'running', label: fmtNum(mod.total_processed) }
}

function flattenMods(byCategory) {
  const m = {}
  for (const list of Object.values(byCategory))
    for (const mod of list)
      if (!HIDDEN.has(mod.id)) m[mod.id] = mod
  return m
}

function buildStages(modMap) {
  return PIPELINE_STAGES.map(st => ({
    ...st,
    modules: [...st.ids].filter(id => modMap[id]).map(id => modMap[id]),
  }))
}

// ── Arrow connector ──────────────────────────────────────────────────────

function Arrow() {
  return React.createElement('div', {
    className: 'flex items-center justify-center self-stretch shrink-0 px-0 py-1 md:py-0 md:px-1.5',
  },
    React.createElement('svg', {
      className: 'w-5 h-5 text-noctis-dim/40 rotate-90 md:rotate-0',
      viewBox: '0 0 20 20',
      fill: 'none',
    },
      React.createElement('path', {
        d: 'M4 10h12M12 6l4 4-4 4',
        stroke: 'currentColor',
        strokeWidth: 1.5,
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
      }),
    ),
  )
}

// ── Health banner ────────────────────────────────────────────────────────

function HealthBanner({ modMap, lastUpdated }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => tick(n => n + 1), 1000)
    return () => clearInterval(t)
  }, [])

  const all = Object.values(modMap)
  const enabled = all.filter(m => m.enabled)
  const down = [], degraded = []
  for (const m of enabled) {
    const { s } = modStatus(m)
    if (s === 'down') down.push(m)
    else if (s === 'degraded') degraded.push(m)
  }

  let dotCls, text, bgCls
  if (down.length) {
    dotCls = 'bg-red-400'
    text = down.length === 1 ? `${down[0].name} is down` : `${down.length} modules are down`
    bgCls = 'bg-red-500/5 border-red-500/20'
  } else if (degraded.length) {
    dotCls = 'bg-yellow-400'
    text = `${degraded.length} of ${enabled.length} modules have issues`
    bgCls = 'bg-yellow-500/5 border-yellow-500/20'
  } else {
    dotCls = 'bg-green-400'
    text = 'All systems operational'
    bgCls = 'bg-green-500/5 border-green-500/20'
  }

  const ago = lastUpdated
    ? `Updated ${Math.floor((Date.now() - lastUpdated) / 1000)}s ago`
    : null

  return React.createElement('div', {
    className: `flex items-center justify-between px-4 py-2.5 rounded-lg border ${bgCls}`,
  },
    React.createElement('div', { className: 'flex items-center gap-2.5' },
      React.createElement('span', {
        className: `inline-block w-2 h-2 rounded-full ${dotCls}`,
      }),
      React.createElement('span', { className: 'text-sm text-noctis-text' }, text),
    ),
    ago && React.createElement('span', {
      className: 'text-[11px] text-noctis-dim font-mono',
    }, ago),
  )
}

// ── Module card ──────────────────────────────────────────────────────────

function ModuleCard({ mod, isExpanded, onToggle }) {
  const { s, label } = modStatus(mod)
  const dot = STATUS_DOT[s]
  const name = (mod.name && mod.name.trim()) || DISPLAY_NAMES[mod.id] || mod.id.split('.').pop().replace(/_/g, ' ')
  const badge = mod.ai_provider ? PROVIDER_BADGE[mod.ai_provider] : null
  const extras = mod.extra ? Object.entries(mod.extra) : []
  const hasDetail = mod.worker_count > 0 || mod.last_error || extras.length > 0 || mod.last_activity_at
  const borderAccent = s === 'degraded' ? 'border-l-yellow-400/70' : s === 'down' ? 'border-l-red-400/70' : 'border-l-transparent'

  return React.createElement('div', {
    className: `rounded-md border border-white/[0.06] border-l-2 ${borderAccent} bg-white/[0.03] py-2 px-2.5 ${hasDetail ? 'cursor-pointer hover:bg-white/[0.06] hover:border-white/[0.1]' : ''} transition-colors duration-150`,
    onClick: hasDetail ? onToggle : undefined,
  },
    // Row 1: identity
    React.createElement('div', { className: 'flex items-center gap-1.5' },
      React.createElement('span', {
        className: `inline-block w-[7px] h-[7px] rounded-full shrink-0 transition-colors duration-200 ${dot}`,
      }),
      React.createElement('span', {
        className: 'text-[13px] font-medium text-noctis-text truncate md:truncate',
        title: name,
      }, name),
      badge && React.createElement('span', {
        className: `inline-flex items-center px-1 py-0 text-[9px] font-mono rounded border leading-4 shrink-0 ${badge}`,
      }, mod.ai_provider),
    ),

    // Row 2: stats
    React.createElement('div', {
      className: 'flex items-center justify-between mt-1.5 text-[11px] font-mono text-noctis-dim',
    },
      React.createElement('span', null, label),
      mod.last_activity_at && React.createElement('span', null, timeAgo(mod.last_activity_at)),
    ),

    // Expanded detail
    isExpanded && React.createElement('div', {
      className: 'mt-2 pt-2 border-t border-white/[0.05] space-y-1 text-[11px]',
    },
      mod.worker_count > 0 && React.createElement('div', {
        className: 'flex justify-between text-noctis-dim',
      },
        React.createElement('span', null, 'Workers'),
        React.createElement('span', { className: 'font-mono text-noctis-muted' }, mod.worker_count),
      ),
      mod.total_errors > 0 && React.createElement('div', {
        className: 'flex justify-between text-noctis-dim',
      },
        React.createElement('span', null, 'Errors'),
        React.createElement('span', {
          className: `font-mono ${mod.total_errors > 10 ? 'text-red-400' : 'text-yellow-400'}`,
        }, fmtNum(mod.total_errors)),
      ),
      mod.last_error && React.createElement('div', {
        className: 'text-red-400/80 break-words mt-0.5',
      },
        React.createElement(AlertTriangle, { className: 'w-3 h-3 inline mr-1 align-text-bottom' }),
        mod.last_error.length > 120 ? mod.last_error.slice(0, 117) + '\u2026' : mod.last_error,
      ),
      extras.map(([k, v]) =>
        React.createElement('div', {
          key: k, className: 'flex justify-between text-noctis-dim',
        },
          React.createElement('span', null, k.replace(/_/g, ' ')),
          React.createElement('span', { className: 'font-mono text-noctis-muted' }, String(v)),
        ),
      ),
    ),
  )
}

// ── Spending bar (Gemini budget) ─────────────────────────────────────────

function SpendingBar({ spending }) {
  if (!spending) return null
  const cost = spending.estimated_cost_usd || 0
  const limit = spending.budget_limit_usd || 0

  if (limit <= 0) {
    return React.createElement('div', {
      className: 'px-3 py-2 border-t border-white/[0.05] flex justify-between text-[11px] text-noctis-dim',
    },
      React.createElement('span', null, 'Gemini'),
      React.createElement('span', { className: 'font-mono' }, `$${cost.toFixed(2)}`),
    )
  }

  const pct = (cost / limit) * 100
  const bar = pct > 80 ? 'bg-red-400' : pct > 60 ? 'bg-yellow-400' : 'bg-green-400'

  return React.createElement('div', {
    className: 'px-3 py-2 border-t border-white/[0.05]',
  },
    React.createElement('div', {
      className: 'flex justify-between text-[11px] text-noctis-dim mb-1',
    },
      React.createElement('span', null, 'Gemini'),
      React.createElement('span', { className: 'font-mono' },
        `$${cost.toFixed(2)} / $${limit.toFixed(2)}`,
      ),
    ),
    React.createElement('div', {
      className: 'w-full h-[3px] rounded-full bg-white/[0.06]',
    },
      React.createElement('div', {
        className: `h-full rounded-full transition-all duration-500 ${bar}`,
        style: { width: `${Math.min(100, pct)}%` },
      }),
    ),
  )
}

// ── Stage box ────────────────────────────────────────────────────────────

function StageBox({ stage, expanded, onToggle, spending }) {
  if (!stage.modules.length) return null

  return React.createElement('div', {
    className: 'border border-white/[0.08] rounded-lg bg-noctis-surface/50 md:flex-1 md:min-w-0 md:min-h-[280px] w-full',
  },
    React.createElement('div', {
      className: 'px-3 py-2 border-b border-white/[0.06]',
    },
      React.createElement('span', {
        className: 'text-[11px] font-semibold uppercase tracking-[0.1em] text-noctis-dim',
      }, stage.label),
    ),
    React.createElement('div', {
      className: 'p-2.5 flex flex-col gap-1.5',
    },
      stage.modules.map(mod =>
        React.createElement(ModuleCard, {
          key: mod.id,
          mod,
          isExpanded: expanded.has(mod.id),
          onToggle: () => onToggle(mod.id),
        }),
      ),
    ),
    spending && React.createElement(SpendingBar, { spending }),
  )
}

// ── Main component ───────────────────────────────────────────────────────

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
    const ctrl = new AbortController()
    abortRef.current = ctrl
    try {
      const res = await fetch('/api/system/status', {
        signal: ctrl.signal,
        headers: { Authorization: `Bearer ${apiKey}` },
      })
      if (res.status === 401) { logout(); return }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setData(await res.json())
      setError(null)
      setLastUpdated(Date.now())
    } catch (e) {
      if (e.name !== 'AbortError') setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [apiKey, logout])

  useEffect(() => {
    fetchData()
    const iv = setInterval(fetchData, 10000)
    return () => { clearInterval(iv); abortRef.current?.abort() }
  }, [fetchData])

  const modMap = data?.modules ? flattenMods(data.modules) : {}
  const stages = buildStages(modMap)
  const visible = stages.filter(st => st.modules.length > 0)

  const pipeline = visible.flatMap((st, i) => {
    const els = []
    if (i > 0) els.push(React.createElement(Arrow, { key: `arrow-${i}` }))
    els.push(React.createElement(StageBox, {
      key: st.key,
      stage: st,
      expanded,
      onToggle: toggleExpand,
      spending: st.key === 'analyze' ? data?.gemini_spending : null,
    }))
    return els
  })

  return React.createElement('div', { className: 'space-y-5 -mx-2 md:mx-0' },
    React.createElement('h1', {
      className: 'font-heading font-normal text-xl',
    }, 'System Status'),

    loading && !data && React.createElement('div', {
      className: 'flex items-center justify-center py-20 text-noctis-dim',
    },
      React.createElement(Loader, { className: 'w-5 h-5 animate-spin mr-2' }),
      'Loading system status\u2026',
    ),

    error && React.createElement('div', {
      className: 'border border-red-500/30 rounded p-4 text-sm text-red-400',
    }, 'Failed to load system status: ', error),

    !loading && data && !data.available && React.createElement('div', {
      className: 'border border-white/[0.08] rounded p-8 text-center text-noctis-dim text-sm',
    }, 'Module status tracking is not available.'),

    data?.available && React.createElement(HealthBanner, { modMap, lastUpdated }),

    data?.available && React.createElement('div', {
      className: 'flex flex-col md:flex-row md:items-stretch gap-1 md:gap-0 overflow-x-auto',
    }, pipeline),
  )
}
