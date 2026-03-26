import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import { useApi, apiFetch } from '../hooks/useApi.js'
import { Search, Network, ArrowLeft, ChevronRight } from 'lucide-react'

// ── Constants ──────────────────────────────────────────────────────────────────

const NODE_COLORS = {
  channel: '#3b82f6',
  ip: '#eab308',
  domain: '#eab308',
  hash: '#a855f7',
  cve: '#06b6d4',
  url: '#f97316',
  email: '#10b981',
  threat_actor: '#ef4444',
  default: '#6b7280',
}

const DEBOUNCE_MS = 300

// ── Helpers ────────────────────────────────────────────────────────────────────

function entityLabel(entity) {
  return entity.properties?.name || entity.properties?.value || entity.id
}

function formatDate(dateStr) {
  if (!dateStr) return ''
  const d = new Date(dateStr)
  if (isNaN(d.getTime())) return ''
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function nodeColor(type) {
  return NODE_COLORS[type] || NODE_COLORS.default
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function Graph() {
  const { apiKey } = useAuth()
  const canvasRef = useRef(null)
  const nodesRef = useRef([])
  const tooltipTimeoutRef = useRef(null)

  // Shared state
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [hops, setHops] = useState(2)

  // Entity list state
  const [selectedEntityId, setSelectedEntityId] = useState(null)

  // Graph state
  const [graphData, setGraphData] = useState(null)
  const [graphLoading, setGraphLoading] = useState(false)
  const [graphError, setGraphError] = useState(null)

  // Tooltip state
  const [hoveredNode, setHoveredNode] = useState(null)
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })

  // ── Debounce search query ──

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query), DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [query])

  // ── Fetch entity list ──

  const entitiesUrl = useMemo(() => {
    const params = new URLSearchParams({ limit: '20', offset: '0' })
    if (debouncedQuery.trim()) params.set('q', debouncedQuery.trim())
    return `/api/entities?${params.toString()}`
  }, [debouncedQuery])

  const { data: entitiesData, loading: entitiesLoading } = useApi(entitiesUrl)

  const entities = entitiesData?.entities || []
  const totalEntities = entitiesData?.total ?? null

  // ── Fetch graph ──

  const fetchGraph = useCallback(async (entityId) => {
    if (!entityId) return
    setSelectedEntityId(entityId)
    setGraphLoading(true)
    setGraphError(null)
    setGraphData(null)
    setHoveredNode(null)
    try {
      const data = await apiFetch(apiKey, `/api/graph?entity_id=${encodeURIComponent(entityId)}&hops=${hops}`)
      setGraphData(data)
    } catch (err) {
      setGraphError(err.message)
      setGraphData(null)
    }
    setGraphLoading(false)
  }, [apiKey, hops])

  // Re-fetch graph when hops change and an entity is selected
  useEffect(() => {
    if (selectedEntityId) {
      fetchGraph(selectedEntityId)
    }
  }, [hops]) // intentionally only depend on hops — fetchGraph identity changes too but we only want hops triggers

  const goBackToList = useCallback(() => {
    setSelectedEntityId(null)
    setGraphData(null)
    setGraphError(null)
    setHoveredNode(null)
  }, [])

  // ── Canvas rendering with force simulation ──

  useEffect(() => {
    if (!graphData || !graphData.nodes?.length || !canvasRef.current) return

    let animFrame
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    const width = canvas.offsetWidth
    const height = canvas.offsetHeight
    canvas.width = width * 2
    canvas.height = height * 2
    ctx.scale(2, 2)

    // Build simulation data
    const nodes = graphData.nodes.map(n => ({
      ...n,
      x: width / 2 + (Math.random() - 0.5) * 200,
      y: height / 2 + (Math.random() - 0.5) * 200,
      vx: 0,
      vy: 0,
    }))

    // Store nodes ref for click/hover detection
    nodesRef.current = nodes

    const nodeMap = new Map(nodes.map(n => [n.id, n]))

    const links = graphData.edges
      .filter(e => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map(e => ({
        source: nodeMap.get(e.source),
        target: nodeMap.get(e.target),
        relationship: e.relationship,
      }))

    // Count connections per node and store on node objects for tooltip
    for (const n of nodes) n._connectionCount = 0
    for (const l of links) {
      l.source._connectionCount = (l.source._connectionCount || 0) + 1
      l.target._connectionCount = (l.target._connectionCount || 0) + 1
    }

    const alpha = { value: 1 }

    function tick() {
      alpha.value *= 0.99

      // Repulsion between nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x
          const dy = nodes[j].y - nodes[i].y
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          const force = (200 * alpha.value) / (dist * dist)
          nodes[i].vx -= (dx / dist) * force
          nodes[i].vy -= (dy / dist) * force
          nodes[j].vx += (dx / dist) * force
          nodes[j].vy += (dy / dist) * force
        }
      }

      // Link attraction
      for (const link of links) {
        const dx = link.target.x - link.source.x
        const dy = link.target.y - link.source.y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (dist - 120) * 0.01 * alpha.value
        link.source.vx += (dx / dist) * force
        link.source.vy += (dy / dist) * force
        link.target.vx -= (dx / dist) * force
        link.target.vy -= (dy / dist) * force
      }

      // Center gravity
      for (const n of nodes) {
        n.vx += (width / 2 - n.x) * 0.001 * alpha.value
        n.vy += (height / 2 - n.y) * 0.001 * alpha.value
        n.vx *= 0.9
        n.vy *= 0.9
        n.x += n.vx
        n.y += n.vy
        n.x = Math.max(30, Math.min(width - 30, n.x))
        n.y = Math.max(30, Math.min(height - 30, n.y))
      }

      // Draw
      ctx.clearRect(0, 0, width, height)

      // Edges
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.2)'
      ctx.lineWidth = 1
      for (const link of links) {
        ctx.beginPath()
        ctx.moveTo(link.source.x, link.source.y)
        ctx.lineTo(link.target.x, link.target.y)
        ctx.stroke()

        const mx = (link.source.x + link.target.x) / 2
        const my = (link.source.y + link.target.y) / 2
        ctx.fillStyle = 'rgba(148, 163, 184, 0.5)'
        ctx.font = '9px Fira Code'
        ctx.textAlign = 'center'
        ctx.fillText(link.relationship, mx, my - 4)
      }

      // Nodes
      for (const n of nodes) {
        const color = nodeColor(n.type)
        const isCenter = n.id === selectedEntityId
        const radius = isCenter ? 10 : 8
        const glowRadius = isCenter ? 15 : 12

        // Glow
        ctx.beginPath()
        ctx.arc(n.x, n.y, glowRadius, 0, Math.PI * 2)
        ctx.fillStyle = color + '30'
        ctx.fill()

        // Circle
        ctx.beginPath()
        ctx.arc(n.x, n.y, radius, 0, Math.PI * 2)
        ctx.fillStyle = color
        ctx.fill()
        ctx.strokeStyle = color + '60'
        ctx.lineWidth = 2
        ctx.stroke()

        // Label
        ctx.fillStyle = '#e2e8f0'
        ctx.font = '10px Fira Code'
        ctx.textAlign = 'center'
        const label = n.properties?.name || n.properties?.value || n.id.slice(0, 20)
        ctx.fillText(label, n.x, n.y + (isCenter ? 24 : 22))
      }

      if (alpha.value > 0.01) {
        animFrame = requestAnimationFrame(tick)
      }
    }

    tick()

    return () => {
      if (animFrame) cancelAnimationFrame(animFrame)
    }
  }, [graphData, selectedEntityId])

  // ── Canvas mouse handlers (click + hover for tooltip) ──

  const findNodeAtPos = useCallback((e) => {
    const canvas = canvasRef.current
    if (!canvas) return null
    const rect = canvas.getBoundingClientRect()
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const nodes = nodesRef.current

    let closest = null
    let closestDist = Infinity
    for (const n of nodes) {
      const dx = n.x - mx
      const dy = n.y - my
      const dist = Math.sqrt(dx * dx + dy * dy)
      if (dist < 20 && dist < closestDist) {
        closest = n
        closestDist = dist
      }
    }
    return closest
  }, [])

  const handleCanvasClick = useCallback((e) => {
    const node = findNodeAtPos(e)
    if (node && node.id !== selectedEntityId) {
      setQuery('')
      fetchGraph(node.id)
    }
  }, [findNodeAtPos, selectedEntityId, fetchGraph])

  const handleCanvasMouseMove = useCallback((e) => {
    const node = findNodeAtPos(e)
    if (node) {
      const canvas = canvasRef.current
      const rect = canvas.getBoundingClientRect()
      setTooltipPos({ x: e.clientX - rect.left, y: e.clientY - rect.top })
      setHoveredNode(node)
      canvas.style.cursor = 'pointer'
    } else {
      setHoveredNode(null)
      if (canvasRef.current) canvasRef.current.style.cursor = 'default'
    }
  }, [findNodeAtPos])

  const handleCanvasMouseLeave = useCallback(() => {
    setHoveredNode(null)
  }, [])

  // ── Render: Entity List View ──

  if (!selectedEntityId) {
    return React.createElement('div', { className: 'space-y-6' },
      // Header
      React.createElement('div', { className: 'flex items-center justify-between' },
        React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Entity Graph'),
      ),

      // Search bar
      React.createElement('div', { className: 'relative max-w-xl' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: query,
          onChange: e => setQuery(e.target.value),
          onKeyDown: e => {
            if (e.key === 'Enter' && entities.length > 0) {
              fetchGraph(entities[0].id)
            }
          },
          placeholder: 'Search for an entity (actor, domain, IP, CVE...)',
          className: 'w-full pl-9 pr-3 py-2.5 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple font-mono transition-colors duration-200',
        }),
      ),

      // Entity list
      entitiesLoading
        ? React.createElement('div', { className: 'flex items-center justify-center py-16 text-noctis-dim text-sm' },
            'Loading entities...',
          )
        : totalEntities === 0 && !debouncedQuery.trim()
          ? React.createElement('div', { className: 'flex flex-col items-center justify-center py-16 text-noctis-dim' },
              React.createElement(Network, { className: 'w-12 h-12 mb-3 opacity-30' }),
              React.createElement('p', { className: 'text-sm text-center max-w-sm' },
                'Entity extraction is processing. Entities will appear as findings are analyzed.',
              ),
            )
          : entities.length === 0
            ? React.createElement('div', { className: 'flex flex-col items-center justify-center py-16 text-noctis-dim' },
                React.createElement(Search, { className: 'w-10 h-10 mb-3 opacity-30' }),
                React.createElement('p', { className: 'text-sm' }, 'No entities found for this search.'),
              )
            : React.createElement('div', { className: 'border border-white/[0.08] rounded-lg overflow-hidden divide-y divide-noctis-border/30' },
                entities.map(entity =>
                  React.createElement('button', {
                    key: entity.id,
                    onClick: () => fetchGraph(entity.id),
                    className: 'w-full flex items-center gap-4 px-4 py-3 hover:bg-noctis-surface/80 transition-colors duration-150 text-left cursor-pointer group',
                  },
                    // Type badge
                    React.createElement('div', { className: 'flex items-center gap-2 min-w-[100px]' },
                      React.createElement('div', {
                        className: 'w-2.5 h-2.5 rounded-full flex-shrink-0',
                        style: { backgroundColor: nodeColor(entity.type) },
                      }),
                      React.createElement('span', {
                        className: 'text-xs text-noctis-muted font-mono',
                      }, entity.type),
                    ),

                    // Entity name
                    React.createElement('span', {
                      className: 'flex-1 text-sm text-noctis-text truncate font-mono',
                    }, entityLabel(entity)),

                    // Edge count
                    React.createElement('span', {
                      className: 'text-xs text-noctis-dim whitespace-nowrap',
                    }, entity.edgeCount === 1 ? '1 connection' : `${entity.edgeCount || 0} connections`),

                    // Created date
                    React.createElement('span', {
                      className: 'text-xs text-noctis-dim whitespace-nowrap min-w-[80px] text-right hidden sm:block',
                    }, formatDate(entity.createdAt)),

                    // Arrow
                    React.createElement(ChevronRight, {
                      className: 'w-4 h-4 text-noctis-dim opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0',
                    }),
                  ),
                ),
              ),
    )
  }

  // ── Render: Graph View ──

  return React.createElement('div', { className: 'space-y-4' },
    // Header with back button
    React.createElement('div', { className: 'flex items-center gap-3' },
      React.createElement('button', {
        onClick: goBackToList,
        className: 'flex items-center gap-1.5 px-3 py-1.5 text-sm text-noctis-muted hover:text-noctis-text border border-white/[0.08] hover:border-noctis-border rounded-lg transition-colors duration-200 cursor-pointer',
      },
        React.createElement(ArrowLeft, { className: 'w-3.5 h-3.5' }),
        'Back to entities',
      ),
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Entity Graph'),
    ),

    // Search + controls
    React.createElement('div', { className: 'flex flex-col sm:flex-row items-stretch sm:items-center gap-3' },
      React.createElement('div', { className: 'relative flex-1 sm:max-w-md' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: query,
          onChange: e => setQuery(e.target.value),
          onKeyDown: e => {
            if (e.key === 'Enter' && query.trim()) {
              fetchGraph(query.trim())
            }
          },
          placeholder: 'Search entity...',
          className: 'w-full pl-9 pr-3 py-2.5 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple font-mono transition-colors duration-200',
        }),
      ),
      React.createElement('select', {
        value: hops,
        onChange: e => setHops(parseInt(e.target.value)),
        className: 'px-3 py-2.5 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple',
      },
        [1, 2, 3, 4, 5].map(h =>
          React.createElement('option', { key: h, value: h }, `${h} hop${h > 1 ? 's' : ''}`)
        ),
      ),
      React.createElement('button', {
        onClick: () => { if (query.trim()) fetchGraph(query.trim()) },
        disabled: graphLoading || !query.trim(),
        className: 'px-4 py-2.5 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 rounded cursor-pointer disabled:opacity-40 transition-all duration-200',
      }, graphLoading ? 'Loading...' : 'Explore'),
    ),

    // Legend
    React.createElement('div', { className: 'flex items-center gap-3 flex-wrap' },
      Object.entries(NODE_COLORS).filter(([k]) => k !== 'default').map(([type, color]) =>
        React.createElement('div', { key: type, className: 'flex items-center gap-1.5 text-xs text-noctis-muted' },
          React.createElement('div', {
            className: 'w-3 h-3 rounded-full',
            style: { backgroundColor: color },
          }),
          type,
        )
      ),
    ),

    // Canvas area
    React.createElement('div', {
      className: 'border border-white/[0.08] rounded overflow-hidden relative',
      style: { height: '500px' },
    },
      graphLoading
        ? React.createElement('div', {
            className: 'absolute inset-0 flex items-center justify-center text-noctis-dim text-sm',
          }, 'Loading graph...')
        : graphData && graphData.nodes?.length > 0
          ? React.createElement(React.Fragment, null,
              React.createElement('canvas', {
                ref: canvasRef,
                className: 'w-full h-full',
                onClick: handleCanvasClick,
                onMouseMove: handleCanvasMouseMove,
                onMouseLeave: handleCanvasMouseLeave,
              }),
              // Tooltip overlay
              hoveredNode && React.createElement('div', {
                className: 'absolute pointer-events-none z-10 px-3 py-2 bg-noctis-bg border border-noctis-border rounded-lg shadow-lg text-xs',
                style: {
                  left: `${tooltipPos.x + 14}px`,
                  top: `${tooltipPos.y - 10}px`,
                  maxWidth: '250px',
                },
              },
                React.createElement('div', { className: 'flex items-center gap-2 mb-1' },
                  React.createElement('div', {
                    className: 'w-2 h-2 rounded-full flex-shrink-0',
                    style: { backgroundColor: nodeColor(hoveredNode.type) },
                  }),
                  React.createElement('span', { className: 'text-noctis-muted' }, hoveredNode.type),
                ),
                React.createElement('div', { className: 'text-noctis-text font-mono truncate' },
                  hoveredNode.properties?.name || hoveredNode.properties?.value || hoveredNode.id,
                ),
                React.createElement('div', { className: 'text-noctis-dim mt-1' },
                  `${hoveredNode._connectionCount || 0} connections`,
                ),
              ),
            )
          : React.createElement('div', {
              className: 'absolute inset-0 flex flex-col items-center justify-center text-noctis-dim',
            },
              React.createElement(Network, { className: 'w-12 h-12 mb-3 opacity-30' }),
              React.createElement('p', { className: 'text-sm' },
                graphError || 'No relationships found for this entity.',
              ),
            ),
    ),
  )
}
