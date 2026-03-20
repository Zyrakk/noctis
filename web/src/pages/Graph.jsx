import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import { apiFetch } from '../hooks/useApi.js'
import { Search, Network } from 'lucide-react'

const NODE_COLORS = {
  actor: '#ef4444',
  ioc: '#eab308',
  channel: '#3b82f6',
  finding: '#7c3aed',
  default: '#6b7280',
}

export default function Graph() {
  const { apiKey } = useAuth()
  const canvasRef = useRef(null)
  const [query, setQuery] = useState('')
  const [graphData, setGraphData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [hops, setHops] = useState(2)

  const fetchGraph = useCallback(async (entityId) => {
    if (!entityId.trim()) return
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch(apiKey, `/api/graph?entity_id=${encodeURIComponent(entityId)}&hops=${hops}`)
      setGraphData(data)
    } catch (err) {
      setError(err.message)
      setGraphData(null)
    }
    setLoading(false)
  }, [apiKey, hops])

  // Canvas rendering with d3-force
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

    const nodeMap = new Map(nodes.map(n => [n.id, n]))

    const links = graphData.edges
      .filter(e => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map(e => ({
        source: nodeMap.get(e.source),
        target: nodeMap.get(e.target),
        relationship: e.relationship,
      }))

    // Simple force simulation (no d3 dep needed for basic version)
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
        // Bounds
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

        // Label
        const mx = (link.source.x + link.target.x) / 2
        const my = (link.source.y + link.target.y) / 2
        ctx.fillStyle = 'rgba(148, 163, 184, 0.5)'
        ctx.font = '9px Fira Code'
        ctx.textAlign = 'center'
        ctx.fillText(link.relationship, mx, my - 4)
      }

      // Nodes
      for (const n of nodes) {
        const color = NODE_COLORS[n.type] || NODE_COLORS.default
        // Glow
        ctx.beginPath()
        ctx.arc(n.x, n.y, 12, 0, Math.PI * 2)
        ctx.fillStyle = color + '30'
        ctx.fill()
        // Circle
        ctx.beginPath()
        ctx.arc(n.x, n.y, 8, 0, Math.PI * 2)
        ctx.fillStyle = color
        ctx.fill()
        ctx.strokeStyle = color + '60'
        ctx.lineWidth = 2
        ctx.stroke()
        // Label
        ctx.fillStyle = '#e2e8f0'
        ctx.font = '10px Fira Code'
        ctx.textAlign = 'center'
        const label = n.properties?.name || n.properties?.value || n.id.slice(0, 8)
        ctx.fillText(label, n.x, n.y + 22)
      }

      if (alpha.value > 0.01) {
        animFrame = requestAnimationFrame(tick)
      }
    }

    tick()

    return () => {
      if (animFrame) cancelAnimationFrame(animFrame)
    }
  }, [graphData])

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-bold text-2xl' }, 'Entity Graph'),
    ),

    // Search
    React.createElement('div', { className: 'flex items-center gap-3' },
      React.createElement('div', { className: 'relative flex-1 max-w-md' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: query,
          onChange: e => setQuery(e.target.value),
          onKeyDown: e => { if (e.key === 'Enter') fetchGraph(query) },
          placeholder: 'Enter entity ID...',
          className: 'w-full pl-9 pr-3 py-2.5 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple font-mono transition-colors duration-200'
        }),
      ),
      React.createElement('select', {
        value: hops,
        onChange: e => setHops(parseInt(e.target.value)),
        className: 'px-3 py-2.5 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
      },
        [1, 2, 3, 4, 5].map(h =>
          React.createElement('option', { key: h, value: h }, `${h} hop${h > 1 ? 's' : ''}`)
        ),
      ),
      React.createElement('button', {
        onClick: () => fetchGraph(query),
        disabled: loading || !query.trim(),
        className: 'px-4 py-2.5 bg-noctis-purple hover:bg-noctis-purple-light text-white text-sm font-medium rounded-lg cursor-pointer disabled:opacity-50 transition-colors duration-200'
      }, loading ? 'Loading...' : 'Explore'),
    ),

    // Legend
    React.createElement('div', { className: 'flex items-center gap-4' },
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

    // Canvas
    React.createElement('div', {
      className: 'bg-noctis-surface border border-noctis-border rounded-xl overflow-hidden relative',
      style: { height: '500px' },
    },
      graphData && graphData.nodes?.length > 0
        ? React.createElement('canvas', {
            ref: canvasRef,
            className: 'w-full h-full',
          })
        : React.createElement('div', {
            className: 'absolute inset-0 flex flex-col items-center justify-center text-noctis-dim'
          },
            React.createElement(Network, { className: 'w-12 h-12 mb-3 opacity-30' }),
            React.createElement('p', { className: 'text-sm' },
              error || (graphData ? 'No connections found for this entity.' : 'Enter an entity ID to explore its connections.'),
            ),
          ),
    ),
  )
}
