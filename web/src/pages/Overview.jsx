import React from 'react'
import { useApi } from '../hooks/useApi.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import {
  FileText, CheckCircle, Shield, Globe, Radar,
  TrendingUp
} from 'lucide-react'
import {
  PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'

const CHART_COLORS = ['#7c3aed', '#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#8b5cf6']
const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280', unclassified: '#374151' }
const TOOLTIP_STYLE = {
  contentStyle: { backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' },
  itemStyle: { color: '#e2e8f0' },
  labelStyle: { color: '#94a3b8' },
  cursor: { fill: 'rgba(124, 58, 237, 0.05)' },
}

function StatCard({ icon: Icon, label, value, color = 'border-noctis-border' }) {
  return React.createElement('div', {
    className: `border-l-2 ${color} pl-4 py-3 transition-all duration-200 hover:-translate-y-0.5`
  },
    React.createElement('div', { className: 'flex items-center gap-2 mb-1' },
      React.createElement(Icon, { className: 'w-3.5 h-3.5 text-noctis-dim' }),
      React.createElement('span', { className: 'text-xs text-noctis-dim' }, label),
    ),
    React.createElement('div', { className: 'text-xl font-mono font-normal text-noctis-text' },
      value != null ? value.toLocaleString() : React.createElement('span', { className: 'skeleton inline-block w-14 h-6' }),
    ),
  )
}

function Skeleton({ className }) {
  return React.createElement('div', { className: `skeleton ${className}` })
}

export default function Overview({ navigate }) {
  const { data: stats, loading: statsLoading } = useApi('/api/stats')
  const { data: categories } = useApi('/api/categories')
  const { data: timeline } = useApi('/api/timeline?since=7d&interval=1 hour')
  const { data: recentFindings } = useApi('/api/findings?severity=critical&limit=10')

  const catTotal = (categories || []).reduce((sum, c) => sum + c.count, 0)
  const catData = (categories || []).map((c, i) => ({
    name: c.category?.replace(/_/g, ' ') || 'unknown',
    value: c.count,
    pct: catTotal > 0 ? Math.round((c.count / catTotal) * 100) : 0,
    fill: CHART_COLORS[i % CHART_COLORS.length],
  }))

  const sevData = stats ? Object.entries(stats.bySeverity || {})
    .filter(([k]) => k !== 'unclassified')
    .map(([name, value]) => ({ name, value, fill: SEV_COLORS[name] || '#6b7280' }))
    : []

  const timeData = (timeline || []).map(p => ({
    time: new Date(p.bucket).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit' }),
    count: p.count,
  }))

  const findings = recentFindings?.findings || []

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Overview'),
      React.createElement('div', { className: 'text-sm text-noctis-muted' },
        'Last 7 days',
      ),
    ),

    // Stat cards
    React.createElement('div', { className: 'grid grid-cols-2 lg:grid-cols-5 gap-4' },
      React.createElement(StatCard, { icon: FileText, label: 'Total Content', value: stats?.totalContent, color: 'border-blue-500/60' }),
      React.createElement(StatCard, { icon: CheckCircle, label: 'Classified', value: stats?.classified, color: 'border-purple-500/60' }),
      React.createElement(StatCard, { icon: Shield, label: 'IOCs Extracted', value: stats?.totalIocs, color: 'border-amber-500/60' }),
      React.createElement(StatCard, { icon: Globe, label: 'Active Sources', value: stats?.activeSources, color: 'border-cyan-500/60' }),
      React.createElement(StatCard, { icon: Radar, label: 'Discovered', value: stats?.discoveredSources, color: 'border-green-500/60' }),
    ),

    // Charts row
    React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-2 gap-6' },
      // Category donut
      React.createElement('div', {
        className: 'border border-noctis-border/50 rounded p-5'
      },
        React.createElement('h3', { className: 'text-sm font-medium text-noctis-muted mb-4' }, 'Category Distribution'),
        catData.length > 0
          ? React.createElement(ResponsiveContainer, { width: '100%', height: 260 },
              React.createElement(PieChart, null,
                React.createElement(Pie, {
                  data: catData, cx: '50%', cy: '50%',
                  innerRadius: 70, outerRadius: 100,
                  paddingAngle: 2, dataKey: 'value',
                  stroke: 'none',
                },
                  catData.map((entry, i) =>
                    React.createElement(Cell, { key: i, fill: entry.fill })
                  ),
                ),
                React.createElement(Tooltip, {
                  ...TOOLTIP_STYLE,
                  formatter: (value, name) => [`${value} (${catTotal > 0 ? Math.round((value / catTotal) * 100) : 0}%)`, name],
                }),
              ),
            )
          : React.createElement(Skeleton, { className: 'h-[260px] w-full' }),

        // Legend
        catData.length > 0 && React.createElement('div', {
          className: 'flex flex-wrap gap-x-4 gap-y-1.5 mt-2 justify-center'
        },
          catData.slice(0, 8).map((c, i) =>
            React.createElement('div', {
              key: i,
              className: 'flex items-center gap-1.5 text-xs text-noctis-muted'
            },
              React.createElement('div', {
                className: 'w-2.5 h-2.5 rounded-full flex-shrink-0',
                style: { backgroundColor: c.fill },
              }),
              `${c.name} ${c.pct}%`,
            )
          ),
        ),
      ),

      // Severity bar
      React.createElement('div', {
        className: 'border border-noctis-border/50 rounded p-5'
      },
        React.createElement('h3', { className: 'text-sm font-medium text-noctis-muted mb-4' }, 'Severity Distribution'),
        sevData.length > 0
          ? React.createElement(ResponsiveContainer, { width: '100%', height: 300 },
              React.createElement(BarChart, { data: sevData },
                React.createElement(CartesianGrid, { strokeDasharray: '3 3', stroke: '#2a2a3e' }),
                React.createElement(XAxis, { dataKey: 'name', tick: { fill: '#94a3b8', fontSize: 12 }, axisLine: { stroke: '#2a2a3e' } }),
                React.createElement(YAxis, { tick: { fill: '#94a3b8', fontSize: 12 }, axisLine: { stroke: '#2a2a3e' } }),
                React.createElement(Tooltip, TOOLTIP_STYLE),
                React.createElement(Bar, { dataKey: 'value', radius: [4, 4, 0, 0] },
                  sevData.map((entry, i) =>
                    React.createElement(Cell, { key: i, fill: entry.fill })
                  ),
                ),
              ),
            )
          : React.createElement(Skeleton, { className: 'h-[300px] w-full' }),
      ),
    ),

    // Timeline
    React.createElement('div', {
      className: 'border border-noctis-border/50 rounded p-5'
    },
      React.createElement('div', { className: 'flex items-center gap-2 mb-4' },
        React.createElement(TrendingUp, { className: 'w-4 h-4 text-noctis-purple-light' }),
        React.createElement('h3', { className: 'text-sm font-medium text-noctis-muted' }, 'Findings Timeline'),
      ),
      timeData.length > 0
        ? React.createElement(ResponsiveContainer, { width: '100%', height: 200 },
            React.createElement(AreaChart, { data: timeData },
              React.createElement(CartesianGrid, { strokeDasharray: '3 3', stroke: '#2a2a3e' }),
              React.createElement(XAxis, { dataKey: 'time', tick: { fill: '#94a3b8', fontSize: 11 }, axisLine: { stroke: '#2a2a3e' }, interval: 'preserveStartEnd' }),
              React.createElement(YAxis, { tick: { fill: '#94a3b8', fontSize: 11 }, axisLine: { stroke: '#2a2a3e' } }),
              React.createElement(Tooltip, TOOLTIP_STYLE),
              React.createElement(Area, {
                type: 'monotone', dataKey: 'count',
                stroke: '#7c3aed', fill: 'url(#purpleGrad)', strokeWidth: 2,
              }),
              React.createElement('defs', null,
                React.createElement('linearGradient', { id: 'purpleGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
                  React.createElement('stop', { offset: '0%', stopColor: '#7c3aed', stopOpacity: 0.3 }),
                  React.createElement('stop', { offset: '100%', stopColor: '#7c3aed', stopOpacity: 0 }),
                ),
              ),
            ),
          )
        : React.createElement(Skeleton, { className: 'h-[200px] w-full' }),
    ),

    // Recent findings
    React.createElement('div', {
      className: 'border border-noctis-border/50 rounded p-5'
    },
      React.createElement('h3', { className: 'text-sm font-medium text-noctis-muted mb-4' }, 'Recent Critical Findings'),
      findings.length > 0
        ? React.createElement('div', { className: 'space-y-2' },
            findings.map(f =>
              React.createElement('div', {
                key: f.id,
                onClick: () => navigate(`/dashboard/findings?id=${f.id}`),
                className: 'flex items-center gap-4 p-3 rounded-lg hover:bg-noctis-surface2 cursor-pointer transition-colors duration-150'
              },
                React.createElement(SeverityBadge, { severity: f.severity }),
                React.createElement('span', { className: 'text-xs text-noctis-dim font-mono min-w-[5rem]' },
                  new Date(f.collectedAt).toLocaleDateString(),
                ),
                React.createElement('span', { className: 'text-xs text-noctis-muted px-2 py-0.5 bg-noctis-bg rounded' }, f.sourceType),
                React.createElement('span', { className: 'text-sm text-noctis-text truncate flex-1' }, f.summary || 'No summary'),
              )
            )
          )
        : statsLoading
          ? React.createElement('div', { className: 'space-y-2' },
              Array.from({ length: 5 }).map((_, i) =>
                React.createElement(Skeleton, { key: i, className: 'h-12 w-full' })
              )
            )
          : React.createElement('p', { className: 'text-sm text-noctis-dim py-4 text-center' }, 'No critical findings yet.'),
    ),
  )
}
