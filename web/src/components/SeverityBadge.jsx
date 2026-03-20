import React from 'react'

const severityConfig = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/40', glow: 'shadow-[0_0_8px_rgba(239,68,68,0.3)]' },
  high:     { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/40', glow: '' },
  medium:   { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/40', glow: '' },
  low:      { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/40', glow: '' },
  info:     { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/40', glow: '' },
}

export default function SeverityBadge({ severity }) {
  const s = severity?.toLowerCase() || 'info'
  const cfg = severityConfig[s] || severityConfig.info

  return React.createElement('span', {
    className: `inline-flex items-center px-2 py-0.5 text-xs font-mono font-medium rounded border ${cfg.bg} ${cfg.text} ${cfg.border} ${cfg.glow}`
  }, s.toUpperCase())
}
