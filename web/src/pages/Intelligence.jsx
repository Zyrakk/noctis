import React, { useState, useEffect } from 'react'
import { useApi } from '../hooks/useApi.js'
import {
  Shield, AlertTriangle, TrendingUp, Bug, FileText, Users, Target,
  ChevronDown, ChevronUp, ArrowUpRight, ArrowRight, ArrowDownRight, RefreshCw
} from 'lucide-react'

const PRIORITY_COLORS = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-noctis-bg text-noctis-dim border-noctis-border',
}

export default function Intelligence({ navigate }) {
  const [refreshKey, setRefreshKey] = useState(0)
  const [briefOpen, setBriefOpen] = useState(true)

  // Auto-refresh every 60s
  useEffect(() => {
    const interval = setInterval(() => setRefreshKey(k => k + 1), 60000)
    return () => clearInterval(interval)
  }, [])

  const { data, loading } = useApi(`/api/intelligence/overview?_=${refreshKey}`)
  const overview = data || {}
  const m = overview.metrics || {}

  const metricCard = (label, value, icon) =>
    React.createElement('div', { className: 'text-center p-3 bg-noctis-surface/50 border border-white/[0.06] rounded-lg' },
      React.createElement(icon, { className: 'w-4 h-4 mx-auto text-noctis-dim mb-1' }),
      React.createElement('div', { className: 'text-lg font-mono text-noctis-text' }, (value || 0).toLocaleString()),
      React.createElement('div', { className: 'text-[10px] text-noctis-dim mt-0.5 uppercase tracking-wider' }, label),
    )

  const trendIcon = (current, prev) => {
    if (current > prev) return ArrowUpRight
    if (current < prev) return ArrowDownRight
    return ArrowRight
  }

  const trendColor = (current, prev) => {
    if (current > prev) return 'text-red-400'
    if (current < prev) return 'text-green-400'
    return 'text-noctis-dim'
  }

  return React.createElement('div', { className: 'space-y-6' },
    // Header
    React.createElement('div', { className: 'flex items-center justify-between' },
      React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Intelligence Overview'),
      React.createElement('div', { className: 'flex items-center gap-2 text-xs text-noctis-dim' },
        React.createElement(RefreshCw, { className: `w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}` }),
        'Auto-refresh',
      ),
    ),

    // Metrics bar
    React.createElement('div', { className: 'grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-7 gap-2' },
      metricCard('Findings', m.totalFindings, FileText),
      metricCard('Active IOCs', m.activeIocs, Shield),
      metricCard('Correlations', m.confirmedCorrelations, Target),
      metricCard('Notes', m.analyticalNotes, FileText),
      metricCard('Actors', m.trackedActors, Users),
      metricCard('Vulns', m.trackedVulns, Bug),
      metricCard('KEV', m.kevCount, AlertTriangle),
    ),

    // Latest Brief
    overview.latestBrief && React.createElement('div', {
      className: 'border border-noctis-purple/20 bg-noctis-purple/5 rounded-lg overflow-hidden'
    },
      React.createElement('button', {
        onClick: () => setBriefOpen(v => !v),
        className: 'w-full flex items-center justify-between p-4 cursor-pointer'
      },
        React.createElement('div', { className: 'flex items-center gap-2' },
          React.createElement(FileText, { className: 'w-4 h-4 text-noctis-purple-light' }),
          React.createElement('span', { className: 'text-sm font-medium text-noctis-text' }, overview.latestBrief.title),
        ),
        briefOpen
          ? React.createElement(ChevronUp, { className: 'w-4 h-4 text-noctis-dim' })
          : React.createElement(ChevronDown, { className: 'w-4 h-4 text-noctis-dim' }),
      ),
      briefOpen && React.createElement('div', { className: 'px-4 pb-4' },
        React.createElement('p', { className: 'text-sm text-noctis-muted leading-relaxed mb-2' }, overview.latestBrief.executiveSummary),
        React.createElement('button', {
          onClick: () => navigate('/dashboard/briefs'),
          className: 'text-xs text-noctis-purple-light hover:underline cursor-pointer'
        }, 'View Full Brief \u2192'),
      ),
    ),

    // Two-column layout
    React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-2 gap-6' },

      // Left column
      React.createElement('div', { className: 'space-y-6' },

        // Active Threat Actors
        React.createElement('div', null,
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-dim uppercase tracking-wider mb-3' }, 'Active Threat Actors'),
          React.createElement('div', { className: 'space-y-3' },
            overview.activeActors?.length > 0
              ? overview.activeActors.map(actor =>
                  React.createElement('div', {
                    key: actor.entityId,
                    onClick: () => navigate(`/dashboard/graph?entity=${actor.entityId}`),
                    className: 'p-3 border border-white/[0.06] rounded-lg cursor-pointer hover:border-noctis-purple/30 hover:bg-noctis-surface/30 transition-all duration-150'
                  },
                    React.createElement('div', { className: 'flex items-center justify-between mb-1.5' },
                      React.createElement('span', { className: 'text-sm font-medium text-noctis-text' }, actor.name),
                      React.createElement('span', {
                        className: `text-[10px] px-2 py-0.5 rounded border ${
                          actor.threatLevel === 'high' ? 'bg-red-500/15 text-red-400 border-red-500/30' :
                          actor.threatLevel === 'medium' ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' :
                          'bg-noctis-bg text-noctis-dim border-noctis-border'
                        }`
                      }, actor.threatLevel),
                    ),
                    React.createElement('div', { className: 'flex items-center gap-3 text-xs text-noctis-dim mb-1.5' },
                      React.createElement('span', null, `${actor.recentFindings} findings (7d)`),
                      actor.linkedInfra > 0 && React.createElement('span', null, `${actor.linkedInfra} infra`),
                    ),
                    actor.linkedMalware?.length > 0 && React.createElement('div', { className: 'flex flex-wrap gap-1 mb-1.5' },
                      actor.linkedMalware.map(m =>
                        React.createElement('span', {
                          key: m,
                          className: 'text-[10px] px-1.5 py-0.5 bg-red-500/10 text-red-400 rounded font-mono'
                        }, m)
                      ),
                    ),
                    actor.latestNote && React.createElement('p', {
                      className: 'text-xs text-noctis-muted line-clamp-2 mt-1'
                    }, actor.latestNote),
                  )
                )
              : React.createElement('p', { className: 'text-xs text-noctis-dim py-4 text-center' }, 'No tracked actors yet.'),
          ),
        ),

        // Active Campaigns
        React.createElement('div', null,
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-dim uppercase tracking-wider mb-3' }, 'Active Campaigns'),
          React.createElement('div', { className: 'space-y-2' },
            overview.activeCampaigns?.length > 0
              ? overview.activeCampaigns.map(c =>
                  React.createElement('div', {
                    key: c.clusterId,
                    className: 'p-3 border border-white/[0.06] rounded-lg'
                  },
                    React.createElement('div', { className: 'flex items-center gap-2 mb-1.5' },
                      React.createElement('span', {
                        className: 'text-xs px-2 py-0.5 bg-noctis-cyan/10 text-cyan-400 rounded font-mono'
                      }, c.correlationType),
                      React.createElement('span', {
                        className: `text-[10px] px-1.5 py-0.5 rounded ${
                          c.method === 'analyst' ? 'bg-noctis-purple/15 text-noctis-purple-light' : 'bg-noctis-surface text-noctis-muted'
                        }`
                      }, c.method),
                      React.createElement('span', {
                        className: 'text-[10px] text-noctis-dim'
                      }, `${(c.confidence * 100).toFixed(0)}% conf`),
                    ),
                    React.createElement('div', { className: 'flex flex-wrap gap-1 mb-1' },
                      c.entityNames.map(name =>
                        React.createElement('span', {
                          key: name,
                          className: 'text-xs text-noctis-muted'
                        }, name)
                      ),
                    ),
                    React.createElement('span', { className: 'text-[10px] text-noctis-dim' },
                      `${c.findingCount} findings \u2022 ${new Date(c.createdAt).toLocaleDateString()}`
                    ),
                  )
                )
              : React.createElement('p', { className: 'text-xs text-noctis-dim py-4 text-center' }, 'No active campaigns.'),
          ),
        ),
      ),

      // Right column
      React.createElement('div', { className: 'space-y-6' },

        // Trending Entities
        React.createElement('div', null,
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-dim uppercase tracking-wider mb-3' }, 'Trending Entities'),
          React.createElement('div', { className: 'space-y-1' },
            overview.trendingEntities?.length > 0
              ? overview.trendingEntities.map(e => {
                  const TIcon = trendIcon(e.mentionCount, e.prevCount)
                  return React.createElement('div', {
                    key: e.id,
                    className: 'flex items-center justify-between p-2 rounded hover:bg-noctis-surface/30 transition-colors duration-150'
                  },
                    React.createElement('div', { className: 'flex items-center gap-2 min-w-0' },
                      React.createElement('span', {
                        className: 'text-[10px] px-1.5 py-0.5 bg-noctis-surface rounded text-noctis-dim font-mono'
                      }, e.type),
                      React.createElement('span', {
                        className: 'text-xs text-noctis-text truncate'
                      }, e.id),
                    ),
                    React.createElement('div', { className: 'flex items-center gap-1.5 flex-shrink-0' },
                      React.createElement('span', { className: 'text-xs font-mono text-noctis-muted' }, e.mentionCount),
                      React.createElement(TIcon, { className: `w-3.5 h-3.5 ${trendColor(e.mentionCount, e.prevCount)}` }),
                    ),
                  )
                })
              : React.createElement('p', { className: 'text-xs text-noctis-dim py-4 text-center' }, 'No trending entities.'),
          ),
        ),

        // Priority Vulnerabilities
        React.createElement('div', null,
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-dim uppercase tracking-wider mb-3' }, 'Priority Vulnerabilities'),
          React.createElement('div', { className: 'space-y-1' },
            overview.topVulnerabilities?.length > 0
              ? overview.topVulnerabilities.map(v =>
                  React.createElement('div', {
                    key: v.id,
                    onClick: () => navigate('/dashboard/vulns'),
                    className: 'flex items-center justify-between p-2 rounded cursor-pointer hover:bg-noctis-surface/30 transition-colors duration-150'
                  },
                    React.createElement('div', { className: 'flex items-center gap-2' },
                      React.createElement('span', { className: 'text-xs font-mono text-noctis-text' }, v.cveId),
                      v.kevListed && React.createElement(AlertTriangle, { className: 'w-3 h-3 text-red-400' }),
                    ),
                    React.createElement('div', { className: 'flex items-center gap-2' },
                      v.cvssScore != null && React.createElement('span', {
                        className: `text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          v.cvssScore >= 9 ? 'bg-red-500/15 text-red-400' :
                          v.cvssScore >= 7 ? 'bg-orange-500/15 text-orange-400' :
                          'bg-noctis-bg text-noctis-dim'
                        }`
                      }, v.cvssScore.toFixed(1)),
                      v.darkWebMentions > 0 && React.createElement('span', {
                        className: 'text-[10px] font-mono px-1.5 py-0.5 bg-noctis-purple/10 text-noctis-purple-light rounded'
                      }, `${v.darkWebMentions} mentions`),
                      v.priorityLabel && React.createElement('span', {
                        className: `text-[10px] px-1.5 py-0.5 rounded border ${PRIORITY_COLORS[v.priorityLabel] || PRIORITY_COLORS.info}`
                      }, v.priorityLabel),
                    ),
                  )
                )
              : React.createElement('p', { className: 'text-xs text-noctis-dim py-4 text-center' }, 'No tracked vulnerabilities.'),
          ),
        ),

        // Recent Notes
        React.createElement('div', null,
          React.createElement('h2', { className: 'text-sm font-medium text-noctis-dim uppercase tracking-wider mb-3' }, 'Recent Analytical Notes'),
          React.createElement('div', { className: 'space-y-2' },
            overview.recentNotes?.length > 0
              ? overview.recentNotes.slice(0, 5).map(n =>
                  React.createElement('div', {
                    key: n.id,
                    className: 'p-2 border border-white/[0.06] rounded'
                  },
                    React.createElement('div', { className: 'flex items-center gap-2 mb-0.5' },
                      React.createElement('span', {
                        className: 'text-[10px] px-1.5 py-0.5 bg-noctis-surface rounded text-noctis-dim'
                      }, n.noteType),
                      React.createElement('span', { className: 'text-[10px] text-noctis-dim' }, n.createdBy),
                    ),
                    React.createElement('p', { className: 'text-xs text-noctis-text line-clamp-1' }, n.title),
                  )
                )
              : React.createElement('p', { className: 'text-xs text-noctis-dim py-4 text-center' }, 'No analytical notes.'),
          ),
        ),
      ),
    ),
  )
}
