import React, { useState, useEffect } from 'react'
import {
  Activity, Radio, Brain, Shield, Network, Bell, Radar,
  ArrowRight, ExternalLink
} from 'lucide-react'

const features = [
  {
    icon: Radio,
    title: 'Multi-Source Collection',
    desc: 'Telegram MTProto, dark web forums via Tor, paste sites, RSS/Atom feeds. Concurrent collectors with per-source dedup and circuit breakers.',
  },
  {
    icon: Brain,
    title: 'LLM Classification',
    desc: 'Every collected item is classified by category and severity via an OpenAI-compatible LLM. Background workers process the queue continuously.',
  },
  {
    icon: Shield,
    title: 'IOC Extraction',
    desc: 'IPs, domains, hashes, CVEs, emails, crypto wallets. Only confirmed malicious indicators are stored — research references are filtered out.',
  },
  {
    icon: Network,
    title: 'Entity Graph',
    desc: 'Actors, IOCs, channels, and findings linked in a traversable graph. BFS queries expose relationship chains across the dataset.',
  },
  {
    icon: Bell,
    title: 'Real-Time Alerts',
    desc: 'Keyword and regex rule engine evaluates every finding inline. Matched content triggers webhooks, Wazuh alerts, or Kubernetes NetworkPolicies.',
  },
  {
    icon: Radar,
    title: 'Autonomous Discovery',
    desc: 'URLs extracted from collected content are classified and queued as new sources. The intelligence net grows itself. Operator approval required by default.',
  },
]

const sevColors = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  info: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
}

export default function Landing({ navigate }) {
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState(null)

  useEffect(() => {
    fetch('/api/public-stats').then(r => r.ok ? r.json() : null).then(setStats).catch(() => {})
    fetch('/api/public-recent').then(r => r.ok ? r.json() : null).then(setRecent).catch(() => {})
  }, [])

  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg text-noctis-text font-body' },

    // Nav — minimal
    React.createElement('nav', {
      className: 'fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 bg-noctis-bg/90 backdrop-blur-sm border-b border-noctis-border/50'
    },
      React.createElement('div', { className: 'flex items-center gap-2.5' },
        React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple' }),
        React.createElement('span', { className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text' }, 'Noctis'),
      ),
      React.createElement('button', {
        onClick: () => navigate('/login'),
        className: 'text-sm text-noctis-muted hover:text-noctis-text cursor-pointer transition-colors duration-200 flex items-center gap-1.5'
      },
        'Dashboard',
        React.createElement(ArrowRight, { className: 'w-3.5 h-3.5' }),
      ),
    ),

    // Hero
    React.createElement('section', {
      className: 'relative pt-32 pb-24 px-8'
    },
      // Subtle grid — very low opacity
      React.createElement('div', {
        className: 'absolute inset-0 opacity-[0.04]',
        style: {
          backgroundImage: 'linear-gradient(rgba(124,58,237,1) 1px, transparent 1px), linear-gradient(90deg, rgba(124,58,237,1) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        },
      }),
      React.createElement('div', { className: 'max-w-3xl mx-auto relative z-10' },
        React.createElement('h1', {
          className: 'font-heading font-normal text-4xl md:text-5xl leading-tight tracking-tight text-noctis-text mb-6'
        }, 'Autonomous Threat Intelligence Collection & Analysis'),
        React.createElement('p', {
          className: 'text-base md:text-lg text-noctis-muted leading-relaxed max-w-2xl mb-10'
        },
          'Noctis continuously monitors Telegram channels, dark web forums, paste sites, and RSS feeds \u2014 classifying threats, extracting IOCs, and building entity graphs with AI. Self-hosted. Open source.',
        ),
        React.createElement('div', { className: 'flex items-center gap-6' },
          React.createElement('button', {
            onClick: () => navigate('/login'),
            className: 'px-5 py-2.5 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 rounded cursor-pointer transition-all duration-200'
          }, 'Access Dashboard'),
          React.createElement('a', {
            href: 'https://github.com/Zyrakk/noctis',
            target: '_blank',
            rel: 'noopener noreferrer',
            className: 'text-sm text-noctis-dim hover:text-noctis-muted cursor-pointer transition-colors duration-200 flex items-center gap-1.5'
          },
            'View on GitHub',
            React.createElement(ExternalLink, { className: 'w-3 h-3' }),
          ),
        ),
      ),
    ),

    // Live stats bar
    stats && React.createElement('div', {
      className: 'px-8 pb-16'
    },
      React.createElement('div', {
        className: 'max-w-3xl mx-auto flex items-center gap-6 text-xs text-noctis-dim font-mono'
      },
        React.createElement('span', null, `${stats.totalFindings.toLocaleString()} findings collected`),
        React.createElement('span', { className: 'text-noctis-border' }, '\u00b7'),
        React.createElement('span', null, `${stats.totalIocs.toLocaleString()} IOCs extracted`),
        React.createElement('span', { className: 'text-noctis-border' }, '\u00b7'),
        React.createElement('span', null, `${stats.activeSources} active sources`),
        stats.totalEntities > 0 && React.createElement('span', { className: 'text-noctis-border' }, '\u00b7'),
        stats.totalEntities > 0 && React.createElement('span', null, `${stats.totalEntities.toLocaleString()} entities mapped`),
      ),
    ),

    // Features
    React.createElement('section', {
      className: 'py-20 px-8 border-t border-noctis-border/50'
    },
      React.createElement('div', { className: 'max-w-5xl mx-auto' },
        React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6' },
          features.map((f, i) =>
            React.createElement('div', {
              key: i,
              className: 'py-4 pl-4 border-l-2 border-noctis-border hover:border-noctis-purple/60 transition-colors duration-200'
            },
              React.createElement('div', { className: 'flex items-center gap-2.5 mb-2' },
                React.createElement(f.icon, { className: 'w-4 h-4 text-noctis-dim' }),
                React.createElement('h3', {
                  className: 'font-heading font-medium text-sm text-noctis-text'
                }, f.title),
              ),
              React.createElement('p', {
                className: 'text-xs text-noctis-muted leading-relaxed'
              }, f.desc),
            )
          ),
        ),
      ),
    ),

    // Recent findings preview
    recent && recent.length > 0 && React.createElement('section', {
      className: 'py-16 px-8 border-t border-noctis-border/50'
    },
      React.createElement('div', { className: 'max-w-5xl mx-auto' },
        React.createElement('h2', {
          className: 'font-heading font-normal text-sm uppercase tracking-widest text-noctis-dim mb-6'
        }, 'Recent Classified Findings'),
        React.createElement('div', {
          className: 'border border-noctis-border/50 rounded overflow-hidden'
        },
          React.createElement('table', { className: 'w-full text-xs' },
            React.createElement('thead', null,
              React.createElement('tr', { className: 'bg-noctis-surface/50 border-b border-noctis-border/50' },
                ['Category', 'Severity', 'Source', 'Summary'].map(h =>
                  React.createElement('th', {
                    key: h,
                    className: 'px-4 py-2.5 text-left font-medium text-noctis-dim uppercase tracking-wider'
                  }, h)
                ),
              ),
            ),
            React.createElement('tbody', null,
              recent.map((f, i) => {
                const sev = f.severity?.toLowerCase() || 'info'
                const sevClass = sevColors[sev] || sevColors.info
                return React.createElement('tr', {
                  key: i,
                  className: 'border-b border-noctis-border/30 last:border-0'
                },
                  React.createElement('td', { className: 'px-4 py-2.5 text-noctis-muted font-mono' },
                    f.category?.replace(/_/g, ' ') || '-',
                  ),
                  React.createElement('td', { className: 'px-4 py-2.5' },
                    React.createElement('span', {
                      className: `inline-block px-1.5 py-0.5 text-[10px] font-mono font-medium rounded border ${sevClass}`
                    }, sev),
                  ),
                  React.createElement('td', { className: 'px-4 py-2.5 text-noctis-dim' }, f.sourceType),
                  React.createElement('td', { className: 'px-4 py-2.5 text-noctis-muted max-w-md truncate' }, f.summary),
                )
              }),
            ),
          ),
        ),
      ),
    ),

    // CTA
    React.createElement('section', {
      className: 'py-20 px-8 border-t border-noctis-border/50'
    },
      React.createElement('div', { className: 'max-w-3xl mx-auto' },
        React.createElement('h2', {
          className: 'font-heading font-normal text-2xl md:text-3xl text-noctis-text mb-3'
        }, 'Deploy Noctis on your infrastructure.'),
        React.createElement('p', {
          className: 'text-noctis-muted text-base mb-8'
        }, 'Monitor your threat landscape with a single binary. Kubernetes-native, PostgreSQL-backed, MIT licensed.'),
        React.createElement('div', { className: 'flex items-center gap-6' },
          React.createElement('a', {
            href: 'https://github.com/Zyrakk/noctis',
            target: '_blank',
            rel: 'noopener noreferrer',
            className: 'px-5 py-2.5 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-muted/60 rounded cursor-pointer transition-all duration-200 flex items-center gap-2'
          },
            'View on GitHub',
            React.createElement(ExternalLink, { className: 'w-3.5 h-3.5' }),
          ),
          React.createElement('button', {
            onClick: () => navigate('/login'),
            className: 'text-sm text-noctis-muted hover:text-noctis-text cursor-pointer transition-colors duration-200 flex items-center gap-1.5'
          },
            'Access Dashboard',
            React.createElement(ArrowRight, { className: 'w-3.5 h-3.5' }),
          ),
        ),
      ),
    ),

    // Footer
    React.createElement('footer', {
      className: 'py-8 px-8 border-t border-noctis-border/30'
    },
      React.createElement('div', { className: 'max-w-5xl mx-auto flex items-center justify-between text-xs text-noctis-dim' },
        React.createElement('span', null, 'Noctis'),
        React.createElement('div', { className: 'flex items-center gap-4' },
          React.createElement('span', null, 'MIT License'),
          React.createElement('a', {
            href: 'https://github.com/Zyrakk/noctis',
            target: '_blank',
            rel: 'noopener noreferrer',
            className: 'hover:text-noctis-muted transition-colors duration-200 cursor-pointer'
          }, 'GitHub'),
        ),
      ),
    ),
  )
}
